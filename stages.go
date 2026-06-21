package otavalidator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

// VersionComparator orders two version identifiers. It returns a negative
// number if a < b, zero if a == b, and a positive number if a > b, plus an
// error if either version is unparseable. The pipeline depends only on the
// sign of the result, so callers may plug in semver, build-number, or any
// monotonic scheme. A default dotted-numeric comparator (CompareDotted) is
// provided.
type VersionComparator interface {
	Compare(a, b string) (int, error)
}

// VersionComparatorFunc adapts a function to VersionComparator.
type VersionComparatorFunc func(a, b string) (int, error)

// Compare calls f.
func (f VersionComparatorFunc) Compare(a, b string) (int, error) { return f(a, b) }

// TargetPolicy decides S5 target compatibility for a declared {os_type, board}.
// Implementations are supplied by the caller (e.g. backed by the known-targets
// table) so the validator carries no database. Known reports whether the target
// is a recognized fleet target; Supported reports whether it is accepted for
// the current phase (Android Phase-1 for MVP).
type TargetPolicy interface {
	Known(os otaprotocol.OSType, board string) bool
	Supported(os otaprotocol.OSType, board string) bool
}

// ValidateHash implements S2: it streams r through SHA-256 and compares the
// computed digest against the expected hash-file value (plain byte-for-byte
// digest comparison — the digest is public, so timing-safety buys nothing).
// expectedHashFile is the raw content of the mandatory hash file; it may carry
// a trailing filename (the common "<hex>  name" coreutils format), which is
// tolerated. The returned digest is the lowercase-hex SHA-256 over r so the
// caller can persist it for S6 / the release record.
func ValidateHash(r io.Reader, expectedHashFile string) (Verdict, string) {
	// If the reader supports seeking (e.g. *bytes.Reader), rewind to position 0
	// so the same reader can be validated multiple times (stress/chaos tests reuse
	// Input structs whose io.Reader is consumed after one Validate call).
	if seeker, ok := r.(io.Seeker); ok {
		_, _ = seeker.Seek(0, io.SeekStart)
	}
	if strings.TrimSpace(expectedHashFile) == "" {
		return reject(StageHash, RejectHashFileMissing, "hash file is empty or absent"), ""
	}
	expected, ok := parseHashFile(expectedHashFile)
	if !ok {
		return reject(StageHash, RejectHashFileMalformed, "hash file does not contain a 64-char lowercase hex SHA-256"), ""
	}

	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return reject(StageHash, RejectHashMismatch, "failed reading artifact bytes: "+err.Error()), ""
	}
	computed := hex.EncodeToString(h.Sum(nil))

	if computed != expected {
		return reject(StageHash, RejectHashMismatch, "computed SHA-256 does not match hash file"), computed
	}
	return pass(StageHash), computed
}

// parseHashFile extracts the lowercase-hex SHA-256 from a hash file. It accepts
// either a bare digest or the coreutils "<hex>  <name>" form, and validates it
// against the ota-protocol SHA-256 contract.
func parseHashFile(content string) (string, bool) {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return "", false
	}
	digest := fields[0]
	if otaprotocol.ValidateSHA256(digest) != nil {
		return "", false
	}
	return digest, true
}

// ValidateSignature implements S3: it verifies the detached ed25519 signature
// over the SHA-256 digest of the artifact under the trusted public key.
// digestHex is the lowercase-hex SHA-256 produced by S2 (this binds the signed
// bytes to the same artifact that passed S2 — the scope-match requirement).
// pubKey is the trusted build-pipeline public key; sig is the raw detached
// signature bytes.
//
// ed25519 is the MVP DEFAULT scheme (signing_verification.md §3). The signature
// is over the digest, not the raw blob, keeping verification streaming-friendly
// for large payloads.
func ValidateSignature(digestHex string, pubKey ed25519.PublicKey, sig []byte) Verdict {
	if len(sig) == 0 {
		return reject(StageSignature, RejectSignatureMissing, "detached signature is absent")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return reject(StageSignature, RejectSignatureKeyInvalid, "trusted public key is not a valid ed25519 key")
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) != sha256.Size {
		return reject(StageSignature, RejectSignatureScopeMismatch, "signed digest is not a well-formed SHA-256")
	}
	if !ed25519.Verify(pubKey, digest, sig) {
		return reject(StageSignature, RejectSignatureInvalid, "signature does not verify under the trusted public key")
	}
	return pass(StageSignature)
}

// ValidateVersion implements S4: the declared version must be strictly greater
// than the latest published version for the same target. currentVersion is the
// latest published version supplied by the caller (the prior-version lookup);
// an empty currentVersion means no prior release exists, which passes. cmp
// orders the versions; if nil, CompareDotted is used.
func ValidateVersion(declared, currentVersion string, cmp VersionComparator) Verdict {
	if strings.TrimSpace(declared) == "" {
		return reject(StageVersion, RejectVersionUnparseable, "declared version is empty")
	}
	if cmp == nil {
		cmp = VersionComparatorFunc(CompareDotted)
	}
	if strings.TrimSpace(currentVersion) == "" {
		// No prior published release for this target: any parseable version is
		// acceptable. Confirm the declared version is itself parseable.
		if _, err := cmp.Compare(declared, declared); err != nil {
			return reject(StageVersion, RejectVersionUnparseable, "declared version is unparseable: "+err.Error())
		}
		return pass(StageVersion)
	}

	c, err := cmp.Compare(declared, currentVersion)
	if err != nil {
		return reject(StageVersion, RejectVersionUnparseable, "version is unparseable: "+err.Error())
	}
	switch {
	case c == 0:
		return reject(StageVersion, RejectDuplicateVersion, "declared version equals the latest published version")
	case c < 0:
		return reject(StageVersion, RejectNotMonotonic, "declared version is a downgrade from the latest published version")
	default:
		return pass(StageVersion)
	}
}

// ValidateTarget implements S5: the artifact must declare a target and that
// target must be both known to the fleet and supported for the current phase.
func ValidateTarget(os otaprotocol.OSType, board string, policy TargetPolicy) Verdict {
	if os == "" || strings.TrimSpace(board) == "" {
		return reject(StageTarget, RejectTargetUndeclared, "artifact declares no os_type/board target")
	}
	if policy == nil {
		return reject(StageTarget, RejectTargetUnknown, "no target policy configured")
	}
	if !policy.Known(os, board) {
		return reject(StageTarget, RejectTargetUnknown, "declared target is not a known fleet target")
	}
	if !policy.Supported(os, board) {
		return reject(StageTarget, RejectTargetUnsupported, "declared target is not supported for this phase")
	}
	return pass(StageTarget)
}

// ValidateMetadata implements S6: required release fields must be present and
// well-formed (delegated to the ota-protocol ArtifactMeta contract), and the
// metadata must be internally consistent with the digest computed in S2.
// computedDigest is the lowercase-hex SHA-256 from S2; pass "" to skip the
// cross-check (e.g. when running S6 in isolation).
func ValidateMetadata(meta otaprotocol.ArtifactMeta, computedDigest string) Verdict {
	if err := otaprotocol.ValidateArtifactMeta(meta); err != nil {
		return reject(StageMetadata, RejectMetadataIncomplete, "metadata incomplete or malformed: "+err.Error())
	}
	if computedDigest != "" && meta.SHA256 != computedDigest {
		return reject(StageMetadata, RejectMetadataInconsistent, "metadata SHA-256 does not match the computed artifact digest")
	}
	return pass(StageMetadata)
}

// errEmptyVersion is returned by CompareDotted when a version string is empty.
var errEmptyVersion = errors.New("empty version")
