package otavalidator

import (
	"crypto/ed25519"
	"io"

	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

// Input carries everything the S2..S6 pipeline needs. It is pure data /
// ports — no transport, disk, or DB. The S1 structure stage (ZIP_STORED
// parsing) is performed by the upload handler before calling Validate; this
// library starts at S2.
type Input struct {
	// Artifact streams the exact bytes that were signed and hashed (the S2/S3
	// scope). Validate reads it once, in full.
	Artifact io.Reader

	// HashFile is the raw content of the mandatory external hash file (S2).
	HashFile string

	// PublicKey is the trusted build-pipeline ed25519 public key (S3).
	PublicKey ed25519.PublicKey

	// Signature is the detached ed25519 signature over the SHA-256 digest (S3).
	Signature []byte

	// CurrentVersion is the latest published version for the same target,
	// supplied by the caller's prior-version lookup (S4). Empty means no prior
	// release exists.
	CurrentVersion string

	// Meta is the declared artifact metadata (version, os_type, board, sizes,
	// hashes) used by S4/S5/S6.
	Meta otaprotocol.ArtifactMeta

	// VersionComparator orders versions for S4. If nil, CompareDotted is used.
	VersionComparator VersionComparator

	// TargetPolicy decides S5 known/supported. Required for S5.
	TargetPolicy TargetPolicy
}

// Result is the outcome of a full pipeline run. Final is the decisive verdict
// (the first rejection, or the passing S6 verdict). Verdicts records every
// stage that ran, in order, for the audit trail. ComputedSHA256 is the
// lowercase-hex digest computed in S2 (empty if S2 could not hash the bytes).
type Result struct {
	Final          Verdict
	Verdicts       []Verdict
	ComputedSHA256 string
}

// Accepted reports whether the artifact passed the full pipeline.
func (r Result) Accepted() bool { return r.Final.Passed }

// Validate runs the ordered, fail-fast S2..S6 pipeline. It returns at the first
// rejecting stage with that stage's verdict and code; later stages do not run.
// On full success the Final verdict is the passing S6 verdict.
func Validate(in Input) Result {
	var res Result

	// S2 — SHA-256 vs hash file.
	hashVerdict, digest, actualSize := ValidateHash(in.Artifact, in.HashFile)
	res.ComputedSHA256 = digest
	res.Verdicts = append(res.Verdicts, hashVerdict)
	if hashVerdict.IsReject() {
		res.Final = hashVerdict
		return res
	}

	// S3 — detached signature over the S2 digest.
	sigVerdict := ValidateSignature(digest, in.PublicKey, in.Signature)
	res.Verdicts = append(res.Verdicts, sigVerdict)
	if sigVerdict.IsReject() {
		res.Final = sigVerdict
		return res
	}

	// S4 — version monotonicity.
	verVerdict := ValidateVersion(in.Meta.Version, in.CurrentVersion, in.VersionComparator)
	res.Verdicts = append(res.Verdicts, verVerdict)
	if verVerdict.IsReject() {
		res.Final = verVerdict
		return res
	}

	// S5 — target compatibility.
	tgtVerdict := ValidateTarget(in.Meta.OSType, in.Meta.Board, in.TargetPolicy)
	res.Verdicts = append(res.Verdicts, tgtVerdict)
	if tgtVerdict.IsReject() {
		res.Final = tgtVerdict
		return res
	}

	// S6 — metadata sanity + consistency with the S2 digest and byte count.
	metaVerdict := ValidateMetadata(in.Meta, digest, actualSize)
	res.Verdicts = append(res.Verdicts, metaVerdict)
	res.Final = metaVerdict
	return res
}
