package otavalidator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

// This file hardens the SECURITY invariants of the validator beyond statement
// coverage: it proves that tampered / mis-scoped / wrong-key / truncated inputs
// are REJECTED (anti-bluff §11.4 — every PASS asserts real rejection behaviour
// that fails on a regression, not merely that the happy path runs). The §G2
// hash-before-signature ordering and the signature-scope-binding property are
// the load-bearing trust invariants of an OTA validator and are asserted here
// directly, end to end.

// signArtifact returns the ed25519 keypair, the lowercase-hex SHA-256 digest of
// payload, and a detached signature over that digest — the exact contract S2/S3
// expect. It mirrors newFixture but is reusable for arbitrary payloads.
func signArtifact(t *testing.T, payload []byte) (ed25519.PublicKey, ed25519.PrivateKey, string, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sum := sha256.Sum256(payload)
	return pub, priv, hex.EncodeToString(sum[:]), ed25519.Sign(priv, sum[:])
}

// --- §G2: hash precedes signature, and a tampered payload dies at S2 ---------

// TestG2HashBeforeSignatureOrdering proves the pipeline computes (and checks)
// the SHA-256 of the ACTUAL uploaded bytes BEFORE it ever verifies the
// signature, and that a payload swapped after signing is rejected at S2 — the
// signature stage is never reached. If a regression reordered S3 ahead of S2,
// or skipped the S2 byte-check, this test would fail.
func TestG2HashBeforeSignatureOrdering(t *testing.T) {
	signed := []byte("the genuine, signed OTA payload")
	pub, _, digest, sig := signArtifact(t, signed)

	// Attacker keeps the genuine hash-file + genuine signature (both bind the
	// ORIGINAL bytes) but swaps in a malicious payload of identical framing.
	tampered := []byte("the genuine, signed OTA payload <BACKDOOR>")

	in := Input{
		Artifact:       bytes.NewReader(tampered),
		HashFile:       digest + "  ota.zip\n", // hash of the ORIGINAL bytes
		PublicKey:      pub,
		Signature:      sig, // valid signature over the ORIGINAL digest
		CurrentVersion: "",
		Meta: otaprotocol.ArtifactMeta{
			SHA256:    digest,
			Size:      int64(len(tampered)),
			OSType:    otaprotocol.OSAndroid,
			Board:     "rk3588",
			Version:   "1.0.0",
			Signature: hex.EncodeToString(sig),
		},
		TargetPolicy: NewStaticTargetPolicy(nil,
			[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}}),
	}

	res := Validate(in)
	if res.Accepted() {
		t.Fatal("tampered payload was ACCEPTED — S2 byte-check bypassed (critical defect)")
	}
	if res.Final.Stage != StageHash || res.Final.Code != RejectHashMismatch {
		t.Fatalf("tampered payload rejected at %s/%s; want S2/%s",
			res.Final.Stage, res.Final.Code, RejectHashMismatch)
	}
	// Ordering proof: signature (S3) must NOT have run — only S2 recorded.
	if len(res.Verdicts) != 1 {
		t.Fatalf("expected ONLY S2 to run before rejection (hash-before-signature), got %d verdicts: %v",
			len(res.Verdicts), res.Verdicts)
	}
	if res.Verdicts[0].Stage != StageHash {
		t.Fatalf("first stage was %s; the hash stage must be first", res.Verdicts[0].Stage)
	}
}

// TestSignatureBindsToS2DigestNotMetaField proves S3 verifies against the
// digest S2 actually computed from the bytes (in.ComputedSHA256), NOT against
// the attacker-supplied Meta.SHA256 field. An attacker who sets Meta.SHA256 to
// the digest their signature DOES cover, while shipping different bytes, must
// still be rejected — first at S2 (bytes vs hash file). This is the scope bind.
func TestSignatureBindsToS2DigestNotMetaField(t *testing.T) {
	signed := []byte("payload the signature actually covers")
	pub, _, signedDigest, sig := signArtifact(t, signed)

	shipped := []byte("entirely different shipped payload")
	shippedSum := sha256.Sum256(shipped)
	shippedDigest := hex.EncodeToString(shippedSum[:])

	in := Input{
		Artifact:  bytes.NewReader(shipped),
		HashFile:  shippedDigest + "  ota.zip\n", // hash file matches shipped bytes
		PublicKey: pub,
		Signature: sig, // but signature covers a DIFFERENT digest
		Meta: otaprotocol.ArtifactMeta{
			SHA256:    signedDigest, // attacker lies in metadata to match their sig
			Size:      int64(len(shipped)),
			OSType:    otaprotocol.OSAndroid,
			Board:     "rk3588",
			Version:   "1.0.0",
			Signature: hex.EncodeToString(sig),
		},
		TargetPolicy: NewStaticTargetPolicy(nil,
			[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}}),
	}

	res := Validate(in)
	if res.Accepted() {
		t.Fatal("mis-scoped artifact ACCEPTED — S3 trusted Meta.SHA256 over the S2-computed digest (critical defect)")
	}
	// S2 hashes the shipped bytes -> matches the (truthful) hash file, so S2
	// passes; S3 then verifies the genuine sig against the SHIPPED digest, which
	// the sig does NOT cover -> S3 rejects. Proves S3 uses the S2 digest.
	if res.Final.Stage != StageSignature || res.Final.Code != RejectSignatureInvalid {
		t.Fatalf("rejected at %s/%s; want S3/%s (signature scoped to S2 digest)",
			res.Final.Stage, res.Final.Code, RejectSignatureInvalid)
	}
	if res.ComputedSHA256 != shippedDigest {
		t.Fatalf("ComputedSHA256=%q; S2 must hash the SHIPPED bytes, want %q",
			res.ComputedSHA256, shippedDigest)
	}
}

// --- ValidateSignature: deeper rejection / scope-binding cases ----------------

// TestValidateSignatureScopeBinding directly proves a valid signature over one
// digest does NOT verify against any other digest — the property that stops a
// signature from being replayed onto different content.
func TestValidateSignatureScopeBinding(t *testing.T) {
	pub, priv, digestA, sigA := signArtifact(t, []byte("content-A"))
	_ = priv
	sumB := sha256.Sum256([]byte("content-B"))
	digestB := hex.EncodeToString(sumB[:])

	// Same key + valid signature, but verified against B's digest -> reject.
	if v := ValidateSignature(digestB, pub, sigA); !v.IsReject() || v.Code != RejectSignatureInvalid {
		t.Fatalf("signature for A verified against B's digest: %s (want S3 invalid reject)", v)
	}
	// Sanity floor: the same signature DOES verify against its own digest.
	if v := ValidateSignature(digestA, pub, sigA); v.IsReject() {
		t.Fatalf("valid signature rejected against its own digest: %s", v)
	}
}

// TestValidateSignatureRejectionMatrix exercises malformed-input rejection paths
// that protect S3 against degenerate/attacker-controlled signature & key bytes.
func TestValidateSignatureRejectionMatrix(t *testing.T) {
	pub, _, digest, goodSig := signArtifact(t, []byte("payload"))

	// A key of the correct LENGTH but wrong bytes (one bit flipped) must reject
	// with INVALID (not KeyInvalid): it is structurally a valid ed25519 key, it
	// just isn't the signer — proves we don't conflate "malformed key" with
	// "wrong key".
	flipped := make(ed25519.PublicKey, len(pub))
	copy(flipped, pub)
	flipped[0] ^= 0x01

	// Truncated signature (one byte short of SignatureSize) must reject.
	truncated := goodSig[:len(goodSig)-1]
	// Oversized signature (one byte long) must reject.
	oversized := append(append([]byte{}, goodSig...), 0x00)
	// Odd-length hex digest (not decodable) must reject as scope mismatch.
	oddHex := digest[:len(digest)-1]

	tests := []struct {
		name     string
		digest   string
		pub      ed25519.PublicKey
		sig      []byte
		wantCode RejectCode
	}{
		{"wrong key correct length", digest, flipped, goodSig, RejectSignatureInvalid},
		{"truncated signature", digest, pub, truncated, RejectSignatureInvalid},
		{"oversized signature", digest, pub, oversized, RejectSignatureInvalid},
		{"odd-length hex digest", oddHex, pub, goodSig, RejectSignatureScopeMismatch},
		{"empty-string digest", "", pub, goodSig, RejectSignatureScopeMismatch},
		{"key one byte too long", digest, append(append(ed25519.PublicKey{}, pub...), 0x00), goodSig, RejectSignatureKeyInvalid},
		{"nil key", digest, nil, goodSig, RejectSignatureKeyInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidateSignature(tc.digest, tc.pub, tc.sig)
			if !v.IsReject() {
				t.Fatalf("input ACCEPTED, want reject %s: %s", tc.wantCode, v)
			}
			if v.Code != tc.wantCode {
				t.Fatalf("code=%s want %s (%s)", v.Code, tc.wantCode, v)
			}
		})
	}
}

// --- ValidateHash: parseHashFile boundary branches ---------------------------

// TestParseHashFileEmptyFields reaches the len(fields)==0 branch of
// parseHashFile (whitespace-only content). ValidateHash's own TrimSpace guard
// catches the all-whitespace case at the call site, so the empty-fields branch
// is exercised via a direct parseHashFile call — the function is reusable by
// other callers that do not pre-trim.
func TestParseHashFileEmptyFields(t *testing.T) {
	if _, ok := parseHashFile("   \t\n  "); ok {
		t.Fatal("whitespace-only hash file parsed as a digest")
	}
	if _, ok := parseHashFile(""); ok {
		t.Fatal("empty hash file parsed as a digest")
	}
}

// TestValidateHashFilenameOnlyRejected proves a hash file containing only a
// filename (no digest) is rejected as malformed — the first field is taken as
// the candidate digest and must fail the SHA-256 contract.
func TestValidateHashFilenameOnlyRejected(t *testing.T) {
	v, got, n := ValidateHash(bytes.NewReader([]byte("abc")), "ota.zip\n")
	if !v.IsReject() || v.Code != RejectHashFileMalformed {
		t.Fatalf("filename-only hash file: %s (want S2 malformed reject)", v)
	}
	if got != "" {
		t.Fatalf("rejected hash returned a digest %q, want empty", got)
	}
	if n != -1 {
		t.Fatalf("rejected hash returned byte count %d, want -1 (nothing measured on this early-reject path; 0 is reserved for a measured-empty artifact)", n)
	}
}

// TestValidateHashReaderError proves a read failure on the artifact stream is a
// rejection (S2 hash mismatch), never a silent pass — a truncated/aborted
// upload must not be treated as valid.
func TestValidateHashReaderError(t *testing.T) {
	sum := sha256.Sum256([]byte("anything"))
	digest := hex.EncodeToString(sum[:])
	v, got, n := ValidateHash(errReader{}, digest)
	if !v.IsReject() || v.Code != RejectHashMismatch {
		t.Fatalf("reader error: %s (want S2 mismatch reject)", v)
	}
	if got != "" {
		t.Fatalf("errored hash returned digest %q, want empty", got)
	}
	if n != 0 {
		t.Fatalf("errored hash returned byte count %d, want 0 (errReader fails on the first Read)", n)
	}
}

// errReader fails on the first Read — models a broken/aborted upload stream.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, errEmptyVersion }

// --- CompareDotted: second-argument error branch -----------------------------

// TestCompareDottedSecondArgError covers the branch where the FIRST version
// parses but the SECOND does not (the existing table only errors on the first
// argument). Both orderings of the parse error must surface as an error so a
// corrupt prior-version lookup can never be silently treated as "equal".
func TestCompareDottedSecondArgError(t *testing.T) {
	if _, err := CompareDotted("1.0.0", "1.x.0"); err == nil {
		t.Fatal("CompareDotted with unparseable SECOND arg returned nil error")
	}
	if _, err := CompareDotted("1.0.0", ""); err == nil {
		t.Fatal("CompareDotted with empty SECOND arg returned nil error")
	}
	// And via the stage: an unparseable currentVersion must reject, not pass.
	v := ValidateVersion("1.0.0", "1.x.0", nil)
	if !v.IsReject() || v.Code != RejectVersionUnparseable {
		t.Fatalf("ValidateVersion with corrupt currentVersion: %s (want S4 unparseable)", v)
	}
}

// --- end-to-end: a fully valid artifact is accepted (positive control) -------

// TestEndToEndValidArtifactAccepted is the positive control for the security
// suite: an artifact whose bytes, hash file, signature, version, target and
// metadata are all mutually consistent passes all five stages. Without this,
// the rejection tests above could be passing for the wrong reason (everything
// rejected). It records all five stage verdicts in order.
func TestEndToEndValidArtifactAccepted(t *testing.T) {
	payload := []byte("fully consistent OTA artifact bytes")
	pub, _, digest, sig := signArtifact(t, payload)

	in := Input{
		Artifact:       bytes.NewReader(payload),
		HashFile:       digest + "  ota.zip\n",
		PublicKey:      pub,
		Signature:      sig,
		CurrentVersion: "1.3.0",
		Meta: otaprotocol.ArtifactMeta{
			SHA256:    digest,
			Size:      int64(len(payload)),
			OSType:    otaprotocol.OSAndroid,
			Board:     "rk3588",
			Version:   "1.4.0",
			Signature: hex.EncodeToString(sig),
		},
		TargetPolicy: NewStaticTargetPolicy(nil,
			[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}}),
	}

	res := Validate(in)
	if !res.Accepted() {
		t.Fatalf("fully consistent artifact REJECTED at %s: %s", res.Final.Stage, res.Final)
	}
	if len(res.Verdicts) != 5 {
		t.Fatalf("expected all 5 stages to run, got %d: %v", len(res.Verdicts), res.Verdicts)
	}
	wantOrder := []Stage{StageHash, StageSignature, StageVersion, StageTarget, StageMetadata}
	for i, want := range wantOrder {
		if res.Verdicts[i].Stage != want {
			t.Fatalf("stage %d = %s, want %s (S2..S6 order broken)", i, res.Verdicts[i].Stage, want)
		}
		if res.Verdicts[i].IsReject() {
			t.Fatalf("stage %s unexpectedly rejected: %s", want, res.Verdicts[i])
		}
	}
	if res.ComputedSHA256 != digest {
		t.Fatalf("ComputedSHA256=%q want %q", res.ComputedSHA256, digest)
	}
	// Reject string must never leak key material.
	for _, v := range res.Verdicts {
		if strings.Contains(v.String(), hex.EncodeToString(pub)) {
			t.Fatal("verdict string leaked public key material")
		}
	}
}
