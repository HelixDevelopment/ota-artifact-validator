package otavalidator

// TestSHA512IsFormatOnlyNotContentVerified documents an intentional scope
// boundary found during the §11.4.102 systematic-debugging audit of
// 2026-07-10, distinct from the Meta.Size gap fixed in validator_size_test.go:
//
// otaprotocol.ArtifactMeta.SHA512 is documented as OPTIONAL ("where
// available") supplementary metadata. This library's S2 stage computes and
// verifies ONLY a SHA-256 digest (the actual trust anchor bound to the
// ed25519 signature in S3); it never computes a SHA-512 over the artifact
// bytes at all. Consequently otaprotocol.ValidateArtifactMeta (delegated to
// by S6) checks SHA512 for FORMAT ONLY (128 lowercase-hex chars) when
// present — it is never cross-checked against the real artifact bytes,
// unlike SHA256 (verified in S2) and Size (verified in S6 as of this audit).
//
// This is NOT a fabricated defect and NOT "fixed" here: SHA-256 + the
// detached ed25519 signature over it is the documented trust chain
// (security/signing_verification.md); SHA512 is supplementary/informational.
// Computing a second full-artifact hash would be a real design change (a new
// S2b stage, a second full read or a multi-writer io.Copy), not a bug fix,
// and is explicitly out of this audit's "fix real defects" scope. This test
// exists so the boundary is asserted and visible rather than silently
// undocumented — a future change to make SHA512 load-bearing must consciously
// break this test, not discover the gap by accident.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

func TestSHA512IsFormatOnlyNotContentVerified(t *testing.T) {
	payload := []byte("sha512-scope-boundary-payload")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, sum[:])

	// A syntactically well-formed SHA-512 (128 lowercase hex chars) that is
	// PROVABLY NOT the real SHA-512 of payload (it's the hex of 64 zero
	// bytes). If SHA512 were content-verified, this artifact would be
	// rejected; per the documented scope boundary, it is accepted.
	forgedSHA512 := hex.EncodeToString(make([]byte, 64))

	meta := otaprotocol.ArtifactMeta{
		SHA256:    digest,
		SHA512:    forgedSHA512,
		Size:      int64(len(payload)),
		OSType:    otaprotocol.OSAndroid,
		Board:     "rk3588",
		Version:   "1.4.0",
		Signature: hex.EncodeToString(sig),
	}
	policy := NewStaticTargetPolicy(nil, []TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}})
	in := Input{
		Artifact:     bytes.NewReader(payload),
		HashFile:     digest + "  ota.zip\n",
		PublicKey:    pub,
		Signature:    sig,
		Meta:         meta,
		TargetPolicy: policy,
	}

	res := Validate(in)
	if !res.Accepted() {
		t.Fatalf("documented scope boundary violated: a forged-but-well-formed SHA512 unexpectedly caused a rejection (%s) — "+
			"if SHA512 content-verification was intentionally added, update this test to match the new contract, do not just delete it",
			res.Final)
	}
}
