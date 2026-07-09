package otavalidator

// This file closes a real gap found during the §11.4.102 systematic-debugging
// audit of 2026-07-10: nothing in the S2..S6 pipeline ever cross-checked the
// caller-declared otaprotocol.ArtifactMeta.Size against the ACTUAL number of
// bytes read from the artifact stream. ValidateHash computed the SHA-256 via
// io.Copy(h, r) and DISCARDED the returned byte count (`if _, err :=
// io.Copy(h, r); err != nil`), so a forged/incorrect declared Size sailed
// through S6 ("metadata sanity + consistency with the S2 digest") as long as
// the SHA-256 and signature were correct for the real bytes. Size is
// caller-controlled (attacker-influenceable, part of the uploaded metadata)
// and is later relied on downstream (Content-Length / Range-serving to
// devices per otaprotocol.UpdateAvailable.Size), so an unverified Size lie is
// a real metadata-integrity defect, not a hypothetical one.
//
// RED->GREEN proof captured under qa-results/audit_20260710/: a throwaway RED
// probe (TestREDPROBE_SizeLieCurrentlyAccepted, since removed) confirmed the
// pre-fix pipeline returned Accepted()=true, Final=PASS S6 for an artifact
// declaring Size=1000058 while the real payload was 59 bytes. See
// TestS6SizeMismatchRejected below for the permanent regression guard.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

// TestValidateHashReturnsActualByteCount proves ValidateHash's third return
// value is the REAL number of bytes streamed through SHA-256, across boundary
// sizes (0, 1, large), independent of whatever the caller later claims in
// ArtifactMeta.Size.
func TestValidateHashReturnsActualByteCount(t *testing.T) {
	for _, size := range []int{0, 1, 2, 1 << 20} {
		size := size
		t.Run(sizeName(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x42}, size)
			sum := sha256.Sum256(payload)
			digest := hex.EncodeToString(sum[:])

			v, gotDigest, gotSize := ValidateHash(bytes.NewReader(payload), digest)
			if !v.Passed {
				t.Fatalf("want pass, got %s", v)
			}
			if gotDigest != digest {
				t.Fatalf("digest=%q want %q", gotDigest, digest)
			}
			if gotSize != int64(size) {
				t.Fatalf("byte count=%d want %d", gotSize, size)
			}
		})
	}
}

func sizeName(n int) string {
	switch n {
	case 0:
		return "zero-bytes"
	case 1:
		return "one-byte"
	default:
		return "many-bytes"
	}
}

// TestValidateHashByteCountOnFailurePaths proves the byte-count return value
// is well-defined (never garbage, never a false non-zero success signal) on
// every ValidateHash rejection path.
func TestValidateHashByteCountOnFailurePaths(t *testing.T) {
	t.Run("empty hash file: nothing measured, sentinel -1", func(t *testing.T) {
		v, digest, n := ValidateHash(bytes.NewReader([]byte("abc")), "")
		if !v.IsReject() || v.Code != RejectHashFileMissing {
			t.Fatalf("want RejectHashFileMissing, got %s", v)
		}
		// -1 (not 0) is the "not measured" sentinel: no bytes were ever read
		// on this path, and 0 is reserved for a genuine measured-empty
		// artifact (see ValidateMetadata's actualSize>=0 enforcement).
		if digest != "" || n != -1 {
			t.Fatalf("want digest=\"\" n=-1 on early-reject, got digest=%q n=%d", digest, n)
		}
	})
	t.Run("malformed hash file: nothing measured, sentinel -1", func(t *testing.T) {
		v, digest, n := ValidateHash(bytes.NewReader([]byte("abc")), "not-a-digest")
		if !v.IsReject() || v.Code != RejectHashFileMalformed {
			t.Fatalf("want RejectHashFileMalformed, got %s", v)
		}
		if digest != "" || n != -1 {
			t.Fatalf("want digest=\"\" n=-1 on early-reject, got digest=%q n=%d", digest, n)
		}
	})
	t.Run("mismatch: byte count reflects what was actually read", func(t *testing.T) {
		other := sha256.Sum256([]byte("something else entirely"))
		payload := []byte("actual payload bytes")
		wantDigest := sha256.Sum256(payload)
		v, digest, n := ValidateHash(bytes.NewReader(payload), hex.EncodeToString(other[:]))
		if !v.IsReject() || v.Code != RejectHashMismatch {
			t.Fatalf("want RejectHashMismatch, got %s", v)
		}
		// On a plain mismatch (as opposed to a read error) ValidateHash still
		// returns the digest it actually computed from the real bytes — only a
		// read error yields an empty digest. Lock this distinction down.
		if digest != hex.EncodeToString(wantDigest[:]) {
			t.Fatalf("want computed digest %q on plain mismatch, got %q", hex.EncodeToString(wantDigest[:]), digest)
		}
		if n != int64(len(payload)) {
			t.Fatalf("want byte count %d (bytes were fully read before the mismatch was detected), got %d",
				len(payload), n)
		}
	})
	t.Run("read error: byte count reflects bytes read before the fault", func(t *testing.T) {
		sum := sha256.Sum256([]byte("anything"))
		digestStr := hex.EncodeToString(sum[:])
		v, digest, n := ValidateHash(errReader{}, digestStr)
		if !v.IsReject() || v.Code != RejectHashMismatch {
			t.Fatalf("want RejectHashMismatch, got %s", v)
		}
		if digest != "" {
			t.Fatalf("want empty digest on read-error path, got %q", digest)
		}
		if n != 0 {
			t.Fatalf("errReader fails on the first Read; want n=0, got %d", n)
		}
	})
}

// TestValidateHashReusableSeekableReader directly isolates the documented
// "rewind a Seeker to position 0" behavior of ValidateHash (previously only
// exercised indirectly, by stress tests reusing a fixture's *bytes.Reader
// across sequential Validate calls). Proves: (1) a reader already fully
// consumed (at EOF) before ValidateHash is called is correctly rewound and
// re-hashed; (2) a reader positioned mid-stream is rewound to the true start,
// not left wherever the caller left it; (3) the byte count returned reflects
// the FULL rewound read, not just what remained from the prior position.
func TestValidateHashReusableSeekableReader(t *testing.T) {
	payload := []byte("a reusable seekable artifact reader payload")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	t.Run("reader already at EOF is rewound and re-hashed correctly", func(t *testing.T) {
		r := bytes.NewReader(payload)
		// Fully drain the reader first, simulating a caller (or a prior
		// Validate call) that already consumed it.
		if _, err := r.Seek(0, 2 /* io.SeekEnd */); err != nil {
			t.Fatalf("seek to end: %v", err)
		}
		v, gotDigest, gotSize := ValidateHash(r, digest)
		if !v.Passed {
			t.Fatalf("want pass on rewound reader, got %s", v)
		}
		if gotDigest != digest || gotSize != int64(len(payload)) {
			t.Fatalf("rewound hash wrong: digest=%q size=%d want digest=%q size=%d",
				gotDigest, gotSize, digest, len(payload))
		}
	})

	t.Run("reader positioned mid-stream is rewound to true start, not left mid-stream", func(t *testing.T) {
		r := bytes.NewReader(payload)
		// Advance partway through the buffer before handing it to ValidateHash.
		mid := make([]byte, len(payload)/2)
		if _, err := r.Read(mid); err != nil {
			t.Fatalf("partial read: %v", err)
		}
		v, gotDigest, gotSize := ValidateHash(r, digest)
		if !v.Passed {
			t.Fatalf("want pass (rewound to true start), got %s", v)
		}
		if gotDigest != digest || gotSize != int64(len(payload)) {
			t.Fatalf("mid-stream rewind wrong: digest=%q size=%d want digest=%q size=%d (partial-read residue leaked through)",
				gotDigest, gotSize, digest, len(payload))
		}
	})

	t.Run("same reader validated twice in a row yields identical results both times", func(t *testing.T) {
		r := bytes.NewReader(payload)
		v1, d1, n1 := ValidateHash(r, digest)
		v2, d2, n2 := ValidateHash(r, digest)
		if !v1.Passed || !v2.Passed {
			t.Fatalf("both calls must pass: v1=%s v2=%s", v1, v2)
		}
		if d1 != d2 || n1 != n2 {
			t.Fatalf("repeat validation of the same Seeker-backed reader diverged: (%q,%d) vs (%q,%d)", d1, n1, d2, n2)
		}
	})
}

// --- the real defect: S6 never cross-checked declared Size vs actual bytes --

// signedArtifactForSize builds a fully self-consistent signed artifact (valid
// hash, valid signature, valid target, valid version) whose ONLY declared lie
// is in in.Meta.Size, allowing the test to isolate the Size cross-check in
// total independence from every other stage.
func signedArtifactForSize(t *testing.T, payload []byte, declaredSize int64) Input {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, sum[:])
	meta := otaprotocol.ArtifactMeta{
		SHA256:    digest,
		Size:      declaredSize, // <-- may be a LIE relative to len(payload)
		OSType:    otaprotocol.OSAndroid,
		Board:     "rk3588",
		Version:   "1.4.0",
		Signature: hex.EncodeToString(sig),
	}
	policy := NewStaticTargetPolicy(
		nil,
		[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}},
	)
	return Input{
		Artifact:     bytes.NewReader(payload),
		HashFile:     digest + "  ota.zip\n",
		PublicKey:    pub,
		Signature:    sig,
		Meta:         meta,
		TargetPolicy: policy,
	}
}

// TestS6SizeMismatchRejected is the RED->GREEN proof for the real defect: an
// artifact whose bytes/hash/signature/target/version are ALL genuinely valid,
// but whose declared Meta.Size does NOT match the real number of bytes in the
// artifact stream, MUST be rejected by the pipeline (S6 metadata
// inconsistency) — not silently accepted just because the hash and signature
// happen to be correct for the real bytes.
//
// Before the fix this defect was reproduced by a throwaway RED probe: the
// pipeline returned Accepted()=true, Final=PASS S6 for declaredSize=1000058
// vs actualSize=59 (captured in qa-results/audit_20260710/).
func TestS6SizeMismatchRejected(t *testing.T) {
	payload := []byte("the genuine, correctly-hashed-and-signed OTA artifact bytes")
	lie := int64(len(payload)) + 999_999 // wildly wrong declared size

	in := signedArtifactForSize(t, payload, lie)
	res := Validate(in)

	if res.Accepted() {
		t.Fatalf("CRITICAL: artifact with forged Meta.Size (declared=%d, actual=%d) was ACCEPTED", lie, len(payload))
	}
	if res.Final.Stage != StageMetadata || res.Final.Code != RejectMetadataSizeMismatch {
		t.Fatalf("want S6/%s, got %s", RejectMetadataSizeMismatch, res.Final)
	}
}

// TestS6SizeMismatchOffByOne proves an off-by-one lie (declared size one byte
// away from the truth) is caught too — not just wildly-wrong values.
func TestS6SizeMismatchOffByOne(t *testing.T) {
	payload := bytes.Repeat([]byte{0x9}, 4096)
	in := signedArtifactForSize(t, payload, int64(len(payload))+1)
	res := Validate(in)
	if res.Accepted() {
		t.Fatal("off-by-one Meta.Size lie was ACCEPTED")
	}
	if res.Final.Stage != StageMetadata || res.Final.Code != RejectMetadataSizeMismatch {
		t.Fatalf("want S6/%s, got %s", RejectMetadataSizeMismatch, res.Final)
	}
}

// TestS6SizeMatchAccepted is the positive control: a truthful declared Size
// (matching the real byte count) must still pass — proves the new check does
// not false-reject a genuine artifact.
func TestS6SizeMatchAccepted(t *testing.T) {
	payload := []byte("truthfully-sized OTA artifact payload")
	in := signedArtifactForSize(t, payload, int64(len(payload)))
	res := Validate(in)
	if !res.Accepted() {
		t.Fatalf("truthful Meta.Size was rejected: %s", res.Final)
	}
}

// TestS6ZeroByteArtifactForgedSizeRejected is the RED->GREEN proof for the
// zero-byte hole found in the §11.4.134 code-review of TestS6SizeMismatchRejected
// above: a genuinely EMPTY (0-byte) artifact is a real, representable case —
// io.Copy returns n=0 with no error, and the SHA-256 of the empty string
// (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) is a
// perfectly ordinary, valid digest. A prior version of the ValidateMetadata
// guard used `actualSize > 0` as its enforcement condition, which treated a
// MEASURED 0 (S2 genuinely streamed zero bytes through the hash) exactly like
// the "nothing was measured" sentinel — so for any artifact whose real byte
// count is 0, the size cross-check was SKIPPED and a forged Meta.Size sailed
// through S6 untouched, even though S2 had already produced the real (zero)
// count.
//
// RED (pre-fix guard `actualSize > 0`): builds a REAL 0-byte artifact (empty
// reader, hash file = SHA-256 of the empty string) with a lying
// Meta.Size=999999, runs it through the full S2..S6 Validate pipeline, and
// the forged size is ACCEPTED (0 > 0 is false, size check skipped). Captured
// pre-fix and post-fix runs in
// qa-results/audit_20260710/RED_GREEN_zerobyte_size.txt.
//
// GREEN (post-fix guard `actualSize >= 0`): the same input is REJECTED at S6
// with RejectMetadataSizeMismatch (0 >= 0 is true, 999999 != 0 is enforced).
func TestS6ZeroByteArtifactForgedSizeRejected(t *testing.T) {
	in := signedArtifactForSize(t, []byte{}, 999_999) // real payload is 0 bytes; declared size is a lie
	res := Validate(in)

	if res.Accepted() {
		t.Fatalf("CRITICAL: 0-byte artifact with forged Meta.Size=999999 (actual=0) was ACCEPTED: %s", res.Final)
	}
	if res.Final.Stage != StageMetadata || res.Final.Code != RejectMetadataSizeMismatch {
		t.Fatalf("want S6/%s, got %s", RejectMetadataSizeMismatch, res.Final)
	}
}

// TestS6ZeroByteArtifactHonestSizeStructurallyRejectedUpstream documents a
// real, independently-discovered fact (captured, not guessed, per §11.4.6):
// an HONESTLY-declared Meta.Size=0 can NEVER reach ACCEPTED via S6, with or
// without this fix, because otaprotocol.ValidateArtifactMeta (see
// submodules/ota-protocol/validate.go, `if m.Size <= 0 { return ... }`)
// unconditionally requires Size > 0 as a metadata-completeness rule — BEFORE
// ValidateMetadata's own size cross-check is ever reached. There is no legal
// ArtifactMeta with Size==0 in this protocol: a 0-byte OTA package is
// nonsensical (nothing to install) and is rejected at the metadata-contract
// layer with RejectMetadataIncomplete, not RejectMetadataSizeMismatch.
//
// This test exists so the "positive control: a real 0-byte artifact with
// honest Meta.Size=0 must be ACCEPTED" scenario is proven FALSE-BY-DESIGN
// rather than silently assumed — the fix above does not change this outcome
// at all (the input was rejected before the fix and is rejected after it,
// same stage, same code), so the fix introduces no regression here. The
// genuine "does the >=0 boundary change false-reject a legitimate artifact"
// proof is TestS6OneByteArtifactHonestSizeAccepted below, at the smallest
// PROTOCOL-LEGAL boundary.
func TestS6ZeroByteArtifactHonestSizeStructurallyRejectedUpstream(t *testing.T) {
	in := signedArtifactForSize(t, []byte{}, 0) // honest: declared size matches the real 0-byte payload
	res := Validate(in)

	if res.Accepted() {
		t.Fatalf("unexpected ACCEPT: an honestly-declared Meta.Size=0 artifact should be structurally rejected upstream, got %s", res.Final)
	}
	if res.Final.Stage != StageMetadata || res.Final.Code != RejectMetadataIncomplete {
		t.Fatalf("want S6/%s (Meta.Size=0 fails otaprotocol.ValidateArtifactMeta's Size>0 rule before the size cross-check runs), got %s",
			RejectMetadataIncomplete, res.Final)
	}
}

// TestS6OneByteArtifactHonestSizeAccepted is the genuine positive control for
// the actualSize>=0 boundary this fix changed: the smallest PROTOCOL-LEGAL
// artifact (1 byte, since Meta.Size must be > 0) whose honestly-declared
// Meta.Size matches the real measured byte count must still be ACCEPTED —
// proving the >=0 guard does not false-reject a genuine artifact adjacent to
// the zero boundary.
func TestS6OneByteArtifactHonestSizeAccepted(t *testing.T) {
	in := signedArtifactForSize(t, []byte{0x01}, 1)
	res := Validate(in)
	if !res.Accepted() {
		t.Fatalf("honest 1-byte artifact (Meta.Size=1, actual=1) was rejected: %s", res.Final)
	}
}

// TestValidateMetadataSizeCrossCheck exercises ValidateMetadata directly
// (unit-level, bypassing the full pipeline) across the size-consistency
// matrix: matching size passes, mismatched size rejects, and actualSize<0
// (the "not measured" skip sentinel, symmetric with computedDigest=="") does
// not false-reject. A MEASURED actualSize==0 (a genuine empty artifact) is
// NOT a skip sentinel — it enforces meta.Size == 0, same as any other
// measured value (see the "actualSize==0" subtest below and
// TestS6ZeroByteArtifactForgedSizeRejected).
func TestValidateMetadataSizeCrossCheck(t *testing.T) {
	sum := sha256.Sum256([]byte("payload"))
	digest := hex.EncodeToString(sum[:])
	good := otaprotocol.ArtifactMeta{
		SHA256:    digest,
		Size:      7,
		OSType:    otaprotocol.OSAndroid,
		Board:     "rk3588",
		Version:   "1.0.0",
		Signature: "sig",
	}

	t.Run("matching size passes", func(t *testing.T) {
		if v := ValidateMetadata(good, digest, 7); !v.Passed {
			t.Fatalf("want pass, got %s", v)
		}
	})
	t.Run("mismatched size rejects", func(t *testing.T) {
		v := ValidateMetadata(good, digest, 8)
		if v.Passed || v.Code != RejectMetadataSizeMismatch {
			t.Fatalf("want RejectMetadataSizeMismatch, got %s", v)
		}
	})
	t.Run("actualSize<0 (not measured) skips the size cross-check", func(t *testing.T) {
		if v := ValidateMetadata(good, digest, -1); !v.Passed {
			t.Fatalf("want pass (size check skipped), got %s", v)
		}
	})
	t.Run("actualSize==0 (measured empty) enforces the size cross-check, does not skip", func(t *testing.T) {
		// good.Size == 7, so a MEASURED 0 must be treated as a real,
		// enforceable measurement — NOT the "not measured" skip sentinel.
		// This is the exact hole the §11.4.134 review found: a prior
		// `actualSize > 0` guard treated measured-zero the same as
		// not-measured and let a forged Meta.Size sail through for the
		// 0-byte-artifact case.
		v := ValidateMetadata(good, digest, 0)
		if v.Passed || v.Code != RejectMetadataSizeMismatch {
			t.Fatalf("want RejectMetadataSizeMismatch (measured 0 != declared %d), got %s", good.Size, v)
		}
	})
	t.Run("digest mismatch still takes priority over size", func(t *testing.T) {
		other := sha256.Sum256([]byte("different"))
		v := ValidateMetadata(good, hex.EncodeToString(other[:]), 7)
		if v.Passed || v.Code != RejectMetadataInconsistent {
			t.Fatalf("want RejectMetadataInconsistent (digest checked first), got %s", v)
		}
	})
}
