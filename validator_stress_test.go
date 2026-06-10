package otavalidator

// §11.4.85 stress coverage for the ota-artifact-validator brick.
//
// The validator is a pure, allocation-only library (no disk/network/db), so
// "stress" here means: sustained-load loops, high-concurrency contention over
// the SAME shared inputs (TargetPolicy maps + the ed25519 public key are read
// concurrently), and boundary inputs. Every PASS cites a real, asserted
// invariant — never a metadata-only "it ran" PASS:
//   - concurrent verdicts MUST be correct AND identical to the serial verdict
//     for the same input (no shared-state corruption under -race);
//   - the validator MUST NEVER accept a corrupted artifact and MUST NEVER
//     panic — every input yields a categorised Verdict;
//   - sustained loops categorise every outcome and assert the category split.
//
// Determinism (§11.4.50) is exercised by running the whole suite under
// `go test -race -count=3`: every assertion holds identically across runs.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

// --- parameterized fixtures for stress/chaos ------------------------------

// signedArtifact is a self-consistent, fully valid artifact for a given
// payload, plus the keypair that signed it. It is the trusted baseline that
// the chaos tests then corrupt one dimension at a time.
type signedArtifact struct {
	payload  []byte
	digest   string // lowercase-hex SHA-256 of payload
	hashFile string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	sig      []byte
	meta     otaprotocol.ArtifactMeta
	policy   TargetPolicy
}

// newSignedArtifact builds a valid signedArtifact over payload with a fresh
// keypair. The returned artifact is accepted by the full pipeline.
func newSignedArtifact(tb testing.TB, payload []byte) signedArtifact {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("keygen: %v", err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, sum[:])
	meta := otaprotocol.ArtifactMeta{
		SHA256:    digest,
		Size:      int64(len(payload)),
		OSType:    otaprotocol.OSAndroid,
		Board:     "rk3588",
		Version:   "1.4.0",
		Signature: hex.EncodeToString(sig),
	}
	policy := NewStaticTargetPolicy(
		nil,
		[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}},
	)
	return signedArtifact{
		payload:  payload,
		digest:   digest,
		hashFile: digest + "  ota.zip\n",
		pub:      pub,
		priv:     priv,
		sig:      sig,
		meta:     meta,
		policy:   policy,
	}
}

// input returns a fresh pipeline Input (fresh Artifact reader each call so the
// same fixture can be validated repeatedly / concurrently).
func (a signedArtifact) input() Input {
	return Input{
		Artifact:       bytes.NewReader(a.payload),
		HashFile:       a.hashFile,
		PublicKey:      a.pub,
		Signature:      a.sig,
		CurrentVersion: "1.3.0",
		Meta:           a.meta,
		TargetPolicy:   a.policy,
	}
}

// --- concurrency: shared-state correctness under -race --------------------

// TestStressConcurrentValidation runs the full pipeline from many goroutines
// over a MIX of valid + invalid inputs sharing the SAME TargetPolicy and the
// SAME ed25519 public key (the read-shared state). Under -race this proves the
// validator has no data race and no shared-state corruption: every concurrent
// verdict matches the verdict computed serially for the same case.
func TestStressConcurrentValidation(t *testing.T) {
	good := newSignedArtifact(t, []byte("concurrent-valid-artifact-payload"))

	// Each case is (label, mutate, expected verdict). The expected verdict is
	// computed serially first, then asserted under concurrency.
	type vcase struct {
		name   string
		mutate func(*Input)
	}
	cases := []vcase{
		{"valid", func(*Input) {}},
		{"hash-mismatch", func(in *Input) { in.Artifact = bytes.NewReader([]byte("tampered")) }},
		{"sig-missing", func(in *Input) { in.Signature = nil }},
		{"wrong-key", func(in *Input) {
			otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
			in.PublicKey = otherPub
		}},
		{"downgrade", func(in *Input) { in.Meta.Version = "1.2.0" }},
		{"bad-target", func(in *Input) { in.Meta.Board = "unknown-board" }},
		{"meta-inconsistent", func(in *Input) {
			other := sha256.Sum256([]byte("different"))
			in.Meta.SHA256 = hex.EncodeToString(other[:])
		}},
	}

	// Serial baseline: the oracle each concurrent verdict must match.
	type want struct {
		accepted bool
		stage    Stage
		code     RejectCode
	}
	wants := make([]want, len(cases))
	for i, c := range cases {
		in := good.input()
		c.mutate(&in)
		res := Validate(in)
		wants[i] = want{res.Accepted(), res.Final.Stage, res.Final.Code}
	}
	// Sanity: the mix really does contain at least one accept and one reject —
	// otherwise the concurrency test would be vacuous.
	var nAccept, nReject int
	for _, w := range wants {
		if w.accepted {
			nAccept++
		} else {
			nReject++
		}
	}
	if nAccept == 0 || nReject == 0 {
		t.Fatalf("stress mix must contain both accepts and rejects: %d/%d", nAccept, nReject)
	}

	const goroutines = 32 // ≥20 per §11.4.85
	const perGoroutine = 50
	var wg sync.WaitGroup
	var mismatches int64
	var iterations int64
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for n := 0; n < perGoroutine; n++ {
				idx := (seed + n) % len(cases)
				in := good.input()
				cases[idx].mutate(&in)
				res := Validate(in)
				atomic.AddInt64(&iterations, 1)
				w := wants[idx]
				if res.Accepted() != w.accepted ||
					res.Final.Stage != w.stage ||
					res.Final.Code != w.code {
					atomic.AddInt64(&mismatches, 1)
				}
			}
		}(g)
	}
	wg.Wait()

	if mismatches != 0 {
		t.Fatalf("concurrent verdict mismatched serial oracle %d times out of %d", mismatches, iterations)
	}
	wantIters := int64(goroutines * perGoroutine)
	if iterations != wantIters {
		t.Fatalf("ran %d iterations, want %d", iterations, wantIters)
	}
	t.Logf("§11.4.85 stress/concurrent: %d goroutines × %d = %d verdicts, 0 mismatches, 0 races",
		goroutines, perGoroutine, iterations)
}

// TestStressConcurrentStageHelpers hammers the two cryptographic stage helpers
// directly (ValidateHash streams + hashes; ValidateSignature ed25519-verifies)
// concurrently against the same shared public key. A torn read of the shared
// key or a hashing-buffer race would surface here under -race as a wrong verdict.
func TestStressConcurrentStageHelpers(t *testing.T) {
	a := newSignedArtifact(t, bytes.Repeat([]byte("S"), 4096))

	const goroutines = 24
	const iters = 100
	var wg sync.WaitGroup
	var badHash, badSig int64
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for n := 0; n < iters; n++ {
				v, digest := ValidateHash(bytes.NewReader(a.payload), a.hashFile)
				if !v.Passed || digest != a.digest {
					atomic.AddInt64(&badHash, 1)
				}
				if sv := ValidateSignature(a.digest, a.pub, a.sig); !sv.Passed {
					atomic.AddInt64(&badSig, 1)
				}
			}
		}()
	}
	wg.Wait()
	if badHash != 0 || badSig != 0 {
		t.Fatalf("concurrent stage helpers produced wrong verdicts: badHash=%d badSig=%d", badHash, badSig)
	}
	t.Logf("§11.4.85 stress/stage-helpers: %d×%d hash+sig verifications, all correct, 0 races",
		goroutines, iters)
}

// --- sustained load: ≥100 iterations, categorised outcomes ----------------

// TestStressSustainedLoad runs ≥100 sustained full-pipeline validations over a
// rotating mix and categorises every outcome by reject code (or ACCEPT). The
// assertion is on the category split — proving the loop genuinely exercised
// both accept and the distinct reject paths, never silently degrading to "all
// pass" or "all fail" (the §11.4 PASS-bluff at the load layer).
func TestStressSustainedLoad(t *testing.T) {
	good := newSignedArtifact(t, []byte("sustained-load-payload"))

	type variant struct {
		name   string
		mutate func(*Input)
		want   RejectCode // "" means ACCEPT
	}
	variants := []variant{
		{"accept", func(*Input) {}, ""},
		{"hash", func(in *Input) { in.Artifact = bytes.NewReader([]byte("x")) }, RejectHashMismatch},
		{"sig", func(in *Input) { in.Signature = nil }, RejectSignatureMissing},
		{"ver", func(in *Input) { in.Meta.Version = "1.2.0" }, RejectNotMonotonic},
		{"tgt", func(in *Input) { in.Meta.Board = "nope" }, RejectTargetUnknown},
	}

	const iterations = 200 // ≥100 per §11.4.85
	categories := map[string]int{}
	for i := 0; i < iterations; i++ {
		v := variants[i%len(variants)]
		in := good.input()
		v.mutate(&in)
		res := Validate(in)

		if v.want == "" {
			if !res.Accepted() {
				t.Fatalf("iter %d (%s): expected ACCEPT, got %s", i, v.name, res.Final)
			}
			categories["ACCEPT"]++
			continue
		}
		if res.Accepted() {
			t.Fatalf("iter %d (%s): expected reject %s, got ACCEPT", i, v.name, v.want)
		}
		if res.Final.Code != v.want {
			t.Fatalf("iter %d (%s): code=%s want %s", i, v.name, res.Final.Code, v.want)
		}
		categories[string(v.want)]++
	}

	// Every category must have fired — proves the load mix was real.
	for _, v := range variants {
		key := "ACCEPT"
		if v.want != "" {
			key = string(v.want)
		}
		if categories[key] == 0 {
			t.Fatalf("category %q never observed across %d iterations", key, iterations)
		}
	}
	t.Logf("§11.4.85 stress/sustained: %d iterations, categories=%v", iterations, categories)
}

// --- boundary inputs ------------------------------------------------------

// TestStressBoundaryInputs feeds the pipeline + stage helpers boundary-sized
// and degenerate inputs. The validator MUST return a categorised Verdict for
// each (never panic, never accept a malformed input). For valid boundary
// payloads (empty payload, 1-byte, large payload) a correctly-signed artifact
// MUST be accepted — proving size does not break hashing/signing.
func TestStressBoundaryInputs(t *testing.T) {
	// Valid artifacts at boundary payload sizes must all be accepted. The
	// ota-protocol ArtifactMeta contract requires size > 0, so the smallest
	// VALID artifact is 1 byte; 0 bytes is covered as a reject case below.
	for _, size := range []int{1, 2, 1 << 20 /* 1 MiB */} {
		size := size
		t.Run(fmt.Sprintf("valid-payload-%d-bytes", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xAB}, size)
			a := newSignedArtifact(t, payload)
			a.meta.Size = int64(size)
			in := a.input()
			res := Validate(in)
			if !res.Accepted() {
				t.Fatalf("valid %d-byte artifact rejected: %s", size, res.Final)
			}
			if res.ComputedSHA256 != a.digest {
				t.Fatalf("computed digest %q != %q for %d-byte payload", res.ComputedSHA256, a.digest, size)
			}
		})
	}

	// 0-byte payload: hash + signature are well-formed and pass, but the
	// ota-protocol metadata contract correctly rejects size==0 at S6. The
	// validator MUST reject (never accept an empty artifact), and the digest
	// of the empty payload MUST still have been computed in S2 — proving the
	// boundary input flowed through the pipeline rather than panicking.
	t.Run("zero-byte-payload-rejected-at-S6", func(t *testing.T) {
		a := newSignedArtifact(t, nil) // empty payload, valid hash+sig over it
		a.meta.Size = 0
		in := a.input()
		res := Validate(in)
		if res.Accepted() {
			t.Fatal("validator ACCEPTED a zero-byte artifact")
		}
		if res.Final.Stage != StageMetadata || res.Final.Code != RejectMetadataIncomplete {
			t.Fatalf("zero-byte: want S6 RejectMetadataIncomplete, got %s", res.Final)
		}
		if res.ComputedSHA256 != a.digest {
			t.Fatalf("zero-byte digest not computed: got %q want %q", res.ComputedSHA256, a.digest)
		}
	})

	// Degenerate stage-helper inputs must be categorised rejects, never panics.
	a := newSignedArtifact(t, []byte("boundary"))
	boundary := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"empty-signature", func(t *testing.T) {
			if v := ValidateSignature(a.digest, a.pub, nil); v.Passed || v.Code != RejectSignatureMissing {
				t.Fatalf("empty sig: got %s", v)
			}
		}},
		{"empty-signature-slice", func(t *testing.T) {
			if v := ValidateSignature(a.digest, a.pub, []byte{}); v.Passed || v.Code != RejectSignatureMissing {
				t.Fatalf("empty sig slice: got %s", v)
			}
		}},
		{"wrong-length-key-short", func(t *testing.T) {
			if v := ValidateSignature(a.digest, ed25519.PublicKey{1, 2, 3}, a.sig); v.Passed || v.Code != RejectSignatureKeyInvalid {
				t.Fatalf("short key: got %s", v)
			}
		}},
		{"wrong-length-key-long", func(t *testing.T) {
			longKey := bytes.Repeat([]byte{0x07}, ed25519.PublicKeySize+1)
			if v := ValidateSignature(a.digest, ed25519.PublicKey(longKey), a.sig); v.Passed || v.Code != RejectSignatureKeyInvalid {
				t.Fatalf("long key: got %s", v)
			}
		}},
		{"nil-public-key", func(t *testing.T) {
			if v := ValidateSignature(a.digest, nil, a.sig); v.Passed || v.Code != RejectSignatureKeyInvalid {
				t.Fatalf("nil key: got %s", v)
			}
		}},
		{"empty-hashfile", func(t *testing.T) {
			if v, _ := ValidateHash(bytes.NewReader(a.payload), ""); v.Passed || v.Code != RejectHashFileMissing {
				t.Fatalf("empty hashfile: got %s", v)
			}
		}},
		{"empty-reader-with-hashfile", func(t *testing.T) {
			// Empty payload hashed against the digest of a non-empty payload =
			// mismatch, never a panic.
			if v, _ := ValidateHash(bytes.NewReader(nil), a.hashFile); v.Passed || v.Code != RejectHashMismatch {
				t.Fatalf("empty reader: got %s", v)
			}
		}},
	}
	for _, bc := range boundary {
		t.Run(bc.name, bc.run)
	}
}
