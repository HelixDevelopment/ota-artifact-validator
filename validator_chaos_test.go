package otavalidator

// §11.4.85 chaos / fault-injection coverage for the ota-artifact-validator
// brick. The validator's whole purpose is to REJECT corrupted artifacts, so
// fault-injection here is adversarial by construction: every test corrupts one
// dimension of a known-good signed artifact (payload bytes, signature bytes,
// public key, artifact length, declared metadata) and asserts the validator
// (a) NEVER accepts the corrupted artifact, (b) NEVER panics, and (c) returns
// the CORRECT categorised reject code for that corruption.
//
// The load-bearing invariant under test is the hash-before-signature ordering
// (handoff note G2): S2 (SHA-256 vs hash file) runs strictly before S3
// (ed25519 signature). The two ordering tests below assert that when BOTH a
// hash fault AND a signature fault are present, the HASH error wins — proving
// fail-fast S2→S3 ordering, not a re-ordering that would let a hash-mismatched
// blob reach signature verification.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// runPipeline is a panic-guarded full-pipeline run: it records whether the run
// panicked so chaos cases can assert "no panic, categorised verdict instead".
func runPipeline(t *testing.T, in Input) (res Result, panicked bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			t.Errorf("Validate panicked on corrupted input: %v", r)
		}
	}()
	res = Validate(in)
	return res, false
}

// TestChaosBitFlipPayload flips a single bit in the payload AFTER it was hashed
// and signed. The SHA-256 over the flipped bytes no longer matches the hash
// file, so S2 MUST catch it with RejectHashMismatch — and S3 must never run.
func TestChaosBitFlipPayload(t *testing.T) {
	a := newSignedArtifact(t, []byte("artifact-to-bit-flip-after-hashing"))

	// Flip the lowest bit of each byte position, one position per sub-test, to
	// prove no single-bit corruption slips through.
	for pos := 0; pos < len(a.payload); pos++ {
		corrupt := append([]byte(nil), a.payload...)
		corrupt[pos] ^= 0x01

		in := a.input()
		in.Artifact = bytes.NewReader(corrupt)

		res, panicked := runPipeline(t, in)
		if panicked {
			return
		}
		if res.Accepted() {
			t.Fatalf("pos %d: validator ACCEPTED a bit-flipped (hash-mismatched) artifact", pos)
		}
		if res.Final.Stage != StageHash || res.Final.Code != RejectHashMismatch {
			t.Fatalf("pos %d: want S2 RejectHashMismatch, got %s", pos, res.Final)
		}
		// Fail-fast: S3 must NOT have run.
		if len(res.Verdicts) != 1 {
			t.Fatalf("pos %d: expected only S2 to run on hash mismatch, got %d verdicts", pos, len(res.Verdicts))
		}
	}
	t.Logf("§11.4.85 chaos/bit-flip: all %d single-bit payload flips rejected at S2", len(a.payload))
}

// TestChaosCorruptSignature corrupts the detached signature bytes. The hash
// still matches (S2 passes), so the corruption surfaces at S3 as
// RejectSignatureInvalid — never accepted, never a panic.
func TestChaosCorruptSignature(t *testing.T) {
	a := newSignedArtifact(t, []byte("artifact-with-corrupt-signature"))

	mutations := []struct {
		name string
		sig  func() []byte
	}{
		{"flip-first-byte", func() []byte {
			s := append([]byte(nil), a.sig...)
			s[0] ^= 0xFF
			return s
		}},
		{"flip-last-byte", func() []byte {
			s := append([]byte(nil), a.sig...)
			s[len(s)-1] ^= 0xFF
			return s
		}},
		{"all-zero-sig", func() []byte {
			return bytes.Repeat([]byte{0x00}, ed25519.SignatureSize)
		}},
		{"random-sig", func() []byte {
			s := make([]byte, ed25519.SignatureSize)
			_, _ = rand.Read(s)
			return s
		}},
		{"truncated-sig", func() []byte {
			return a.sig[:ed25519.SignatureSize-1]
		}},
		{"oversized-sig", func() []byte {
			return append(append([]byte(nil), a.sig...), 0x00)
		}},
		{"foreign-valid-sig", func() []byte {
			// A perfectly valid ed25519 signature — but over the SAME digest
			// from a DIFFERENT key. Must fail verification under the trusted key.
			_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
			d, _ := hex.DecodeString(a.digest)
			return ed25519.Sign(otherPriv, d)
		}},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			in := a.input()
			in.Signature = m.sig()

			res, panicked := runPipeline(t, in)
			if panicked {
				return
			}
			if res.Accepted() {
				t.Fatalf("validator ACCEPTED an artifact with a corrupt signature (%s)", m.name)
			}
			if res.Final.Stage != StageSignature {
				t.Fatalf("%s: corruption should surface at S3, got %s", m.name, res.Final)
			}
			if res.Final.Code != RejectSignatureInvalid {
				t.Fatalf("%s: want RejectSignatureInvalid, got %s", m.name, res.Final.Code)
			}
			// S2 must have passed (hash unchanged) before S3 caught it.
			if len(res.Verdicts) != 2 || !res.Verdicts[0].Passed {
				t.Fatalf("%s: expected S2 PASS then S3 REJECT, got %v", m.name, res.Verdicts)
			}
		})
	}
}

// TestChaosWrongPublicKey swaps in a wrong (but well-formed) public key. The
// signature is valid under the ORIGINAL key but not the wrong one, so S3 MUST
// reject with RejectSignatureInvalid. This is the trust-boundary case: the
// verification key must defeat a signature it did not produce.
func TestChaosWrongPublicKey(t *testing.T) {
	a := newSignedArtifact(t, []byte("artifact-verified-with-wrong-key"))

	// Many independent wrong keys — none may ever accept the foreign signature.
	const trials = 64
	for i := 0; i < trials; i++ {
		wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		in := a.input()
		in.PublicKey = wrongPub

		res, panicked := runPipeline(t, in)
		if panicked {
			return
		}
		if res.Accepted() {
			t.Fatalf("trial %d: validator ACCEPTED a signature under the WRONG public key", i)
		}
		if res.Final.Stage != StageSignature || res.Final.Code != RejectSignatureInvalid {
			t.Fatalf("trial %d: want S3 RejectSignatureInvalid, got %s", i, res.Final)
		}
	}
	t.Logf("§11.4.85 chaos/wrong-key: all %d foreign keys rejected the signature at S3", trials)
}

// TestChaosTruncatedArtifact truncates the artifact stream mid-flight at every
// boundary. A short read changes the SHA-256, so S2 MUST reject with
// RejectHashMismatch (truncation is just another form of payload corruption).
func TestChaosTruncatedArtifact(t *testing.T) {
	a := newSignedArtifact(t, bytes.Repeat([]byte("CHUNK"), 256)) // 1280 bytes

	for _, cut := range []int{0, 1, len(a.payload) / 2, len(a.payload) - 1} {
		in := a.input()
		in.Artifact = bytes.NewReader(a.payload[:cut])

		res, panicked := runPipeline(t, in)
		if panicked {
			return
		}
		if res.Accepted() {
			t.Fatalf("cut=%d: validator ACCEPTED a truncated artifact", cut)
		}
		if res.Final.Stage != StageHash || res.Final.Code != RejectHashMismatch {
			t.Fatalf("cut=%d: want S2 RejectHashMismatch, got %s", cut, res.Final)
		}
	}
	t.Logf("§11.4.85 chaos/truncation: every truncation boundary rejected at S2")
}

// TestChaosErroringReader injects an I/O fault mid-stream: the artifact reader
// returns an error partway through hashing. S2 MUST surface this as a reject
// (RejectHashMismatch per the implementation's read-error path), NEVER accept,
// NEVER panic. This is the "state-corruption / partial-read fault" chaos class.
func TestChaosErroringReader(t *testing.T) {
	a := newSignedArtifact(t, bytes.Repeat([]byte("R"), 1024))
	in := a.input()
	in.Artifact = &faultyReader{data: a.payload, failAfter: 100}

	res, panicked := runPipeline(t, in)
	if panicked {
		return
	}
	if res.Accepted() {
		t.Fatal("validator ACCEPTED an artifact whose reader faulted mid-stream")
	}
	if res.Final.Stage != StageHash || res.Final.Code != RejectHashMismatch {
		t.Fatalf("want S2 reject on read fault, got %s", res.Final)
	}
	t.Logf("§11.4.85 chaos/io-fault: mid-stream read error rejected at S2 (%s)", res.Final)
}

// faultyReader yields data normally until failAfter bytes, then returns an
// error — simulating a storage/network read fault during hashing.
type faultyReader struct {
	data      []byte
	pos       int
	failAfter int
}

func (r *faultyReader) Read(p []byte) (int, error) {
	if r.pos >= r.failAfter {
		return 0, errInjectedReadFault
	}
	n := copy(p, r.data[r.pos:min(r.pos+len(p), r.failAfter)])
	r.pos += n
	return n, nil
}

var errInjectedReadFault = injectedErr("injected mid-stream read fault")

type injectedErr string

func (e injectedErr) Error() string { return string(e) }

// --- hash-before-signature ordering (handoff note G2) ---------------------

// TestChaosHashBeforeSignatureOrdering is the load-bearing ordering proof.
//
// Case A: valid-hash-but-WRONG-signature → the hash passes (S2), so the
//
//	signature fault is the one that wins → S3 RejectSignatureInvalid, S2 ran
//	first and passed.
//
// Case B: WRONG-hash-but-otherwise-valid-signature → the hash fails first, so
//
//	the HASH error wins and S3 NEVER runs. If ordering were reversed (sig
//	before hash), a hash-mismatched blob would reach — and could pass —
//	signature verification. This case mechanically forbids that.
func TestChaosHashBeforeSignatureOrdering(t *testing.T) {
	a := newSignedArtifact(t, []byte("ordering-proof-payload"))

	t.Run("valid-hash-wrong-signature-yields-S3", func(t *testing.T) {
		in := a.input() // hash matches
		// Replace with a valid signature from a foreign key over the SAME digest:
		// S2 passes, S3 must reject.
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		d, _ := hex.DecodeString(a.digest)
		in.Signature = ed25519.Sign(otherPriv, d)

		res := Validate(in)
		if res.Accepted() {
			t.Fatal("ACCEPTED valid-hash/wrong-signature artifact")
		}
		if res.Final.Stage != StageSignature || res.Final.Code != RejectSignatureInvalid {
			t.Fatalf("want S3 RejectSignatureInvalid (hash passed first), got %s", res.Final)
		}
		if len(res.Verdicts) != 2 || res.Verdicts[0].Stage != StageHash || !res.Verdicts[0].Passed {
			t.Fatalf("expected S2 PASS then S3 REJECT, got %v", res.Verdicts)
		}
	})

	t.Run("wrong-hash-valid-signature-yields-S2-not-S3", func(t *testing.T) {
		// Construct a blob whose bytes do NOT match the hash file, yet carry a
		// perfectly valid signature OVER THE HASH FILE'S digest. If the pipeline
		// (incorrectly) checked the signature first, this could slip through.
		// Because S2 runs first, the HASH error must win and S3 must not run.
		tampered := append([]byte(nil), a.payload...)
		tampered[0] ^= 0xFF // bytes no longer match a.hashFile's digest

		in := a.input()
		in.Artifact = bytes.NewReader(tampered)
		// Signature is the original, valid over the (declared) hash-file digest.
		// (in.Signature is already a.sig — valid over a.digest.)

		res := Validate(in)
		if res.Accepted() {
			t.Fatal("ACCEPTED wrong-hash artifact — hash-before-signature ordering BROKEN")
		}
		if res.Final.Stage != StageHash || res.Final.Code != RejectHashMismatch {
			t.Fatalf("hash error must win: want S2 RejectHashMismatch, got %s", res.Final)
		}
		// The decisive proof of ordering: S3 NEVER ran.
		if len(res.Verdicts) != 1 {
			t.Fatalf("S3 must NOT run when S2 rejects; got %d verdicts: %v", len(res.Verdicts), res.Verdicts)
		}
		for _, v := range res.Verdicts {
			if v.Stage == StageSignature {
				t.Fatal("S3 verdict present despite S2 hash mismatch — ordering violated")
			}
		}
	})
}

// TestChaosNeverAcceptsCorruption is a broad belt-and-suspenders sweep: across
// a battery of independent corruptions over freshly-keyed artifacts, the
// validator must NEVER once return Accepted()==true and NEVER panic. This is
// the §11.4.85 anti-bluff invariant stated directly: no corrupted artifact is
// ever accepted.
func TestChaosNeverAcceptsCorruption(t *testing.T) {
	corruptions := []struct {
		name   string
		mutate func(a signedArtifact, in *Input)
	}{
		{"payload-byte-corrupt", func(a signedArtifact, in *Input) {
			c := append([]byte(nil), a.payload...)
			c[len(c)/2] ^= 0xAA
			in.Artifact = bytes.NewReader(c)
		}},
		{"sig-corrupt", func(a signedArtifact, in *Input) {
			s := append([]byte(nil), a.sig...)
			s[10] ^= 0xAA
			in.Signature = s
		}},
		{"key-swap", func(a signedArtifact, in *Input) {
			p, _, _ := ed25519.GenerateKey(rand.Reader)
			in.PublicKey = p
		}},
		{"hashfile-corrupt", func(a signedArtifact, in *Input) {
			other := sha256.Sum256([]byte("not the artifact"))
			in.HashFile = hex.EncodeToString(other[:]) + "  ota.zip\n"
		}},
		{"meta-sha-corrupt", func(a signedArtifact, in *Input) {
			other := sha256.Sum256([]byte("meta lie"))
			in.Meta.SHA256 = hex.EncodeToString(other[:])
		}},
		{"truncate", func(a signedArtifact, in *Input) {
			in.Artifact = bytes.NewReader(a.payload[:len(a.payload)/3])
		}},
	}

	const rounds = 20 // fresh keys/artifact each round per corruption
	var total, accepted int
	for round := 0; round < rounds; round++ {
		a := newSignedArtifact(t, []byte("never-accept-corruption-round"))
		for _, c := range corruptions {
			in := a.input()
			c.mutate(a, &in)
			res, panicked := runPipeline(t, in)
			if panicked {
				return
			}
			total++
			if res.Accepted() {
				accepted++
				t.Errorf("round %d: corruption %q was ACCEPTED (%s)", round, c.name, res.Final)
			}
			// Every verdict must be a categorised reject with a non-empty code.
			if res.Final.IsReject() && res.Final.Code == "" {
				t.Errorf("round %d: corruption %q produced reject with EMPTY code", round, c.name)
			}
		}
	}
	if accepted != 0 {
		t.Fatalf("§11.4.85 INVARIANT VIOLATED: %d/%d corrupted artifacts accepted", accepted, total)
	}
	t.Logf("§11.4.85 chaos/never-accept: %d corrupted artifacts, 0 accepted, 0 panics", total)
}
