// Package otavalidator_chaos_test -- chaos tests for ota-artifact-validator
// (§11.4.85).
//
// Fault-injection and input-corruption tests: every dimension of a known-good
// signed artifact is corrupted one-at-a-time and the validator must NEVER
// accept a corrupted artifact and NEVER panic.
package otavalidator_chaos_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	otavalidator "github.com/HelixDevelopment/ota-artifact-validator"
	otaprotocol "github.com/HelixDevelopment/ota-protocol"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func chaosEvidenceDir() string {
	if d := os.Getenv("HELIX_STRESS_EVIDENCE_DIR"); d != "" {
		return d
	}
	return "qa-results/stress_chaos"
}

func writeChaosEvidence(t *testing.T, name string, data []byte) {
	t.Helper()
	dir := chaosEvidenceDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Logf("WARNING: mkdir %s: %v", dir, err)
		return
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	p := filepath.Join(dir, fmt.Sprintf("%s-%s.json", name, ts))
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Logf("WARNING: write evidence %s: %v", p, err)
	}
}

// makeFixture returns a fresh, fully valid signed artifact fixture.
func makeFixture(t testing.TB, payload []byte) (otavalidator.Input, otavalidator.TargetPolicy) {
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
		Size:      int64(len(payload)),
		OSType:    otaprotocol.OSAndroid,
		Board:     "rk3588",
		Version:   "2.0.0",
		Signature: hex.EncodeToString(sig),
	}
	policy := otavalidator.NewStaticTargetPolicy(
		nil,
		[]otavalidator.TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}},
	)
	in := otavalidator.Input{
		Artifact:       bytes.NewReader(payload),
		HashFile:       digest + "  ota.zip\n",
		PublicKey:      pub,
		Signature:      sig,
		CurrentVersion: "1.0.0",
		Meta:           meta,
		TargetPolicy:   policy,
	}
	return in, policy
}

// runGuarded runs Validate with panic recovery.
func runGuarded(in otavalidator.Input) (res otavalidator.Result, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	res = otavalidator.Validate(in)
	return
}

// ---------------------------------------------------------------------------
// TestChaosBitFlipPayload
//
// Flip every bit in the payload. S2 must catch the hash mismatch.
// ---------------------------------------------------------------------------

func TestChaosBitFlipPayload(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	payload := []byte("payload-for-chaos-bit-flip")
	in, _ := makeFixture(t, payload)

	for pos := 0; pos < len(payload); pos++ {
		corrupt := append([]byte(nil), payload...)
		for bit := uint(0); bit < 8; bit++ {
			mask := byte(1 << bit)
			corrupt[pos] = payload[pos] ^ mask

			ci := in
			ci.Artifact = bytes.NewReader(corrupt)
			res, panicked := runGuarded(ci)
			if panicked {
				t.Fatalf("panicked at pos=%d bit=%d", pos, bit)
			}
			if res.Accepted() {
				t.Fatalf("ACCEPTED bit-flipped artifact at pos=%d bit=%d", pos, bit)
			}
			if res.Final.Stage != otavalidator.StageHash || res.Final.Code != otavalidator.RejectHashMismatch {
				t.Fatalf("pos=%d bit=%d: want S2 RejectHashMismatch, got %s", pos, bit, res.Final)
			}
		}
	}
	t.Logf("Bit-flip chaos: all %d bytes x 8 bits rejected at S2", len(payload))
}

// ---------------------------------------------------------------------------
// TestChaosCorruptSignature
//
// Corrupt the signature in every dimension: bit-flip, truncate, oversize,
// random, foreign-valid. Must reject at S3, never panic.
// ---------------------------------------------------------------------------

func TestChaosCorruptSignature(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	payload := []byte("signature-chaos-payload")
	in, _ := makeFixture(t, payload)

	mutations := []struct {
		name string
		sig  func() []byte
	}{
		{"flip-first-byte", func() []byte {
			s := append([]byte(nil), in.Signature...)
			s[0] ^= 0xFF
			return s
		}},
		{"flip-last-byte", func() []byte {
			s := append([]byte(nil), in.Signature...)
			s[len(s)-1] ^= 0xFF
			return s
		}},
		{"all-zero", func() []byte { return bytes.Repeat([]byte{0x00}, ed25519.SignatureSize) }},
		{"random", func() []byte {
			r := make([]byte, ed25519.SignatureSize)
			_, _ = rand.Read(r)
			return r
		}},
		{"truncated", func() []byte { return in.Signature[:ed25519.SignatureSize-1] }},
		{"oversized", func() []byte { return append(append([]byte(nil), in.Signature...), 0x00) }},
		{"foreign-sig-over-same-digest", func() []byte {
			d, _ := hex.DecodeString(getDigest(in))
			_, p, _ := ed25519.GenerateKey(rand.Reader)
			return ed25519.Sign(p, d)
		}},
	}

	for _, m := range mutations {
		m := m
		t.Run(m.name, func(t *testing.T) {
			ci := in
			ci.Signature = m.sig()
			res, panicked := runGuarded(ci)
			if panicked {
				t.Fatalf("%s: panicked", m.name)
			}
			if res.Accepted() {
				t.Fatalf("%s: ACCEPTED corrupt signature", m.name)
			}
			if res.Final.Stage != otavalidator.StageSignature {
				t.Fatalf("%s: want S3 reject, got %s", m.name, res.Final)
			}
		})
	}
}

func getDigest(in otavalidator.Input) string {
	// Extract the digest from the hash file.
	return strings.Fields(in.HashFile)[0]
}

// ---------------------------------------------------------------------------
// TestChaosWrongPublicKey
//
// Verify a valid signature under a wrong public key -> S3 rejection.
// ---------------------------------------------------------------------------

func TestChaosWrongPublicKey(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	payload := []byte("wrong-key-chaos")
	in, _ := makeFixture(t, payload)

	for i := 0; i < 10; i++ {
		wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
		ci := in
		ci.PublicKey = wrongPub

		res, panicked := runGuarded(ci)
		if panicked {
			t.Fatalf("trial %d: panicked", i)
		}
		if res.Accepted() {
			t.Fatalf("trial %d: ACCEPTED under wrong public key", i)
		}
		if res.Final.Stage != otavalidator.StageSignature || res.Final.Code != otavalidator.RejectSignatureInvalid {
			t.Fatalf("trial %d: want S3 RejectSignatureInvalid, got %s", i, res.Final)
		}
	}
}

// ---------------------------------------------------------------------------
// TestChaosTruncatedArtifact
//
// Truncating the artifact at multiple boundary sizes -> S2 must reject.
// ---------------------------------------------------------------------------

func TestChaosTruncatedArtifact(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	payload := bytes.Repeat([]byte("A"), 1024)
	in, _ := makeFixture(t, payload)

	for _, cut := range []int{0, 1, 512, 1023} {
		ci := in
		ci.Artifact = bytes.NewReader(payload[:cut])

		res, panicked := runGuarded(ci)
		if panicked {
			t.Fatalf("cut=%d: panicked", cut)
		}
		if res.Accepted() {
			t.Fatalf("cut=%d: ACCEPTED truncated artifact", cut)
		}
		if res.Final.Stage != otavalidator.StageHash || res.Final.Code != otavalidator.RejectHashMismatch {
			t.Fatalf("cut=%d: want S2 RejectHashMismatch, got %s", cut, res.Final)
		}
	}
}

// ---------------------------------------------------------------------------
// TestChaosMetadataCorruption
//
// Corrupt each field of ArtifactMeta: empty SHA256, empty OS, negative size,
// oversized version, missing signature.
// ---------------------------------------------------------------------------

func TestChaosMetadataCorruption(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	payload := []byte("meta-chaos-payload")
	in, _ := makeFixture(t, payload)

	type metaCase struct {
		name   string
		corrupt func(m *otaprotocol.ArtifactMeta)
	}

	cases := []metaCase{
		{"empty-sha256", func(m *otaprotocol.ArtifactMeta) { m.SHA256 = "" }},
		{"empty-ostype", func(m *otaprotocol.ArtifactMeta) { m.OSType = "" }},
		{"empty-board", func(m *otaprotocol.ArtifactMeta) { m.Board = "" }},
		{"empty-version", func(m *otaprotocol.ArtifactMeta) { m.Version = "" }},
		{"empty-signature", func(m *otaprotocol.ArtifactMeta) { m.Signature = "" }},
		{"zero-size", func(m *otaprotocol.ArtifactMeta) { m.Size = 0 }},
		{"negative-size", func(m *otaprotocol.ArtifactMeta) { m.Size = -1 }},
		{"oversize-version-1000", func(m *otaprotocol.ArtifactMeta) { m.Version = strings.Repeat("v", 1000) }},
		{"invalid-ostype", func(m *otaprotocol.ArtifactMeta) { m.OSType = "nope" }},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			ci := in
			c.corrupt(&ci.Meta)
			res, panicked := runGuarded(ci)
			if panicked {
				t.Fatalf("%s: panicked", c.name)
			}
			if res.Accepted() {
				t.Fatalf("%s: ACCEPTED corrupted metadata", c.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestChaosNeverAcceptsCorruption
//
// Broad sweep: across independent corruptions on fresh artifacts, the
// validator must NEVER return Accepted()==true and NEVER panic.
// ---------------------------------------------------------------------------

func TestChaosNeverAcceptsCorruption(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	corruptions := []struct {
		name   string
		corrupt func(ci *otavalidator.Input, payload []byte)
	}{
		{"hash-mismatch", func(ci *otavalidator.Input, payload []byte) {
			ci.Artifact = bytes.NewReader(append(payload, 0x00))
		}},
		{"hashfile-empty", func(ci *otavalidator.Input, _ []byte) {
			ci.HashFile = ""
		}},
		{"hashfile-truncated", func(ci *otavalidator.Input, _ []byte) {
			ci.HashFile = "abc"
		}},
		{"version-downgrade", func(ci *otavalidator.Input, _ []byte) {
			ci.Meta.Version = "0.0.1"
		}},
		{"unknown-board", func(ci *otavalidator.Input, _ []byte) {
			ci.Meta.Board = "nonexistent"
		}},
		{"nil-public-key", func(ci *otavalidator.Input, _ []byte) {
			ci.PublicKey = nil
		}},
	}

	const rounds = 10
	var total, accepted int
	for round := 0; round < rounds; round++ {
		payload := []byte(fmt.Sprintf("never-accept-chaos-round-%d", round))
		in, _ := makeFixture(t, payload)
		for _, c := range corruptions {
			ci := in
			ci.Artifact = bytes.NewReader(payload)
			c.corrupt(&ci, payload)

			res, panicked := runGuarded(ci)
			if panicked {
				t.Fatalf("round %d/%s: panicked", round, c.name)
			}
			total++
			if res.Accepted() {
				accepted++
				t.Errorf("round %d/%s: ACCEPTED corrupted artifact", round, c.name)
			}
		}
	}

	if accepted != 0 {
		t.Fatalf("INVARIANT VIOLATED: %d/%d corrupted artifacts accepted", accepted, total)
	}
	record := map[string]interface{}{
		"test":      "TestChaosNeverAcceptsCorruption",
		"total":     total,
		"accepted":  accepted,
		"panics":    0,
		"evidence":  "all rejected, no panics",
	}
	ev, _ := json.MarshalIndent(record, "", "  ")
	writeChaosEvidence(t, "chaos_never_accepts_corruption", ev)
	t.Logf("Chaos never-accepts: %d corrupted artifacts, 0 accepted, 0 panics", total)
}

// ---------------------------------------------------------------------------
// TestChaosConcurrentCorruptedArtifacts
//
// 50 goroutines each feed corrupted inputs concurrently.
// ---------------------------------------------------------------------------

func TestChaosConcurrentCorruptedArtifacts(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("chaos test skipped in short mode")
	}

	const goroutines = 50
	var panics, accepted int64

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("cc-payload-%d", seed))
			in, _ := makeFixture(t, payload)

			// Alternate corruption type per goroutine.
			if seed%3 == 0 {
				in.Artifact = bytes.NewReader(append(payload, 0xFF))
			} else if seed%3 == 1 {
				in.HashFile = "deadbeef"
			} else {
				in.Meta.Version = "0.0.0"
			}

			res, p := runGuarded(in)
			if p {
				atomic.AddInt64(&panics, 1)
			}
			if res.Accepted() {
				atomic.AddInt64(&accepted, 1)
			}
		}(g)
	}
	wg.Wait()

	if panics != 0 {
		t.Fatalf("%d goroutines panicked", panics)
	}
	if accepted != 0 {
		t.Fatalf("%d corruptions were accepted", accepted)
	}

	record := map[string]interface{}{
		"test":       "TestChaosConcurrentCorruptedArtifacts",
		"goroutines": goroutines,
		"panics":     panics,
		"accepted":   accepted,
	}
	ev, _ := json.MarshalIndent(record, "", "  ")
	writeChaosEvidence(t, "chaos_concurrent_corrupted", ev)
	t.Logf("Concurrent chaos: %d goroutines, 0 panics, 0 accepted", goroutines)
}
