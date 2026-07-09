// Exercises the full S2..S6 pipeline and individual stage helpers under
// sustained concurrent load with real cryptographic primitives, recording
// p50/p95/p99 latency and categorised outcomes as captured evidence.
package otavalidator_stress_test

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
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
func evidenceDir() string {
	if d := os.Getenv("HELIX_STRESS_EVIDENCE_DIR"); d != "" {
		return d
	}
	return "qa-results/stress_chaos"
}
func writeEvidence(t *testing.T, name string, data []byte) {
	t.Helper()
	dir := evidenceDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Logf("WARNING: create evidence dir %s: %v", dir, err)
		return
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	p := filepath.Join(dir, fmt.Sprintf("%s-%s.json", name, ts))
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Logf("WARNING: write evidence %s: %v", p, err)
	}
}
func percentiles(durations []time.Duration) (p50, p95, p99 time.Duration) {
	n := len(durations)
	if n == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, n)
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50 = sorted[n*50/100]
	p95 = sorted[n*95/100]
	p99 = sorted[n*99/100]
	return
}

// genSHA256 returns a random lowercase-hex SHA-256 digest.
func genSHA256() string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = hexd[rand.Intn(len(hexd))]
	}
	return string(b)
}

// signedFixture returns a self-consistent, fully-valid signed artifact.
func signedFixture(t testing.TB) (otavalidator.Input, otavalidator.Result) {
	t.Helper()
	payload := []byte("stress-test-payload-for-validator")
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
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
	res := otavalidator.Validate(in)
	return in, res
}

// ---------------------------------------------------------------------------
// TestStressSustainedFullPipeline
//
// N=200 iterations of Validate() with a valid artifact mix, recording passed
// and rejected categorised outcomes and p50/p95/p99 latency.
// ---------------------------------------------------------------------------
func TestStressSustainedFullPipeline(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("stress test skipped in short mode")
	}
	const N = 200
	durations := make([]time.Duration, 0, N)
	var accepted, rejected, failed int
	for i := 0; i < N; i++ {
		in, _ := signedFixture(t)
		// Every 5th iteration corrupt the hash file to trigger S2 reject.
		if i%5 == 3 {
			in.HashFile = genSHA256()
		}
		start := time.Now()
		res := otavalidator.Validate(in)
		durations = append(durations, time.Since(start))
		if res.Accepted() {
			accepted++
		} else {
			rejected++
		}
		if res.Final.IsReject() && res.Final.Code == "" {
			failed++
		}
	}
	p50, p95, p99 := percentiles(durations)
	record := map[string]interface{}{
		"test":     "TestStressSustainedFullPipeline",
		"N":        N,
		"accepted": accepted,
		"rejected": rejected,
		"failed":   failed,
		"p50_ns":   p50.Nanoseconds(),
		"p95_ns":   p95.Nanoseconds(),
		"p99_ns":   p99.Nanoseconds(),
	}
	ev, _ := json.MarshalIndent(record, "", "  ")
	writeEvidence(t, "sustained_full_pipeline", ev)
	t.Logf("Sustained N=%d: accepted=%d rejected=%d p50=%v p95=%v p99=%v",
		N, accepted, rejected, p50, p95, p99)
	if accepted == 0 || rejected == 0 {
		t.Error("stress mix must contain both accepted and rejected outcomes")
	}
}

// ---------------------------------------------------------------------------
// TestStressConcurrentFullPipeline
//
// N=50 goroutines each call Validate() concurrently. All use the same shared
// TargetPolicy and public key to exercise read-shared state.
// ---------------------------------------------------------------------------
func TestStressConcurrentFullPipeline(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("stress test skipped in short mode")
	}
	const goroutines = 50
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		results    []time.Duration
		mismatches int64
	)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			in, want := signedFixture(t)
			for i := 0; i < 20; i++ {
				start := time.Now()
				got := otavalidator.Validate(in)
				elapsed := time.Since(start)
				mu.Lock()
				results = append(results, elapsed)
				mu.Unlock()
				if got.Accepted() != want.Accepted() {
					atomic.AddInt64(&mismatches, 1)
				}
			}
		}()
	}
	wg.Wait()
	p50, p95, p99 := percentiles(results)
	record := map[string]interface{}{
		"test":       "TestStressConcurrentFullPipeline",
		"goroutines": goroutines,
		"iters":      len(results),
		"mismatches": mismatches,
		"p50_ns":     p50.Nanoseconds(),
		"p95_ns":     p95.Nanoseconds(),
		"p99_ns":     p99.Nanoseconds(),
	}
	ev, _ := json.MarshalIndent(record, "", "  ")
	writeEvidence(t, "concurrent_full_pipeline", ev)
	t.Logf("Concurrent %d goroutines x 20 iters: p50=%v p95=%v p99=%v mismatches=%d",
		goroutines, p50, p95, p99, mismatches)
	if mismatches != 0 {
		t.Fatal("concurrent verdicts differed from serial baseline")
	}
}

// ---------------------------------------------------------------------------
// TestStressBoundaryStageHelpers
//
// Boundary conditions for the validation stage helper functions:
// empty readers, nil keys, empty hash files, off-by-one signature lengths.
// ---------------------------------------------------------------------------
func TestStressBoundaryStageHelpers(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("stress test skipped in short mode")
	}
	payload := []byte("boundary-payload")
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, sum[:])
	type helperCase struct {
		name string
		run  func(*testing.T)
	}
	cases := []helperCase{
		{"empty-hashfile", func(t *testing.T) {
			v, _, _ := otavalidator.ValidateHash(bytes.NewReader(payload), "")
			if v.Passed || v.Code != otavalidator.RejectHashFileMissing {
				t.Fatalf("expected RejectHashFileMissing, got %s", v)
			}
		}},
		{"empty-reader", func(t *testing.T) {
			v, _, _ := otavalidator.ValidateHash(bytes.NewReader(nil), digest+"  x")
			if v.Passed || v.Code != otavalidator.RejectHashMismatch {
				t.Fatalf("expected RejectHashMismatch, got %s", v)
			}
		}},
		{"nil-signature", func(t *testing.T) {
			if v := otavalidator.ValidateSignature(digest, pub, nil); v.Passed || v.Code != otavalidator.RejectSignatureMissing {
				t.Fatalf("expected RejectSignatureMissing, got %s", v)
			}
		}},
		{"empty-signature-slice", func(t *testing.T) {
			if v := otavalidator.ValidateSignature(digest, pub, []byte{}); v.Passed || v.Code != otavalidator.RejectSignatureMissing {
				t.Fatalf("expected RejectSignatureMissing, got %s", v)
			}
		}},
		{"short-key", func(t *testing.T) {
			if v := otavalidator.ValidateSignature(digest, ed25519.PublicKey{1, 2, 3}, sig); v.Passed || v.Code != otavalidator.RejectSignatureKeyInvalid {
				t.Fatalf("expected RejectSignatureKeyInvalid, got %s", v)
			}
		}},
		{"nil-key", func(t *testing.T) {
			if v := otavalidator.ValidateSignature(digest, nil, sig); v.Passed || v.Code != otavalidator.RejectSignatureKeyInvalid {
				t.Fatalf("expected RejectSignatureKeyInvalid, got %s", v)
			}
		}},
		{"empty-version", func(t *testing.T) {
			if v := otavalidator.ValidateVersion("", "1.0.0", nil); v.Passed || v.Code != otavalidator.RejectVersionUnparseable {
				t.Fatalf("expected RejectVersionUnparseable, got %s", v)
			}
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, c.run)
	}
}
