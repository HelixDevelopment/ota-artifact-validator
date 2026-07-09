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

// --- test fixtures --------------------------------------------------------

// fixture bundles a self-consistent valid artifact and the keys to sign it.
type fixture struct {
	artifact []byte
	digest   string // lowercase hex SHA-256 of artifact
	hashFile string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	sig      []byte
	meta     otaprotocol.ArtifactMeta
	policy   TargetPolicy
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	artifact := []byte("helix-ota-payload.bin ZIP_STORED byte-identical contents")
	sum := sha256.Sum256(artifact)
	digest := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, sum[:])

	meta := otaprotocol.ArtifactMeta{
		SHA256:    digest,
		Size:      int64(len(artifact)),
		OSType:    otaprotocol.OSAndroid,
		Board:     "rk3588",
		Version:   "1.4.0",
		Signature: hex.EncodeToString(sig),
	}
	policy := NewStaticTargetPolicy(
		nil,
		[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}},
	)
	return fixture{
		artifact: artifact,
		digest:   digest,
		hashFile: digest + "  ota.zip\n",
		pub:      pub,
		priv:     priv,
		sig:      sig,
		meta:     meta,
		policy:   policy,
	}
}

// input builds a pipeline Input from the fixture (with a fresh reader).
func (f fixture) input() Input {
	return Input{
		Artifact:       bytes.NewReader(f.artifact),
		HashFile:       f.hashFile,
		PublicKey:      f.pub,
		Signature:      f.sig,
		CurrentVersion: "1.3.0",
		Meta:           f.meta,
		TargetPolicy:   f.policy,
	}
}

// --- top-level pipeline (valid + every failure mode) ----------------------

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*fixture, *Input)
		wantPass  bool
		wantStage Stage
		wantCode  RejectCode
		wantRan   int // number of stage verdicts recorded
	}{
		{
			name:     "valid artifact accepted",
			mutate:   func(_ *fixture, _ *Input) {},
			wantPass: true,
			wantRan:  5,
		},
		{
			name: "S2 hash file missing",
			mutate: func(_ *fixture, in *Input) {
				in.HashFile = "   "
			},
			wantStage: StageHash,
			wantCode:  RejectHashFileMissing,
			wantRan:   1,
		},
		{
			name: "S2 hash file malformed",
			mutate: func(_ *fixture, in *Input) {
				in.HashFile = "not-a-real-digest"
			},
			wantStage: StageHash,
			wantCode:  RejectHashFileMalformed,
			wantRan:   1,
		},
		{
			name: "S2 hash mismatch (tampered bytes)",
			mutate: func(f *fixture, in *Input) {
				in.Artifact = bytes.NewReader([]byte("tampered payload"))
			},
			wantStage: StageHash,
			wantCode:  RejectHashMismatch,
			wantRan:   1,
		},
		{
			name: "S3 signature missing",
			mutate: func(_ *fixture, in *Input) {
				in.Signature = nil
			},
			wantStage: StageSignature,
			wantCode:  RejectSignatureMissing,
			wantRan:   2,
		},
		{
			name: "S3 public key invalid",
			mutate: func(_ *fixture, in *Input) {
				in.PublicKey = []byte{0x01, 0x02}
			},
			wantStage: StageSignature,
			wantCode:  RejectSignatureKeyInvalid,
			wantRan:   2,
		},
		{
			name: "S3 signature invalid (wrong key)",
			mutate: func(_ *fixture, in *Input) {
				otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
				in.PublicKey = otherPub
			},
			wantStage: StageSignature,
			wantCode:  RejectSignatureInvalid,
			wantRan:   2,
		},
		{
			name: "S4 downgrade rejected",
			mutate: func(f *fixture, in *Input) {
				in.Meta.Version = "1.2.0" // re-sign not needed; digest unchanged
				in.CurrentVersion = "1.3.0"
			},
			wantStage: StageVersion,
			wantCode:  RejectNotMonotonic,
			wantRan:   3,
		},
		{
			name: "S4 duplicate version rejected",
			mutate: func(f *fixture, in *Input) {
				in.Meta.Version = "1.3.0"
				in.CurrentVersion = "1.3.0"
			},
			wantStage: StageVersion,
			wantCode:  RejectDuplicateVersion,
			wantRan:   3,
		},
		{
			name: "S4 unparseable version rejected",
			mutate: func(f *fixture, in *Input) {
				in.Meta.Version = "not.a.version"
			},
			wantStage: StageVersion,
			wantCode:  RejectVersionUnparseable,
			wantRan:   3,
		},
		{
			name: "S4 no prior release accepts new version",
			mutate: func(f *fixture, in *Input) {
				in.CurrentVersion = ""
			},
			wantPass: true,
			wantRan:  5,
		},
		{
			name: "S5 wrong target (unknown board)",
			mutate: func(f *fixture, in *Input) {
				in.Meta.Board = "unknown-board"
			},
			wantStage: StageTarget,
			wantCode:  RejectTargetUnknown,
			wantRan:   4,
		},
		{
			name: "S5 target undeclared",
			mutate: func(f *fixture, in *Input) {
				in.Meta.Board = ""
			},
			wantStage: StageTarget,
			wantCode:  RejectTargetUndeclared,
			wantRan:   4,
		},
		{
			name: "S5 target known but unsupported",
			mutate: func(f *fixture, in *Input) {
				in.Meta.OSType = otaprotocol.OSLinux
				in.Meta.Board = "generic"
				in.TargetPolicy = NewStaticTargetPolicy(
					[]TargetKey{{OSType: otaprotocol.OSLinux, Board: "generic"}},
					nil,
				)
			},
			wantStage: StageTarget,
			wantCode:  RejectTargetUnsupported,
			wantRan:   4,
		},
		{
			name: "S6 malformed meta (bad sha256 field)",
			mutate: func(f *fixture, in *Input) {
				in.Meta.SHA256 = "tooshort"
			},
			wantStage: StageMetadata,
			wantCode:  RejectMetadataIncomplete,
			wantRan:   5,
		},
		{
			name: "S6 metadata inconsistent with computed digest",
			mutate: func(f *fixture, in *Input) {
				// A well-formed but different digest: flip the meta SHA256 to
				// another valid 64-hex value that is not the computed one.
				other := sha256.Sum256([]byte("different artifact"))
				in.Meta.SHA256 = hex.EncodeToString(other[:])
			},
			wantStage: StageMetadata,
			wantCode:  RejectMetadataInconsistent,
			wantRan:   5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			in := f.input()
			tc.mutate(&f, &in)

			res := Validate(in)

			if res.Accepted() != tc.wantPass {
				t.Fatalf("Accepted()=%v want %v (final=%s)", res.Accepted(), tc.wantPass, res.Final)
			}
			if len(res.Verdicts) != tc.wantRan {
				t.Fatalf("ran %d stages want %d (verdicts=%v)", len(res.Verdicts), tc.wantRan, res.Verdicts)
			}
			if tc.wantPass {
				if res.ComputedSHA256 != f.digest {
					t.Fatalf("ComputedSHA256=%q want %q", res.ComputedSHA256, f.digest)
				}
				return
			}
			if res.Final.Stage != tc.wantStage {
				t.Fatalf("final stage=%q want %q", res.Final.Stage, tc.wantStage)
			}
			if res.Final.Code != tc.wantCode {
				t.Fatalf("final code=%q want %q", res.Final.Code, tc.wantCode)
			}
			if !res.Final.IsReject() {
				t.Fatalf("expected reject verdict, got %s", res.Final)
			}
			// Fail-fast: the failing stage is always the last recorded verdict.
			last := res.Verdicts[len(res.Verdicts)-1]
			if last.Code != tc.wantCode {
				t.Fatalf("last recorded verdict code=%q want %q", last.Code, tc.wantCode)
			}
		})
	}
}

// --- per-stage unit tests -------------------------------------------------

func TestValidateHash(t *testing.T) {
	data := []byte("abc")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	tests := []struct {
		name     string
		body     []byte
		hashFile string
		wantPass bool
		wantCode RejectCode
	}{
		{"bare digest", data, digest, true, ""},
		{"coreutils format", data, digest + "  file.zip", true, ""},
		{"empty hash file", data, "", false, RejectHashFileMissing},
		{"malformed hash file", data, "zzzz", false, RejectHashFileMalformed},
		{"uppercase hex rejected as malformed", data, strings.ToUpper(digest), false, RejectHashFileMalformed},
		{"mismatch", []byte("xyz"), digest, false, RejectHashMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, got, n := ValidateHash(bytes.NewReader(tc.body), tc.hashFile)
			if v.Passed != tc.wantPass {
				t.Fatalf("Passed=%v want %v (%s)", v.Passed, tc.wantPass, v)
			}
			if tc.wantPass && got != digest {
				t.Fatalf("digest=%q want %q", got, digest)
			}
			if tc.wantPass && n != int64(len(tc.body)) {
				t.Fatalf("byte count=%d want %d", n, len(tc.body))
			}
			if !tc.wantPass && v.Code != tc.wantCode {
				t.Fatalf("code=%q want %q", v.Code, tc.wantCode)
			}
		})
	}
}

func TestValidateSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sum := sha256.Sum256([]byte("payload"))
	digest := hex.EncodeToString(sum[:])
	goodSig := ed25519.Sign(priv, sum[:])

	tests := []struct {
		name     string
		digest   string
		pub      ed25519.PublicKey
		sig      []byte
		wantPass bool
		wantCode RejectCode
	}{
		{"valid", digest, pub, goodSig, true, ""},
		{"missing sig", digest, pub, nil, false, RejectSignatureMissing},
		{"bad key size", digest, []byte{1, 2, 3}, goodSig, false, RejectSignatureKeyInvalid},
		{"non-hex digest", "zz", pub, goodSig, false, RejectSignatureScopeMismatch},
		{"short digest", "abcd", pub, goodSig, false, RejectSignatureScopeMismatch},
		{"forged sig", digest, pub, bytes.Repeat([]byte{0}, ed25519.SignatureSize), false, RejectSignatureInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidateSignature(tc.digest, tc.pub, tc.sig)
			if v.Passed != tc.wantPass {
				t.Fatalf("Passed=%v want %v (%s)", v.Passed, tc.wantPass, v)
			}
			if !tc.wantPass && v.Code != tc.wantCode {
				t.Fatalf("code=%q want %q", v.Code, tc.wantCode)
			}
		})
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		current  string
		wantPass bool
		wantCode RejectCode
	}{
		{"strictly newer", "2.0.0", "1.9.9", true, ""},
		{"numeric ordering 1.10 > 1.9", "1.10.0", "1.9.0", true, ""},
		{"no prior release", "1.0.0", "", true, ""},
		{"equal is duplicate", "1.0.0", "1.0.0", false, RejectDuplicateVersion},
		{"older is downgrade", "1.0.0", "1.0.1", false, RejectNotMonotonic},
		{"empty declared", "", "1.0.0", false, RejectVersionUnparseable},
		{"unparseable declared", "abc", "1.0.0", false, RejectVersionUnparseable},
		{"unparseable with no prior", "abc", "", false, RejectVersionUnparseable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidateVersion(tc.declared, tc.current, nil)
			if v.Passed != tc.wantPass {
				t.Fatalf("Passed=%v want %v (%s)", v.Passed, tc.wantPass, v)
			}
			if !tc.wantPass && v.Code != tc.wantCode {
				t.Fatalf("code=%q want %q", v.Code, tc.wantCode)
			}
		})
	}
}

// errComparator always errors, exercising the comparator-error path.
type errComparator struct{}

func (errComparator) Compare(_, _ string) (int, error) { return 0, errEmptyVersion }

func TestValidateVersionCustomComparatorError(t *testing.T) {
	v := ValidateVersion("1.0.0", "0.9.0", errComparator{})
	if v.Passed || v.Code != RejectVersionUnparseable {
		t.Fatalf("want unparseable reject, got %s", v)
	}
}

func TestValidateTarget(t *testing.T) {
	policy := NewStaticTargetPolicy(
		[]TargetKey{{OSType: otaprotocol.OSLinux, Board: "known-only"}},
		[]TargetKey{{OSType: otaprotocol.OSAndroid, Board: "rk3588"}},
	)
	tests := []struct {
		name     string
		os       otaprotocol.OSType
		board    string
		policy   TargetPolicy
		wantPass bool
		wantCode RejectCode
	}{
		{"supported", otaprotocol.OSAndroid, "rk3588", policy, true, ""},
		{"undeclared os", "", "rk3588", policy, false, RejectTargetUndeclared},
		{"undeclared board", otaprotocol.OSAndroid, "", policy, false, RejectTargetUndeclared},
		{"nil policy", otaprotocol.OSAndroid, "rk3588", nil, false, RejectTargetUnknown},
		{"unknown", otaprotocol.OSAndroid, "nope", policy, false, RejectTargetUnknown},
		{"known but unsupported", otaprotocol.OSLinux, "known-only", policy, false, RejectTargetUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidateTarget(tc.os, tc.board, tc.policy)
			if v.Passed != tc.wantPass {
				t.Fatalf("Passed=%v want %v (%s)", v.Passed, tc.wantPass, v)
			}
			if !tc.wantPass && v.Code != tc.wantCode {
				t.Fatalf("code=%q want %q", v.Code, tc.wantCode)
			}
		})
	}
}

func TestValidateMetadata(t *testing.T) {
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

	t.Run("valid with matching digest", func(t *testing.T) {
		if v := ValidateMetadata(good, digest, 7); !v.Passed {
			t.Fatalf("want pass, got %s", v)
		}
	})
	t.Run("valid skip cross-check", func(t *testing.T) {
		// -1 is ValidateHash's "not measured" sentinel: it is the value that
		// skips the size cross-check. A measured 0 is NOT a skip sentinel (see
		// TestValidateMetadataSizeCrossCheck / TestS6ZeroByteArtifactForgedSizeRejected)
		// — it enforces meta.Size == 0.
		if v := ValidateMetadata(good, "", -1); !v.Passed {
			t.Fatalf("want pass, got %s", v)
		}
	})
	t.Run("incomplete meta", func(t *testing.T) {
		bad := good
		bad.Board = ""
		v := ValidateMetadata(bad, digest, 7)
		if v.Passed || v.Code != RejectMetadataIncomplete {
			t.Fatalf("want incomplete reject, got %s", v)
		}
	})
	t.Run("inconsistent digest", func(t *testing.T) {
		other := sha256.Sum256([]byte("other"))
		v := ValidateMetadata(good, hex.EncodeToString(other[:]), 7)
		if v.Passed || v.Code != RejectMetadataInconsistent {
			t.Fatalf("want inconsistent reject, got %s", v)
		}
	})
}

func TestCompareDotted(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		err  bool
	}{
		{"1.0.0", "1.0.0", 0, false},
		{"1.2.0", "1.10.0", -1, false},
		{"2.0", "1.9.9", 1, false},
		{"v1.2.3", "1.2.3", 0, false},
		{"1.2", "1.2.0", 0, false},
		{"1.2.1", "1.2", 1, false},
		{"", "1.0.0", 0, true},
		{"1.x.0", "1.0.0", 0, true},
		{"-1.0", "1.0", 0, true},
	}
	for _, tc := range tests {
		got, err := CompareDotted(tc.a, tc.b)
		if tc.err {
			if err == nil {
				t.Fatalf("CompareDotted(%q,%q) expected error", tc.a, tc.b)
			}
			continue
		}
		if err != nil {
			t.Fatalf("CompareDotted(%q,%q) unexpected error: %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("CompareDotted(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVerdictString(t *testing.T) {
	if got := pass(StageHash).String(); got != "PASS S2" {
		t.Fatalf("pass string=%q", got)
	}
	r := reject(StageSignature, RejectSignatureInvalid, "bad")
	if !strings.HasPrefix(r.String(), "REJECT S3 S3_SIGNATURE_INVALID") {
		t.Fatalf("reject string=%q", r.String())
	}
	if !r.IsReject() {
		t.Fatal("expected IsReject true")
	}
}

// TestFailFast confirms later stages do not run after an early rejection by
// asserting the artifact reader is left unread when S-stage inputs are bad...
// here specifically that a bad signature stops the pipeline before S4/S5/S6.
func TestFailFast(t *testing.T) {
	f := newFixture(t)
	in := f.input()
	in.Signature = nil // S3 will reject

	res := Validate(in)
	if res.Accepted() {
		t.Fatal("expected rejection")
	}
	if len(res.Verdicts) != 2 {
		t.Fatalf("expected exactly S2,S3 to run, got %d verdicts", len(res.Verdicts))
	}
	if res.Verdicts[0].Stage != StageHash || res.Verdicts[1].Stage != StageSignature {
		t.Fatalf("unexpected stage order: %v", res.Verdicts)
	}
}
