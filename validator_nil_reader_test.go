package otavalidator

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// TestValidateHash_NilReader is the regression guard for a nil-io.Reader
// panic in ValidateHash. Input.Artifact is an exported io.Reader field with
// no non-zero enforcement; a caller that forgets to wire the upload-body
// reader (a realistic integration mistake, e.g. a nil *bytes.Reader typed
// through an early-return code path, or simply an unset field on a
// hand-built Input{}) leaves r as a genuinely nil io.Reader interface value.
//
// Before the fix, ValidateHash passed that nil reader straight into
// io.Copy(h, r): io.Copy calls src.Read(buf) through the interface's method
// table, and calling a method on a nil interface value panics with
// "invalid memory address or nil pointer dereference" instead of producing
// an ordinary S2 reject Verdict like every other malformed-input path in
// this package. A public validation library panicking on a zero-value
// struct field crashes the caller's request handler instead of returning a
// verdict — the exact "no panic, only Verdicts" contract every other stage
// in this file upholds.
func TestValidateHash_NilReader(t *testing.T) {
	digest := strings.Repeat("a", 64) // well-formed length/charset per otaprotocol.ValidateSHA256
	hashFile := digest + "  ota.zip"

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ValidateHash panicked on a nil Artifact reader instead of returning a reject verdict: %v", r)
		}
	}()

	v, digestOut, n := ValidateHash(nil, hashFile)

	if v.Passed {
		t.Fatalf("expected a reject verdict for a nil artifact reader, got PASS")
	}
	if v.Stage != StageHash {
		t.Fatalf("stage=%q want %q", v.Stage, StageHash)
	}
	if digestOut != "" {
		t.Fatalf("digest=%q want empty on the nil-reader reject path", digestOut)
	}
	if n != -1 {
		t.Fatalf("byte count=%d want -1 (not measured) on the nil-reader reject path", n)
	}
}

// TestValidate_NilArtifactReader proves the same guard through the public
// top-level Validate entrypoint using a caller-realistic Input{} that simply
// never set Artifact (its exported zero value stays a nil io.Reader).
func TestValidate_NilArtifactReader(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	digest := strings.Repeat("b", 64)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Validate panicked on Input{} with an unset (nil) Artifact reader: %v", r)
		}
	}()

	in := Input{
		// Artifact intentionally left unset -- the exact zero-value mistake
		// a caller makes when it forgets to wire the upload body reader.
		HashFile:  digest + "  ota.zip",
		PublicKey: pub,
	}

	res := Validate(in)

	if res.Accepted() {
		t.Fatalf("expected rejection for a nil Artifact reader, got Accepted()=true")
	}
	if res.Final.Stage != StageHash {
		t.Fatalf("final stage=%q want %q", res.Final.Stage, StageHash)
	}
	if len(res.Verdicts) != 1 {
		t.Fatalf("ran %d stages want 1 (fail-fast at S2)", len(res.Verdicts))
	}
}
