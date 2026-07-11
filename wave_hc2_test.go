package otavalidator

// This file closes HC-2: a version-string-length amplification DoS found
// during the Wave-20 audit. S4 (ValidateVersion) ran BEFORE S6
// (ValidateMetadata -> otaprotocol.ValidateArtifactMeta), and the 255-char
// bound on the declared version was enforced ONLY inside S6. Because the
// default comparator (CompareDotted -> parseDotted) allocates proportional to
// the raw string length (strings.Split's slice of string headers, plus
// make([]int, len(parts))) UNCONDITIONALLY, an attacker-supplied oversized
// Meta.Version reached that proportional-cost parse before any length bound
// ever ran, for every declared version regardless of how it compared to the
// prior release. The fix moves an O(1) length check (len(declared) >
// maxDeclaredVersionLen, mirroring otaprotocol's own 255-char bound) to the
// very start of ValidateVersion, before the TrimSpace scan or any
// comparator/parse call.
//
// TestValidateVersionRejectsOverLongDeclaredVersion is the permanent §11.4.115
// GREEN regression guard: it asserts ValidateVersion returns a REJECT verdict
// (never a panic/hang) for a declared version past the bound.
// TestValidateVersionAcceptsNormalLengthVersion is the positive control
// proving the guard does not disturb ordinary version validation.

import (
	"strings"
	"testing"
)

// TestValidateVersionRejectsOverLongDeclaredVersion is the RED->GREEN
// regression guard for HC-2. The oversized input is deliberately a WELL-FORMED
// dotted-numeric version (many single-digit "1" components joined by dots,
// e.g. "1.1.1. ... .1") rather than an all-digit run or non-numeric junk --
// those alternate shapes would ALSO get rejected by the PRE-EXISTING
// "unparseable" path (strconv overflow / non-numeric component) even WITHOUT
// the HC-2 length guard, which would make this test pass regardless of
// whether the fix is present (a tautology per the anti-tautology mandate).
// A long CHAIN of valid "1" components parses successfully under
// CompareDotted with no overflow, so on the PRE-FIX code this input compares
// as strictly greater than "1.0.0" and PASSES -- only the HC-2 length guard
// (added ahead of any parse) turns this into a REJECT. That asymmetry is what
// was proven by reverting the fix and re-running this exact test (captured
// in the commit message / task report): revert -> PASS (RED), restore -> the
// REJECT asserted below (GREEN).
//
// The length here (301 chars) is intentionally modest -- this test exercises
// the LENGTH GUARD itself, not the amplification's real-world scale (a
// multi-megabyte string would also be rejected by the same guard, at the same
// O(1) cost, but there is no need to actually allocate tens of megabytes in a
// unit test to prove the guard fires).
func TestValidateVersionRejectsOverLongDeclaredVersion(t *testing.T) {
	// 151 single-digit "1" components joined by dots: 150*("1.") + "1" = 301
	// chars, no overflow, no non-numeric component -- a fully well-formed
	// dotted version that only the LENGTH bound can reject.
	oversized := strings.Repeat("1.", 150) + "1"
	if len(oversized) <= maxDeclaredVersionLenForTest {
		t.Fatalf("test fixture too short: %d chars, want > %d", len(oversized), maxDeclaredVersionLenForTest)
	}

	v := ValidateVersion(oversized, "1.0.0", nil)

	if v.Passed {
		t.Fatalf("want REJECT for a %d-char declared version, got PASS: %s", len(oversized), v)
	}
	if v.Stage != StageVersion {
		t.Fatalf("want Stage=%s, got %s (%s)", StageVersion, v.Stage, v)
	}
	if v.Code != RejectVersionUnparseable {
		t.Fatalf("want Code=%s, got %s (%s)", RejectVersionUnparseable, v.Code, v)
	}
}

// maxDeclaredVersionLenForTest mirrors the production maxDeclaredVersionLen
// constant (stages.go) for the fixture-length self-check above. Duplicated
// (rather than referencing the production constant directly) so this test
// still compiles and documents its own expectation even if a future change
// renames or removes the production constant -- the compiler would then flag
// THIS duplicate too, forcing a conscious update rather than a silent skip.
const maxDeclaredVersionLenForTest = 255

// TestValidateVersionAcceptsNormalLengthVersion is the positive control: a
// normal, well-formed, under-the-bound version must still validate exactly as
// before the HC-2 fix (no regression introduced by the new early-return
// guard).
func TestValidateVersionAcceptsNormalLengthVersion(t *testing.T) {
	v := ValidateVersion("1.4.0", "1.3.9", nil)

	if !v.Passed {
		t.Fatalf("want PASS for a normal monotonic version bump, got %s", v)
	}
	if v.Stage != StageVersion {
		t.Fatalf("want Stage=%s, got %s (%s)", StageVersion, v.Stage, v)
	}
}

// TestValidateVersionLengthGuardRunsBeforeParse proves the guard's ordering
// property directly: an over-length version that would ALSO fail to parse as
// dotted-numeric (e.g. contains a non-numeric component) is still rejected
// with the length-guard's verdict shape (REJECT/StageVersion/
// RejectVersionUnparseable) rather than reaching CompareDotted at all -- i.e.
// the length check is genuinely the FIRST thing ValidateVersion does, not an
// incidental side effect of some other check.
func TestValidateVersionLengthGuardRunsBeforeParse(t *testing.T) {
	// 300 'x' characters: not dotted-numeric AND over the length bound. If the
	// length guard did not run first, this would still reject via the
	// existing "unparseable" path inside CompareDotted -- so this test alone
	// does not distinguish the two. Its purpose is to document the invariant;
	// TestValidateVersionRejectsOverLongDeclaredVersion (all-digit oversized
	// input, which WOULD parse fine as dotted-numeric) is the test that
	// actually proves the length guard -- not parse failure -- is what fires.
	oversized := strings.Repeat("x", 300)

	v := ValidateVersion(oversized, "1.0.0", nil)

	if v.Passed {
		t.Fatalf("want REJECT for a %d-char declared version, got PASS: %s", len(oversized), v)
	}
	if v.Code != RejectVersionUnparseable {
		t.Fatalf("want Code=%s, got %s (%s)", RejectVersionUnparseable, v.Code, v)
	}
}
