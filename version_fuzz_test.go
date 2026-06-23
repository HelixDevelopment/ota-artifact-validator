package otavalidator

import (
	"testing"
)

// FuzzCompareDotted fuzzes the dotted-version comparator. Version strings
// (current device version vs offered artifact version) are attacker-influenceable
// inputs to the anti-downgrade / rollout-eligibility decision. CompareDotted
// parses both sides component-by-component via strconv.Atoi. Property: ANY two
// strings must yield (cmp, nil) or (0, err) — never a panic — and the result
// must obey the comparator axioms it claims (antisymmetry + reflexivity) for the
// inputs it accepts.
func FuzzCompareDotted(f *testing.F) {
	pairs := [][2]string{
		{"1.0.0", "1.0.0"},
		{"1.10.2", "1.4.0"},
		{"v1.2", "1.2.0"},
		{"", "1"},
		{"1.2.3.4.5.6.7.8.9", "0"},
		{"-1", "1"},
		{"1.2.x", "1.2.0"},
		{"99999999999999999999", "1"}, // overflows int via Atoi -> error path
		{"  1.2  ", "1.2"},
		{".", ".."},
		{"v", "v0"},
		{"00.01", "0.1"},
	}
	for _, p := range pairs {
		f.Add(p[0], p[1])
	}

	f.Fuzz(func(t *testing.T, a, b string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CompareDotted panicked on (%q,%q): %v", a, b, r)
			}
		}()

		cmp, err := CompareDotted(a, b)
		if err != nil {
			// Error is fine for malformed versions; cmp must be the zero value.
			if cmp != 0 {
				t.Fatalf("CompareDotted(%q,%q) returned err but cmp=%d (want 0)", a, b, cmp)
			}
			return
		}
		if cmp < -1 || cmp > 1 {
			t.Fatalf("CompareDotted(%q,%q) returned out-of-range cmp=%d", a, b, cmp)
		}
		// Antisymmetry: when both sides parse, swapping the arguments must
		// negate the result. A violation is a real ordering bug that could
		// mis-decide an anti-downgrade gate.
		rev, rerr := CompareDotted(b, a)
		if rerr != nil {
			t.Fatalf("CompareDotted(%q,%q)=%d ok but reverse CompareDotted(%q,%q) errored: %v", a, b, cmp, b, a, rerr)
		}
		if cmp != -rev {
			t.Fatalf("antisymmetry violated: CompareDotted(%q,%q)=%d but CompareDotted(%q,%q)=%d", a, b, cmp, b, a, rev)
		}
	})
}
