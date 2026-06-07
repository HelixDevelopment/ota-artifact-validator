package otavalidator

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareDotted is the default VersionComparator: it compares dotted-numeric
// version identifiers (e.g. "1.4.0" vs "1.10.2") component-by-component as
// integers, so 1.10.0 > 1.9.0. An optional leading "v" is tolerated. Versions
// with differing component counts are compared as if the shorter were
// zero-padded (1.2 == 1.2.0). It returns an error if a component is not a
// non-negative integer.
func CompareDotted(a, b string) (int, error) {
	pa, err := parseDotted(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseDotted(b)
	if err != nil {
		return 0, err
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(pa) {
			ai = pa[i]
		}
		if i < len(pb) {
			bi = pb[i]
		}
		if ai != bi {
			if ai < bi {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// parseDotted parses a dotted-numeric version into its integer components.
func parseDotted(v string) ([]int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errEmptyVersion
	}
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid version component %q in %q", p, v)
		}
		out[i] = n
	}
	return out, nil
}
