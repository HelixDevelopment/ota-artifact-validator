package otavalidator

import otaprotocol "github.com/HelixDevelopment/ota-protocol"

// target keys a {os_type, board} pair.
type target struct {
	os    otaprotocol.OSType
	board string
}

// StaticTargetPolicy is an in-memory TargetPolicy backed by an explicit set of
// known targets and an explicit set of supported targets. It is a convenience
// for callers (and tests) that do not need a database-backed policy; the
// pipeline accepts any TargetPolicy implementation.
//
// A target is Supported only if it is also present in the known set.
type StaticTargetPolicy struct {
	known     map[target]struct{}
	supported map[target]struct{}
}

// NewStaticTargetPolicy builds a policy. supported targets are implicitly added
// to the known set so a supported target is always known.
func NewStaticTargetPolicy(known, supported []TargetKey) *StaticTargetPolicy {
	p := &StaticTargetPolicy{
		known:     make(map[target]struct{}),
		supported: make(map[target]struct{}),
	}
	for _, k := range known {
		p.known[target{k.OSType, k.Board}] = struct{}{}
	}
	for _, k := range supported {
		t := target{k.OSType, k.Board}
		p.known[t] = struct{}{}
		p.supported[t] = struct{}{}
	}
	return p
}

// TargetKey is an exported {os_type, board} pair for constructing a
// StaticTargetPolicy.
type TargetKey struct {
	OSType otaprotocol.OSType
	Board  string
}

// Known reports whether the target is recognized.
func (p *StaticTargetPolicy) Known(os otaprotocol.OSType, board string) bool {
	_, ok := p.known[target{os, board}]
	return ok
}

// Supported reports whether the target is accepted for the current phase.
func (p *StaticTargetPolicy) Supported(os otaprotocol.OSType, board string) bool {
	_, ok := p.supported[target{os, board}]
	return ok
}
