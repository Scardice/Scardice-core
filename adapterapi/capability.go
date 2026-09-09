package adapterapi

// CapabilitySet is a closed bitset advertised by a runtime. Unknown bits are
// invalid; callers must branch on declared capabilities rather than probe SDKs.
type CapabilitySet uint64

const (
	CapabilityInbound CapabilitySet = 1 << iota
	CapabilityOutbound
	CapabilityLifecycle
	CapabilityActions
	CapabilityArtifacts
	CapabilityRichMessages
)

const capabilityKnownBits = CapabilityInbound | CapabilityOutbound | CapabilityLifecycle | CapabilityActions | CapabilityArtifacts | CapabilityRichMessages

// Compatibility aliases make the vocabulary readable at call sites while
// preserving one closed set of bits.
const (
	CapabilityReceive = CapabilityInbound
	CapabilitySend    = CapabilityOutbound
	CapabilityAction  = CapabilityActions
)

func (set CapabilitySet) Valid() bool { return set&^capabilityKnownBits == 0 }
func (set CapabilitySet) Has(required CapabilitySet) bool {
	return set.Valid() && required.Valid() && set&required == required
}
func (set CapabilitySet) With(other ...CapabilitySet) CapabilitySet {
	for _, value := range other {
		set |= value
	}
	return set
}
