package jsengine

// CapabilitySet is the bitset advertised by a provider.
type CapabilitySet uint64

const (
	CapabilityScript CapabilitySet = 1 << iota
	CapabilityCommonJS
	CapabilityESM
	CapabilityPromise
	CapabilityTimers
	CapabilityHostObject
	CapabilityHostFunction
	CapabilityAsyncHostService
	CapabilitySourceLocation
	CapabilityHostService
	CapabilityContextPropagation
)

// Has reports whether all requested capabilities are present.
func (set CapabilitySet) Has(requested CapabilitySet) bool {
	return set&requested == requested
}

// With returns a set containing the supplied capabilities.
func (set CapabilitySet) With(capabilities ...CapabilitySet) CapabilitySet {
	for _, capability := range capabilities {
		set |= capability
	}
	return set
}
