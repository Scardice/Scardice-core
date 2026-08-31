package jsengine

// Descriptor is immutable provider metadata returned as a value snapshot.
type Descriptor struct {
	ID           EngineID
	Name         string
	Version      string
	Language     string

	ABIMajor     uint32
	ABIMinor     uint32
	HostABIMajor uint32
	HostABIMinor uint32

	Capabilities CapabilitySet
	Builtin      bool
	Path         string
}

// RuntimeManifest contains discovery metadata for a runtime candidate. A
// manifest is metadata only: registering it does not load or execute a
// runtime library.
type RuntimeManifest struct {
	ID           EngineID
	Name         string
	Version      string
	Language     string

	ABIMajor     uint32
	ABIMinor     uint32
	HostABIMajor uint32
	HostABIMinor uint32

	Capabilities CapabilitySet
	Path         string

	// Descriptor permits callers that already have manifest-shaped metadata to
	// pass it without exposing a loader or provider callback in the registry.
	Descriptor Descriptor
}

func (m RuntimeManifest) descriptor() Descriptor {
	d := m.Descriptor
	if d.ID == "" {
		d.ID = m.ID
	}
	if d.Name == "" {
		d.Name = m.Name
	}
	if d.Version == "" {
		d.Version = m.Version
	}
	if d.Language == "" {
		d.Language = m.Language
	}
	if d.ABIMajor == 0 {
		d.ABIMajor = m.ABIMajor
	}
	if d.ABIMinor == 0 {
		d.ABIMinor = m.ABIMinor
	}
	if d.HostABIMajor == 0 {
		d.HostABIMajor = m.HostABIMajor
	}
	if d.HostABIMinor == 0 {
		d.HostABIMinor = m.HostABIMinor
	}
	if d.Capabilities == 0 {
		d.Capabilities = m.Capabilities
	}
	if d.Path == "" {
		d.Path = m.Path
	}
	d.Builtin = false
	return d
}
