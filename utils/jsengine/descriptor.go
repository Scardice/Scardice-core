package jsengine

import "strings"

// Descriptor is immutable provider metadata returned as a value snapshot.
type Descriptor struct {
	ID       EngineID
	Name     string
	Version  string
	Language string
	Author   string

	ABIMajor     uint32
	ABIMinor     uint32
	HostABIMajor uint32
	HostABIMinor uint32

	Capabilities CapabilitySet
	// Services lists explicitly supported host-service names. Native ABI
	// descriptors do not carry names; the native loader supplies this metadata
	// from the provider manifest.
	Services   []string
	Extensions []string
	Builtin    bool
	Path       string
}

// RuntimeManifest contains discovery metadata for a runtime candidate. A
// manifest is metadata only: registering it does not load or execute a
// runtime library.
type RuntimeManifest struct {
	ID       EngineID
	Name     string
	Version  string
	Language string
	Author   string

	ABIMajor     uint32
	ABIMinor     uint32
	HostABIMajor uint32
	HostABIMinor uint32

	Capabilities CapabilitySet
	Services     []string
	Extensions   []string
	Path         string

	// Descriptor permits callers that already have manifest-shaped metadata to
	// pass it without exposing a loader or provider callback in the registry.
	Descriptor Descriptor
}

func (m RuntimeManifest) descriptor() Descriptor {
	d := m.Descriptor
	if m.ID != "" {
		d.ID = m.ID
	}
	if m.Name != "" {
		d.Name = m.Name
	}
	if m.Version != "" {
		d.Version = m.Version
	}
	if m.Language != "" {
		d.Language = m.Language
	}
	if m.Author != "" {
		d.Author = m.Author
	}
	if m.ABIMajor != 0 {
		d.ABIMajor = m.ABIMajor
	}
	if m.ABIMinor != 0 {
		d.ABIMinor = m.ABIMinor
	}
	if m.HostABIMajor != 0 {
		d.HostABIMajor = m.HostABIMajor
	}
	if m.HostABIMinor != 0 {
		d.HostABIMinor = m.HostABIMinor
	}
	if m.Capabilities != 0 {
		d.Capabilities = m.Capabilities
	}
	if m.Services != nil {
		d.Services = append([]string(nil), m.Services...)
	}
	if m.Extensions != nil {
		d.Extensions = append([]string(nil), m.Extensions...)
	}
	if m.Path != "" {
		d.Path = m.Path
	}
	d.Builtin = false
	return d
}

// NormalizeExtension returns the canonical lower-case dotted suffix.
func NormalizeExtension(extension string) string {
	extension = strings.ToLower(strings.TrimSpace(extension))
	if extension == "" {
		return ""
	}
	if !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}
	return extension
}

// NormalizeExtensions returns deduplicated suffixes while preserving
// declaration order.
func NormalizeExtensions(extensions []string) []string {
	normalized := make([]string, 0, len(extensions))
	seen := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		extension = NormalizeExtension(extension)
		if extension == "" {
			continue
		}
		if _, ok := seen[extension]; ok {
			continue
		}
		seen[extension] = struct{}{}
		normalized = append(normalized, extension)
	}
	return normalized
}
