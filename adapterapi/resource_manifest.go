package adapterapi

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

const MaxOwnedResources = 256

// OwnedResourceKind describes an adapter resource whose cleanup is owned by
// the runtime generation. Paths are always relative to RuntimeInit.ResourceRoot.
type OwnedResourceKind uint8

const (
	OwnedResourceInvalid OwnedResourceKind = iota
	OwnedResourceDirectory
	OwnedResourceFile
)

func (kind OwnedResourceKind) Valid() bool {
	return kind == OwnedResourceDirectory || kind == OwnedResourceFile
}

// OwnedResource is a canonical relative path in the runtime-owned manifest.
type OwnedResource struct {
	Path string            `json:"path"`
	Kind OwnedResourceKind `json:"kind"`
}

// OwnedResourceManifest exposes exactly the filesystem paths a runtime may
// create and later remove. The manifest cannot name an absolute, parent, or
// duplicate path, so cleanup remains inside the generation-owned root.
type OwnedResourceManifest struct {
	Resources []OwnedResource `json:"resources"`
}

func (manifest OwnedResourceManifest) Validate() error {
	if len(manifest.Resources) > MaxOwnedResources {
		return fmt.Errorf("%w: owned resource limit exceeded", ErrInvalidContract)
	}
	previous := ""
	for _, resource := range manifest.Resources {
		if !resource.Kind.Valid() || resource.Path == "" || len(resource.Path) > MaxIdentifierBytes || strings.Contains(resource.Path, "\\") || path.IsAbs(resource.Path) || path.Clean(resource.Path) != resource.Path || resource.Path == "." || strings.HasPrefix(resource.Path, "../") {
			return fmt.Errorf("%w: invalid owned resource", ErrInvalidContract)
		}
		if previous >= resource.Path {
			return fmt.Errorf("%w: owned resources are not canonical", ErrInvalidContract)
		}
		previous = resource.Path
	}
	return nil
}

// OwnedResourceManifestRuntime declares the canonical cleanup manifest for a
// runtime generation. Every adapter that owns generated filesystem paths must
// implement it; an empty manifest is valid for runtimes without such paths.
type OwnedResourceManifestRuntime interface {
	OwnedResources() OwnedResourceManifest
}

// CanonicalOwnedResources creates a sorted manifest after validating every
// path. It is the only helper providers should use when building manifests.
func CanonicalOwnedResources(resources ...OwnedResource) (OwnedResourceManifest, error) {
	copyResources := append([]OwnedResource(nil), resources...)
	sort.Slice(copyResources, func(left, right int) bool { return copyResources[left].Path < copyResources[right].Path })
	manifest := OwnedResourceManifest{Resources: copyResources}
	if err := manifest.Validate(); err != nil {
		return OwnedResourceManifest{}, err
	}
	return manifest, nil
}
