package adapterapi

import "testing"

func TestOwnedResourceManifestRejectsUnsafeOrNonCanonicalPaths(t *testing.T) {
	valid, err := CanonicalOwnedResources(
		OwnedResource{Path: "state", Kind: OwnedResourceDirectory},
		OwnedResource{Path: "state/token", Kind: OwnedResourceFile},
	)
	if err != nil {
		t.Fatalf("canonical manifest: %v", err)
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("canonical manifest validation: %v", err)
	}

	for _, manifest := range []OwnedResourceManifest{
		{Resources: []OwnedResource{{Path: "/tmp/token", Kind: OwnedResourceFile}}},
		{Resources: []OwnedResource{{Path: "../token", Kind: OwnedResourceFile}}},
		{Resources: []OwnedResource{{Path: "state/../token", Kind: OwnedResourceFile}}},
		{Resources: []OwnedResource{{Path: "state\\token", Kind: OwnedResourceFile}}},
		{Resources: []OwnedResource{{Path: "token", Kind: OwnedResourceFile}, {Path: "token", Kind: OwnedResourceFile}}},
		{Resources: []OwnedResource{{Path: "token", Kind: OwnedResourceInvalid}}},
	} {
		if err := manifest.Validate(); err == nil {
			t.Fatalf("unsafe manifest %#v was accepted", manifest)
		}
	}
}
