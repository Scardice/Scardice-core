//go:build !cgo

package native

import (
	"context"
	"errors"
	"fmt"
	"os"

	"Scardice-core/utils/jsengine"
)
type Provider struct{ candidate Candidate }
type LoadedProvider = Provider

func Load(candidate Candidate) (*Provider, error) { return candidate.Load() }
func loadNative(candidate Candidate) (*Provider, error) {
	if _, err := os.Stat(candidate.LibraryPath); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrMissingLibrary, candidate.LibraryPath)
	}
	return nil, wrapNoCgo(candidate.LibraryPath)
}
func (p *Provider) Descriptor() jsengine.Descriptor { return jsengine.Descriptor{ID: jsengine.NormalizeEngineID(p.candidate.Manifest.ID), Name: p.candidate.Manifest.Name, Version: p.candidate.Manifest.Version, Language: p.candidate.Manifest.Language, Path: p.candidate.LibraryPath} }
func (p *Provider) Open(context.Context, jsengine.RuntimeOptions) (jsengine.Loop, error) { return nil, wrapNoCgo(p.candidate.LibraryPath) }
func ResidentLibraryCount() uint64 { return 0 }
