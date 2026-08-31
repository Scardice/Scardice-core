package native

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"Scardice-core/utils/jsengine"

	"strings"
)

type ABIRequirement struct {
	Major    uint32 `json:"major"`
	MinMinor uint32 `json:"minMinor"`
}

type Manifest struct {
	Schema     uint32                 `json:"schema"`
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Version    string                 `json:"version"`
	Language   string                 `json:"language"`
	RuntimeABI ABIRequirement         `json:"runtimeAbi"`
	HostABI    ABIRequirement         `json:"hostAbi"`
	Libraries  map[string]string      `json:"libraries"`
	Capabilities uint64               `json:"capabilities,omitempty"`
	ManifestPath string               `json:"-"`
}

type Candidate struct {
	Manifest   Manifest
	LibraryPath string
	loaded     bool
}

func (c Candidate) Loaded() bool { return c.loaded }

// Discover scans only immediate runtime package directories under root. It
// reads metadata but does not open or execute any native library.
func Discover(root string) ([]Candidate, error) {
	if strings.TrimSpace(root) == "" {
		executable, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("find executable directory: %w", err)
		}
		root = filepath.Join(filepath.Dir(executable), "runtimes")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime package root: %w", err)
	}
	root = absoluteRoot
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []Candidate{}, nil
		}
		return nil, fmt.Errorf("scan runtime packages: %w", err)
	}
	key := runtime.GOOS + "-" + runtime.GOARCH
	candidates := make([]Candidate, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		packageDir := filepath.Join(root, entry.Name())
		manifestPath := filepath.Join(packageDir, "runtime.json")
		contents, err := os.ReadFile(manifestPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", manifestPath, err)
		}
		var manifest Manifest
		if err := json.Unmarshal(contents, &manifest); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrManifestMismatch, manifestPath, err)
		}
		if manifest.Schema != 1 || manifest.ID == "" || manifest.Name == "" || manifest.Version == "" ||
			manifest.Language == "" || manifest.RuntimeABI.Major == 0 || manifest.HostABI.Major == 0 {
			return nil, fmt.Errorf("%w: invalid required fields in %s", ErrManifestMismatch, manifestPath)
		}
		libraryName, ok := manifest.Libraries[key]
		if !ok || strings.TrimSpace(libraryName) == "" {
			return nil, fmt.Errorf("%w: %s has no %s library", ErrUnsupportedArchitecture, manifestPath, key)
		}
		libraryPath, err := packagePath(packageDir, libraryName)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrManifestMismatch, manifestPath, err)
		}
		manifest.ManifestPath = manifestPath
		candidates = append(candidates, Candidate{Manifest: manifest, LibraryPath: libraryPath})
	}
	return candidates, nil
}

func packagePath(packageDir, libraryName string) (string, error) {
	if filepath.IsAbs(libraryName) {
		return "", fmt.Errorf("library path must be relative")
	}
	clean := filepath.Clean(libraryName)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("library path escapes package directory")
	}
	path := filepath.Join(packageDir, clean)
	if real, err := filepath.EvalSymlinks(path); err == nil {
		rel, relErr := filepath.Rel(packageDir, real)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("library symlink escapes package directory")
		}
	}
	return path, nil
}

// Load resolves a candidate and executes its native query exactly once per
// call. The returned provider keeps the C-owned library resident for process
// lifetime.
func (c Candidate) Load() (*Provider, error) { return loadNative(c) }

type Loader struct {
	root       string
	candidates []Candidate
}

func NewLoader(root string) *Loader { return &Loader{root: root} }

func (l *Loader) Discover() ([]Candidate, error) {
	candidates, err := Discover(l.root)
	if err != nil {
		return nil, err
	}
	l.candidates = candidates
	return append([]Candidate(nil), candidates...), nil
}

func (l *Loader) Load(id string) (*Provider, error) {
	if l.candidates == nil {
		if _, err := l.Discover(); err != nil {
			return nil, err
		}
	}
	want := jsengine.NormalizeEngineID(id)
	for _, candidate := range l.candidates {
		if jsengine.NormalizeEngineID(candidate.Manifest.ID) == want {
			return candidate.Load()
		}
	}
	return nil, fmt.Errorf("%w: candidate %q", ErrMissingLibrary, id)
}

// RegisterCandidates adds metadata-only candidates to the engine registry.
// It never calls Load and never replaces an already registered builtin.
func (l *Loader) RegisterCandidates(registry jsengine.Registry) error {
	if registry == nil {
		return fmt.Errorf("%w: nil registry", jsengine.ErrInvalidProvider)
	}
	if l.candidates == nil {
		if _, err := l.Discover(); err != nil {
			return err
		}
	}
	for _, candidate := range l.candidates {
		manifest := candidate.Manifest
		if err := registry.RegisterCandidate(jsengine.RuntimeManifest{
			ID: jsengine.EngineID(manifest.ID), Name: manifest.Name, Version: manifest.Version,
			Language: manifest.Language, ABIMajor: manifest.RuntimeABI.Major,
			ABIMinor: manifest.RuntimeABI.MinMinor, HostABIMajor: manifest.HostABI.Major,
			HostABIMinor: manifest.HostABI.MinMinor, Capabilities: jsengine.CapabilitySet(manifest.Capabilities),
			Path: candidate.LibraryPath,
		}); err != nil {
			return err
		}
	}
	return nil
}

func wrapNoCgo(path string) error {
	return fmt.Errorf("%w: cgo is required to load %s", ErrNativeUnavailable, path)
}
