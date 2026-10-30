package dice

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"Scardice-core/utils"
	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/native"
)

const (
	jsRuntimePendingStateVersion = 1
	maxJSRuntimeManifestBytes    = 1 << 20
	maxJSRuntimePendingBytes     = 1 << 20
)

var (
	ErrJSRuntimeStoreUnavailable = errors.New("JavaScript runtime package store is unavailable")
	ErrInvalidJSRuntimeArchive   = errors.New("invalid JavaScript runtime archive")
	ErrJSRuntimeArchiveTooLarge  = errors.New("JavaScript runtime archive exceeds size limit")
	ErrJSRuntimePackageExists    = errors.New("JavaScript runtime package already exists")
	ErrJSRuntimePackagePending   = errors.New("JavaScript runtime package already has a pending change")
	ErrJSRuntimeNotManaged       = errors.New("JavaScript runtime package is not managed by this Dice")
	ErrJSRuntimeInUse            = errors.New("JavaScript runtime is still referenced by routing configuration")
	ErrInvalidJSRuntimePending   = errors.New("invalid pending JavaScript runtime state")
)

const (
	jsRuntimeActionInstall   = "install"
	jsRuntimeActionUninstall = "uninstall"
)

type JSRuntimePendingChange struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type jsRuntimeArchiveLimits struct {
	maxArchiveBytes  int64
	maxExpandedBytes int64
	maxEntries       int
	maxPathBytes     int
}

var defaultJSRuntimeArchiveLimits = jsRuntimeArchiveLimits{
	maxArchiveBytes:  64 << 20,
	maxExpandedBytes: 256 << 20,
	maxEntries:       512,
	maxPathBytes:     1024,
}

type jsRuntimePendingRecord struct {
	JSRuntimePendingChange
	ManifestSHA256 string `json:"manifestSha256,omitempty"`
}

type jsRuntimePendingState struct {
	Version int                      `json:"version"`
	Changes []jsRuntimePendingRecord `json:"changes"`
}

type jsRuntimePackageStore struct {
	activeRoot   string
	installRoot  string
	incomingRoot string
	pendingFile  string
	limits       jsRuntimeArchiveLimits
	mu           sync.Mutex
}

func newJSRuntimePackageStore(dataDir string) (*jsRuntimePackageStore, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("%w: Dice data directory is empty", ErrJSRuntimeStoreUnavailable)
	}
	root, err := filepath.Abs(filepath.Join(dataDir, "js-runtimes"))
	if err != nil {
		return nil, fmt.Errorf("resolve runtime package directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
		return nil, fmt.Errorf("create Dice data directory: %w", err)
	}
	store := &jsRuntimePackageStore{
		activeRoot:   filepath.Join(root, "active"),
		installRoot:  filepath.Join(root, "pending", "install"),
		incomingRoot: filepath.Join(root, "incoming"),
		pendingFile:  filepath.Join(root, "pending.json"),
		limits:       defaultJSRuntimeArchiveLimits,
	}
	for _, dir := range []string{root, store.activeRoot, filepath.Join(root, "pending"), store.installRoot, store.incomingRoot} {
		if err := ensureJSRuntimeStoreDirectory(dir); err != nil {
			return nil, err
		}
	}
	if err := cleanupJSRuntimeTemporaryFiles(store.installRoot, ".extract-", true); err != nil {
		return nil, err
	}
	if err := cleanupJSRuntimeTemporaryFiles(store.incomingRoot, ".runtime-archive-", false); err != nil {
		return nil, err
	}
	return store, nil
}

func ensureJSRuntimeStoreDirectory(directory string) error {
	if err := os.Mkdir(directory, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create runtime package directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: runtime store path is not a real directory: %s", ErrJSRuntimeStoreUnavailable, directory)
	}
	return nil
}
func cleanupJSRuntimeTemporaryFiles(directory, prefix string, directories bool) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || directories && !info.IsDir() || !directories && !info.Mode().IsRegular() {
			continue
		}
		if directories {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func normalizeManagedRuntimeID(raw string) (string, error) {
	if raw == "" || len(raw) > 128 || strings.TrimSpace(raw) != raw || string(jsengine.NormalizeEngineID(raw)) != raw {
		return "", fmt.Errorf("%w: invalid runtime ID %q", ErrInvalidJSRuntimeArchive, raw)
	}
	for index, char := range raw {
		valid := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.'
		if !valid || index == 0 && (char == '.' || char == '-') {
			return "", fmt.Errorf("%w: invalid runtime ID %q", ErrInvalidJSRuntimeArchive, raw)
		}
	}
	if raw == "." || raw == ".." {
		return "", fmt.Errorf("%w: invalid runtime ID %q", ErrInvalidJSRuntimeArchive, raw)
	}
	return raw, nil
}

func (s *jsRuntimePackageStore) StageInstall(
	source io.Reader,
	registered []jsengine.Descriptor,
	requirements jsengine.RuntimeRequirements,
) (JSRuntimePendingChange, error) {
	if s == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	if source == nil {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: empty archive body", ErrInvalidJSRuntimeArchive)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadPendingLocked()
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	archivePath, _, err := spoolRuntimeArchive(source, s.incomingRoot, s.limits.maxArchiveBytes)
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	defer os.Remove(archivePath)
	archive, err := os.Open(archivePath)
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	defer archive.Close()

	extractRoot, err := os.MkdirTemp(s.installRoot, ".extract-")
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	defer os.RemoveAll(extractRoot)
	packageRoot, err := extractJSRuntimeArchive(archive, extractRoot, s.limits)
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	candidate, manifestDigest, err := validateJSRuntimePackage(extractRoot, packageRoot, requirements)
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	id, err := normalizeManagedRuntimeID(candidate.Manifest.ID)
	if err != nil || id != packageRoot {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: package directory and manifest ID differ", ErrInvalidJSRuntimeArchive)
	}
	for _, descriptor := range registered {
		if jsengine.NormalizeEngineID(string(descriptor.ID)) == jsengine.EngineID(id) {
			return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimePackageExists, id)
		}
	}
	for _, change := range state.Changes {
		if change.ID == id {
			return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimePackagePending, id)
		}
	}
	activePath := filepath.Join(s.activeRoot, id)
	if _, err := os.Lstat(activePath); err == nil {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimePackageExists, id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return JSRuntimePendingChange{}, err
	}
	stagedPath := filepath.Join(s.installRoot, id)
	if _, err := os.Lstat(stagedPath); err == nil {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimePackagePending, id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return JSRuntimePendingChange{}, err
	}
	if err := os.Rename(filepath.Join(extractRoot, packageRoot), stagedPath); err != nil {
		return JSRuntimePendingChange{}, err
	}
	syncRuntimeDirectory(s.installRoot)

	change := JSRuntimePendingChange{ID: id, Action: jsRuntimeActionInstall, Name: candidate.Manifest.Name, Version: candidate.Manifest.Version}
	state.Changes = append(state.Changes, jsRuntimePendingRecord{
		JSRuntimePendingChange: change,
		ManifestSHA256:         manifestDigest,
	})
	sortRuntimePending(state.Changes)
	if err := s.writePendingLocked(state); err != nil {
		_ = os.RemoveAll(stagedPath)
		syncRuntimeDirectory(s.installRoot)
		return JSRuntimePendingChange{}, err
	}
	return change, nil
}

func (s *jsRuntimePackageStore) StageUninstall(id string) (JSRuntimePendingChange, error) {
	if s == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	id, err := normalizeManagedRuntimeID(id)
	if err != nil {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimeNotManaged, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadPendingLocked()
	if err != nil {
		return JSRuntimePendingChange{}, err
	}
	for _, pending := range state.Changes {
		if pending.ID == id {
			return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimePackagePending, id)
		}
	}
	packageDir := filepath.Join(s.activeRoot, id)
	manifest, _, err := readJSRuntimeManifest(packageDir)
	if err != nil || manifest.ID != id {
		if err == nil {
			err = ErrJSRuntimeNotManaged
		}
		return JSRuntimePendingChange{}, fmt.Errorf("%w: %s: %w", ErrJSRuntimeNotManaged, id, err)
	}
	change := JSRuntimePendingChange{ID: id, Action: jsRuntimeActionUninstall, Name: manifest.Name, Version: manifest.Version}
	state.Changes = append(state.Changes, jsRuntimePendingRecord{JSRuntimePendingChange: change})
	sortRuntimePending(state.Changes)
	if err := s.writePendingLocked(state); err != nil {
		return JSRuntimePendingChange{}, err
	}
	return change, nil
}

func (s *jsRuntimePackageStore) PendingChanges() ([]JSRuntimePendingChange, error) {
	if s == nil {
		return []JSRuntimePendingChange{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadPendingLocked()
	if err != nil {
		return nil, err
	}
	changes := make([]JSRuntimePendingChange, 0, len(state.Changes))
	for _, record := range state.Changes {
		changes = append(changes, record.JSRuntimePendingChange)
	}
	return changes, nil
}

func (s *jsRuntimePackageStore) ApplyPending(requirements jsengine.RuntimeRequirements) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadPendingLocked()
	if err != nil {
		return err
	}
	recovered, err := s.recoverOrphanedInstallRecords(&state)
	if err != nil {
		return err
	}
	if recovered {
		if err := s.writePendingLocked(state); err != nil {
			return err
		}
	}
	var applyErrors []error
	for index := 0; index < len(state.Changes); {
		record := state.Changes[index]
		var applyErr error
		switch record.Action {
		case jsRuntimeActionInstall:
			applyErr = s.applyPendingInstall(record, requirements)
		case jsRuntimeActionUninstall:
			applyErr = s.applyPendingUninstall(record.ID)
		default:
			applyErr = fmt.Errorf("%w: unknown action %q", ErrInvalidJSRuntimePending, record.Action)
		}
		if applyErr != nil {
			applyErrors = append(applyErrors, fmt.Errorf("apply pending runtime %q: %w", record.ID, applyErr))
			index++
			continue
		}
		state.Changes = append(state.Changes[:index], state.Changes[index+1:]...)
		if err := s.writePendingLocked(state); err != nil {
			return errors.Join(append(applyErrors, err)...)
		}
	}
	return errors.Join(applyErrors...)
}
func (s *jsRuntimePackageStore) recoverOrphanedInstallRecords(state *jsRuntimePendingState) (bool, error) {
	pendingIDs := make(map[string]struct{}, len(state.Changes))
	for _, record := range state.Changes {
		pendingIDs[record.ID] = struct{}{}
	}
	entries, err := os.ReadDir(s.installRoot)
	if err != nil {
		return false, err
	}
	recovered := false
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		id, err := normalizeManagedRuntimeID(entry.Name())
		if err != nil || id != entry.Name() {
			continue
		}
		if _, exists := pendingIDs[id]; exists {
			continue
		}
		if _, err := os.Lstat(filepath.Join(s.activeRoot, id)); err == nil {
			return recovered, fmt.Errorf("%w: orphaned and active package paths both exist for %q", ErrJSRuntimePackageExists, id)
		} else if !errors.Is(err, os.ErrNotExist) {
			return recovered, err
		}
		manifest, digest, err := readJSRuntimeManifest(filepath.Join(s.installRoot, id))
		if err != nil || manifest.ID != id {
			return recovered, fmt.Errorf("%w: cannot recover staged package %q: %w", ErrInvalidJSRuntimePending, id, err)
		}
		state.Changes = append(state.Changes, jsRuntimePendingRecord{
			JSRuntimePendingChange: JSRuntimePendingChange{
				ID: id, Action: jsRuntimeActionInstall, Name: manifest.Name, Version: manifest.Version,
			},
			ManifestSHA256: digest,
		})
		pendingIDs[id] = struct{}{}
		recovered = true
	}
	if recovered {
		sortRuntimePending(state.Changes)
	}
	return recovered, nil
}

func (s *jsRuntimePackageStore) applyPendingInstall(record jsRuntimePendingRecord, requirements jsengine.RuntimeRequirements) error {
	stagedPath := filepath.Join(s.installRoot, record.ID)
	activePath := filepath.Join(s.activeRoot, record.ID)
	activeInfo, activeErr := os.Lstat(activePath)
	stagedInfo, stagedErr := os.Lstat(stagedPath)
	if activeErr == nil {
		if stagedErr == nil {
			return fmt.Errorf("%w: both staged and active paths exist", ErrJSRuntimePackageExists)
		}
		if !errors.Is(stagedErr, os.ErrNotExist) {
			return stagedErr
		}
		if activeInfo.Mode()&os.ModeSymlink != 0 || !activeInfo.IsDir() {
			return fmt.Errorf("%w: active package path is not a directory", ErrInvalidJSRuntimePending)
		}
		_, digest, err := findAndValidateJSRuntimePackage(s.activeRoot, record.ID, requirements)
		if err != nil {
			return err
		}
		if digest != record.ManifestSHA256 {
			return fmt.Errorf("%w: active package does not match pending install", ErrJSRuntimePackageExists)
		}
		return nil
	}
	if !errors.Is(activeErr, os.ErrNotExist) {
		return activeErr
	}
	if stagedErr != nil {
		if errors.Is(stagedErr, os.ErrNotExist) {
			return fmt.Errorf("%w: staged package is missing", ErrInvalidJSRuntimePending)
		}
		return stagedErr
	}
	if stagedInfo.Mode()&os.ModeSymlink != 0 || !stagedInfo.IsDir() {
		return fmt.Errorf("%w: staged package path is not a directory", ErrInvalidJSRuntimePending)
	}
	_, digest, err := findAndValidateJSRuntimePackage(s.installRoot, record.ID, requirements)
	if err != nil {
		return err
	}
	if digest != record.ManifestSHA256 {
		return fmt.Errorf("%w: staged manifest changed", ErrInvalidJSRuntimePending)
	}
	if err := os.Rename(stagedPath, activePath); err != nil {
		return err
	}
	syncRuntimeDirectory(s.installRoot)
	syncRuntimeDirectory(s.activeRoot)
	return nil
}

func (s *jsRuntimePackageStore) applyPendingUninstall(id string) error {
	packageDir := filepath.Join(s.activeRoot, id)
	info, err := os.Lstat(packageDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: active package path is not a directory", ErrInvalidJSRuntimePending)
	}
	manifest, _, err := readJSRuntimeManifest(packageDir)
	if err != nil || manifest.ID != id {
		if err == nil {
			err = ErrInvalidJSRuntimePending
		}
		return fmt.Errorf("%w: cannot verify uninstall target: %w", ErrInvalidJSRuntimePending, err)
	}
	if err := os.RemoveAll(packageDir); err != nil {
		return err
	}
	syncRuntimeDirectory(s.activeRoot)
	return nil
}

func (s *jsRuntimePackageStore) loadPendingLocked() (jsRuntimePendingState, error) {
	state := jsRuntimePendingState{Version: jsRuntimePendingStateVersion, Changes: []jsRuntimePendingRecord{}}
	info, err := os.Lstat(s.pendingFile)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return jsRuntimePendingState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxJSRuntimePendingBytes {
		return jsRuntimePendingState{}, fmt.Errorf("%w: pending file type or size is invalid", ErrInvalidJSRuntimePending)
	}
	file, err := os.Open(s.pendingFile)
	if err != nil {
		return jsRuntimePendingState{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxJSRuntimePendingBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return jsRuntimePendingState{}, fmt.Errorf("%w: %w", ErrInvalidJSRuntimePending, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return jsRuntimePendingState{}, fmt.Errorf("%w: trailing JSON data", ErrInvalidJSRuntimePending)
	}
	if state.Version != jsRuntimePendingStateVersion {
		return jsRuntimePendingState{}, fmt.Errorf("%w: unsupported state version %d", ErrInvalidJSRuntimePending, state.Version)
	}
	seen := make(map[string]struct{}, len(state.Changes))
	for _, record := range state.Changes {
		id, idErr := normalizeManagedRuntimeID(record.ID)
		if idErr != nil || id != record.ID || record.Action != jsRuntimeActionInstall && record.Action != jsRuntimeActionUninstall {
			return jsRuntimePendingState{}, fmt.Errorf("%w: invalid pending change", ErrInvalidJSRuntimePending)
		}
		if _, ok := seen[id]; ok {
			return jsRuntimePendingState{}, fmt.Errorf("%w: duplicate pending change for %q", ErrInvalidJSRuntimePending, id)
		}
		seen[id] = struct{}{}
		if record.Action == jsRuntimeActionInstall {
			digest, err := hex.DecodeString(record.ManifestSHA256)
			if err != nil || len(digest) != sha256.Size {
				return jsRuntimePendingState{}, fmt.Errorf("%w: invalid pending manifest digest", ErrInvalidJSRuntimePending)
			}
		} else if record.ManifestSHA256 != "" {
			return jsRuntimePendingState{}, fmt.Errorf("%w: uninstall has an install digest", ErrInvalidJSRuntimePending)
		}
	}
	sortRuntimePending(state.Changes)
	return state, nil
}

func (s *jsRuntimePackageStore) writePendingLocked(state jsRuntimePendingState) error {
	state.Version = jsRuntimePendingStateVersion
	sortRuntimePending(state.Changes)
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return utils.AtomicWriteFile(s.pendingFile, payload, 0o600)
}

func sortRuntimePending(changes []jsRuntimePendingRecord) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].ID != changes[j].ID {
			return changes[i].ID < changes[j].ID
		}
		return changes[i].Action < changes[j].Action
	})
}

func spoolRuntimeArchive(source io.Reader, directory string, limit int64) (string, int64, error) {
	if limit < 0 || limit == int64(^uint64(0)>>1) {
		return "", 0, fmt.Errorf("%w: invalid compressed size limit", ErrInvalidJSRuntimeArchive)
	}
	file, err := os.CreateTemp(directory, ".runtime-archive-")
	if err != nil {
		return "", 0, err
	}
	filename := file.Name()
	removeFile := true
	defer func() {
		if removeFile {
			_ = os.Remove(filename)
		}
	}()
	written, err := io.Copy(file, io.LimitReader(source, limit+1))
	if err != nil {
		_ = file.Close()
		return "", 0, fmt.Errorf("read runtime archive: %w", err)
	}
	if written > limit {
		_ = file.Close()
		return "", 0, ErrJSRuntimeArchiveTooLarge
	}
	if written == 0 {
		_ = file.Close()
		return "", 0, fmt.Errorf("%w: empty archive", ErrInvalidJSRuntimeArchive)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", 0, err
	}
	if err := file.Close(); err != nil {
		return "", 0, err
	}
	removeFile = false
	return filename, written, nil
}

func extractJSRuntimeArchive(file *os.File, destination string, limits jsRuntimeArchiveLimits) (string, error) {
	var signature [2]byte
	if _, err := file.ReadAt(signature[:], 0); err != nil {
		return "", fmt.Errorf("%w: cannot read archive signature: %w", ErrInvalidJSRuntimeArchive, err)
	}
	switch {
	case signature[0] == 'P' && signature[1] == 'K':
		return extractJSRuntimeZip(file, destination, limits)
	case signature[0] == 0x1f && signature[1] == 0x8b:
		return extractJSRuntimeTarGzip(file, destination, limits)
	default:
		return "", fmt.Errorf("%w: only zip and tar.gz archives are supported", ErrInvalidJSRuntimeArchive)
	}
}

func extractJSRuntimeZip(file *os.File, destination string, limits jsRuntimeArchiveLimits) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return "", fmt.Errorf("%w: invalid zip: %w", ErrInvalidJSRuntimeArchive, err)
	}
	if len(archive.File) == 0 || len(archive.File) > limits.maxEntries {
		return "", fmt.Errorf("%w: invalid entry count", ErrInvalidJSRuntimeArchive)
	}
	var root string
	seenPaths := make(map[string]struct{}, len(archive.File))
	var expanded int64
	for _, entry := range archive.File {
		mode := entry.Mode()
		isDir := mode.IsDir() || strings.HasSuffix(entry.Name, "/")
		if mode&os.ModeSymlink != 0 || !isDir && !mode.IsRegular() {
			return "", fmt.Errorf("%w: unsupported zip entry type", ErrInvalidJSRuntimeArchive)
		}
		name, entryRoot, err := normalizeJSRuntimeArchivePath(entry.Name, isDir, limits.maxPathBytes)
		if err != nil {
			return "", err
		}
		if _, duplicate := seenPaths[name]; duplicate {
			return "", fmt.Errorf("%w: duplicate archive entry path %q", ErrInvalidJSRuntimeArchive, name)
		}
		seenPaths[name] = struct{}{}
		if root == "" {
			root = entryRoot
		} else if root != entryRoot {
			return "", fmt.Errorf("%w: archive must contain exactly one package directory", ErrInvalidJSRuntimeArchive)
		}
		if isDir {
			if entry.UncompressedSize64 != 0 {
				return "", fmt.Errorf("%w: directory entry has data", ErrInvalidJSRuntimeArchive)
			}
			if err := os.MkdirAll(filepath.Join(destination, name), 0o755); err != nil {
				return "", err
			}
			continue
		}
		if entry.UncompressedSize64 > uint64(limits.maxExpandedBytes-expanded) {
			return "", ErrJSRuntimeArchiveTooLarge
		}
		expanded += int64(entry.UncompressedSize64)
		reader, err := entry.Open()
		if err != nil {
			return "", fmt.Errorf("%w: open zip entry: %w", ErrInvalidJSRuntimeArchive, err)
		}
		target := filepath.Join(destination, name)
		if err := writeJSRuntimeArchiveFile(target, reader, int64(entry.UncompressedSize64)); err != nil {
			_ = reader.Close()
			return "", err
		}
		if _, err := io.CopyN(io.Discard, reader, 1); !errors.Is(err, io.EOF) {
			_ = reader.Close()
			if err == nil {
				err = errors.New("zip entry exceeds declared size")
			}
			return "", fmt.Errorf("%w: %w", ErrInvalidJSRuntimeArchive, err)
		}
		if err := reader.Close(); err != nil {
			return "", fmt.Errorf("%w: close zip entry: %w", ErrInvalidJSRuntimeArchive, err)
		}
	}
	if root == "" {
		return "", fmt.Errorf("%w: archive contains no package entries", ErrInvalidJSRuntimeArchive)
	}
	return root, nil
}

func extractJSRuntimeTarGzip(file *os.File, destination string, limits jsRuntimeArchiveLimits) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("%w: invalid gzip: %w", ErrInvalidJSRuntimeArchive, err)
	}
	defer gzipReader.Close()
	limited := &io.LimitedReader{R: gzipReader, N: limits.maxExpandedBytes + 1}
	tarReader := tar.NewReader(limited)
	var root string
	seenPaths := make(map[string]struct{})
	entries := 0
	var fileBytes int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if limited.N == 0 {
				return "", ErrJSRuntimeArchiveTooLarge
			}
			return "", fmt.Errorf("%w: invalid tar: %w", ErrInvalidJSRuntimeArchive, err)
		}
		entries++
		if entries > limits.maxEntries {
			return "", fmt.Errorf("%w: too many archive entries", ErrInvalidJSRuntimeArchive)
		}
		isDir := header.Typeflag == tar.TypeDir
		if !isDir && header.Typeflag != tar.TypeReg {
			return "", fmt.Errorf("%w: unsupported tar entry type %d", ErrInvalidJSRuntimeArchive, header.Typeflag)
		}
		name, entryRoot, err := normalizeJSRuntimeArchivePath(header.Name, isDir, limits.maxPathBytes)
		if err != nil {
			return "", err
		}
		if _, duplicate := seenPaths[name]; duplicate {
			return "", fmt.Errorf("%w: duplicate archive entry path %q", ErrInvalidJSRuntimeArchive, name)
		}
		seenPaths[name] = struct{}{}
		if root == "" {
			root = entryRoot
		} else if root != entryRoot {
			return "", fmt.Errorf("%w: archive must contain exactly one package directory", ErrInvalidJSRuntimeArchive)
		}
		if isDir {
			if header.Size != 0 {
				return "", fmt.Errorf("%w: directory entry has data", ErrInvalidJSRuntimeArchive)
			}
			if err := os.MkdirAll(filepath.Join(destination, name), 0o755); err != nil {
				return "", err
			}
			continue
		}
		if header.Size < 0 || header.Size > limits.maxExpandedBytes-fileBytes {
			return "", ErrJSRuntimeArchiveTooLarge
		}
		fileBytes += header.Size
		if err := writeJSRuntimeArchiveFile(filepath.Join(destination, name), tarReader, header.Size); err != nil {
			if limited.N == 0 {
				return "", ErrJSRuntimeArchiveTooLarge
			}
			return "", err
		}
	}
	if root == "" {
		return "", fmt.Errorf("%w: archive contains no package entries", ErrInvalidJSRuntimeArchive)
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return "", fmt.Errorf("%w: invalid gzip stream: %w", ErrInvalidJSRuntimeArchive, err)
	}
	if limited.N == 0 {
		return "", ErrJSRuntimeArchiveTooLarge
	}
	return root, nil
}

func normalizeJSRuntimeArchivePath(raw string, isDir bool, maxBytes int) (string, string, error) {
	if raw == "" || len(raw) > maxBytes || strings.ContainsAny(raw, "\\:\x00") || strings.HasPrefix(raw, "/") {
		return "", "", fmt.Errorf("%w: unsafe archive path", ErrInvalidJSRuntimeArchive)
	}
	name := raw
	if isDir {
		name = strings.TrimSuffix(name, "/")
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", "", fmt.Errorf("%w: unsafe archive path %q", ErrInvalidJSRuntimeArchive, raw)
	}
	parts := strings.Split(clean, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", "", fmt.Errorf("%w: unsafe archive path %q", ErrInvalidJSRuntimeArchive, raw)
		}
	}
	return filepath.Join(parts...), parts[0], nil
}

func writeJSRuntimeArchiveFile(filename string, source io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("%w: duplicate or inaccessible archive path: %w", ErrInvalidJSRuntimeArchive, err)
	}
	_, copyErr := io.CopyN(file, source, size)
	if copyErr == nil {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("%w: extract archive file: %w", ErrInvalidJSRuntimeArchive, copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func validateJSRuntimePackage(extractRoot, packageRoot string, requirements jsengine.RuntimeRequirements) (native.Candidate, string, error) {
	id, err := normalizeManagedRuntimeID(packageRoot)
	if err != nil {
		return native.Candidate{}, "", err
	}
	manifest, digest, err := readJSRuntimeManifest(filepath.Join(extractRoot, id))
	if err != nil {
		return native.Candidate{}, "", fmt.Errorf("%w: %w", ErrInvalidJSRuntimeArchive, err)
	}
	if manifest.ID != id {
		return native.Candidate{}, "", fmt.Errorf("%w: manifest ID does not match package directory", ErrInvalidJSRuntimeArchive)
	}
	if err := manifest.ValidateABI(); err != nil {
		return native.Candidate{}, "", fmt.Errorf("%w: runtime manifest ABI: %w", ErrInvalidJSRuntimeArchive, err)
	}
	candidates, err := native.Discover(extractRoot)
	if err != nil {
		return native.Candidate{}, "", fmt.Errorf("%w: runtime manifest discovery: %w", ErrInvalidJSRuntimeArchive, err)
	}
	if len(candidates) != 1 || candidates[0].Manifest.ID != id {
		return native.Candidate{}, "", fmt.Errorf("%w: archive must contain one runtime whose ID matches its directory", ErrInvalidJSRuntimeArchive)
	}
	candidate := candidates[0]
	library, err := os.Lstat(candidate.LibraryPath)
	if err != nil || library.Mode()&os.ModeSymlink != 0 || !library.Mode().IsRegular() || library.Size() == 0 {
		return native.Candidate{}, "", fmt.Errorf("%w: native library is missing or not a regular file", ErrInvalidJSRuntimeArchive)
	}
	descriptor := jsengine.Descriptor{
		ID: jsengine.EngineID(manifest.ID), Name: manifest.Name, Version: manifest.Version,
		Language: manifest.Language, Author: manifest.Author, ABIMajor: manifest.RuntimeABI.Major,
		HostABIMajor: manifest.HostABI.Major, Capabilities: jsengine.CapabilitySet(manifest.Capabilities),
		Services: manifest.Services, Extensions: manifest.Extensions, Path: candidate.LibraryPath,
	}
	if err := requirements.ValidateDescriptor(descriptor); err != nil {
		return native.Candidate{}, "", fmt.Errorf("%w: provider cannot be admitted by Dice: %w", ErrInvalidJSRuntimeArchive, err)
	}
	return candidate, digest, nil
}

func findAndValidateJSRuntimePackage(root, id string, requirements jsengine.RuntimeRequirements) (native.Candidate, string, error) {
	if err := validateJSRuntimeManifestSizes(root); err != nil {
		return native.Candidate{}, "", err
	}
	candidates, err := native.Discover(root)
	if err != nil {
		return native.Candidate{}, "", err
	}
	for _, candidate := range candidates {
		if jsengine.NormalizeEngineID(candidate.Manifest.ID) != jsengine.EngineID(id) {
			continue
		}
		manifest, digest, err := readJSRuntimeManifest(filepath.Dir(candidate.Manifest.ManifestPath))
		if err != nil {
			return native.Candidate{}, "", err
		}
		if err := manifest.ValidateABI(); err != nil {
			return native.Candidate{}, "", fmt.Errorf("%w: runtime manifest ABI: %w", ErrInvalidJSRuntimePending, err)
		}
		library, err := os.Lstat(candidate.LibraryPath)
		if err != nil || library.Mode()&os.ModeSymlink != 0 || !library.Mode().IsRegular() || library.Size() == 0 {
			return native.Candidate{}, "", fmt.Errorf("%w: runtime library is missing or invalid", ErrInvalidJSRuntimePending)
		}
		descriptor := jsengine.Descriptor{
			ID: jsengine.EngineID(manifest.ID), Name: manifest.Name, Version: manifest.Version,
			Language: manifest.Language, Author: manifest.Author, ABIMajor: manifest.RuntimeABI.Major,
			HostABIMajor: manifest.HostABI.Major, Capabilities: jsengine.CapabilitySet(manifest.Capabilities),
			Services: manifest.Services, Extensions: manifest.Extensions, Path: candidate.LibraryPath,
		}
		if err := requirements.ValidateDescriptor(descriptor); err != nil {
			return native.Candidate{}, "", err
		}
		return candidate, digest, nil
	}
	return native.Candidate{}, "", fmt.Errorf("%w: runtime package %q was not found", ErrInvalidJSRuntimePending, id)
}

func validateJSRuntimeManifestSizes(root string) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(root, entry.Name(), "runtime.json")
		info, err := os.Lstat(manifestPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxJSRuntimeManifestBytes {
			return fmt.Errorf("%w: runtime manifest file type or size is invalid", ErrInvalidJSRuntimePending)
		}
	}
	return nil
}

func readJSRuntimeManifest(packageDir string) (native.Manifest, string, error) {
	packageInfo, err := os.Lstat(packageDir)
	if err != nil {
		return native.Manifest{}, "", err
	}
	if packageInfo.Mode()&os.ModeSymlink != 0 || !packageInfo.IsDir() {
		return native.Manifest{}, "", errors.New("runtime package path is not a real directory")
	}
	manifestPath := filepath.Join(packageDir, "runtime.json")
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return native.Manifest{}, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxJSRuntimeManifestBytes {
		return native.Manifest{}, "", errors.New("runtime manifest file type or size is invalid")
	}
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		return native.Manifest{}, "", err
	}
	var manifest native.Manifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return native.Manifest{}, "", err
	}
	if manifest.Schema != 1 || manifest.Name == "" || manifest.Version == "" || manifest.Language == "" ||
		manifest.RuntimeABI.Major == 0 || manifest.HostABI.Major == 0 {
		return native.Manifest{}, "", errors.New("runtime manifest is missing required fields")
	}
	id, err := normalizeManagedRuntimeID(manifest.ID)
	if err != nil || id != manifest.ID {
		return native.Manifest{}, "", errors.New("runtime manifest ID is invalid")
	}
	digest := sha256.Sum256(contents)
	return manifest, hex.EncodeToString(digest[:]), nil
}
func (d *Dice) StageJSRuntimeArchive(source io.Reader) (JSRuntimePendingChange, error) {
	if d == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	manager := d.jsRuntimeManagerInstance()
	if manager == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	manager.mu.RLock()
	store := manager.packageStore
	descriptors := manager.registry.Descriptors()
	requirements := manager.requirements
	manager.mu.RUnlock()
	if store == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	return store.StageInstall(source, descriptors, requirements)
}

func (d *Dice) StageJSRuntimeUninstall(id string) (JSRuntimePendingChange, error) {
	if d == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	manager := d.jsRuntimeManagerInstance()
	runtimeID := jsengine.NormalizeEngineID(id)
	status, ok := manager.Status(runtimeID)
	if !ok || !status.Managed || status.Builtin {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: %s", ErrJSRuntimeNotManaged, id)
	}
	manager.mu.RLock()
	store := manager.packageStore
	manager.mu.RUnlock()
	if store == nil {
		return JSRuntimePendingChange{}, ErrJSRuntimeStoreUnavailable
	}
	d.configUpdateMu.Lock()
	defer d.configUpdateMu.Unlock()
	if d.configuredJSEngine() == runtimeID {
		return JSRuntimePendingChange{}, fmt.Errorf("%w: runtime %q is the global default", ErrJSRuntimeInUse, runtimeID)
	}
	for extensionID, route := range d.Config.JsRuntimeRoutes {
		if jsengine.NormalizeEngineID(route) == runtimeID {
			return JSRuntimePendingChange{}, fmt.Errorf("%w: runtime %q is routed from package %q", ErrJSRuntimeInUse, runtimeID, extensionID)
		}
	}
	return store.StageUninstall(string(runtimeID))
}

func (d *Dice) JSRuntimePendingChanges() ([]JSRuntimePendingChange, error) {
	if d == nil {
		return []JSRuntimePendingChange{}, nil
	}
	manager := d.jsRuntimeManagerInstance()
	manager.mu.RLock()
	store := manager.packageStore
	manager.mu.RUnlock()
	if store == nil {
		return []JSRuntimePendingChange{}, nil
	}
	return store.PendingChanges()
}

func syncRuntimeDirectory(directory string) {
	file, err := os.Open(directory)
	if err != nil {
		return
	}
	defer file.Close()
	_ = file.Sync()
}
