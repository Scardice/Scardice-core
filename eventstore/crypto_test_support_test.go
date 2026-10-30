package eventstore

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

type MemoryKeySource struct {
	IndexID       string
	IndexMaterial []byte
	Roots         map[string][]byte
	CurrentID     string
}

func NewMemoryKeySource(indexID string, indexMaterial []byte, roots map[string][]byte, currentID string) *MemoryKeySource {
	copyRoots := make(map[string][]byte, len(roots))
	for id, material := range roots {
		copyRoots[id] = append([]byte(nil), material...)
	}
	return &MemoryKeySource{IndexID: indexID, IndexMaterial: append([]byte(nil), indexMaterial...), Roots: copyRoots, CurrentID: currentID}
}
func (m *MemoryKeySource) IndexRootID(context.Context) (string, error) {
	if m == nil || m.IndexID == "" {
		return "", ErrKeySourceUnavailable
	}
	return m.IndexID, nil
}
func (m *MemoryKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	if m == nil || len(m.IndexMaterial) != 32 {
		return nil, ErrKeySourceUnavailable
	}
	return append([]byte(nil), m.IndexMaterial...), nil
}
func (m *MemoryKeySource) CurrentEncryptionRoot(ctx context.Context) (EncryptionRoot, error) {
	if m == nil || m.CurrentID == "" {
		return EncryptionRoot{}, ErrKeySourceUnavailable
	}
	material, err := m.EncryptionRoot(ctx, m.CurrentID)
	return EncryptionRoot{ID: m.CurrentID, Material: material}, err
}
func (m *MemoryKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if m == nil {
		return nil, ErrKeySourceUnavailable
	}
	material, ok := m.Roots[id]
	if !ok || len(material) != 32 {
		return nil, ErrKeyUnavailable
	}
	return append([]byte(nil), material...), nil
}
func (m *MemoryKeySource) EncryptionRoots(ctx context.Context) ([]EncryptionRoot, error) {
	if m == nil {
		return nil, ErrKeySourceUnavailable
	}
	ids := make([]string, 0, len(m.Roots))
	for id := range m.Roots {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]EncryptionRoot, 0, len(ids))
	for _, id := range ids {
		material, err := m.EncryptionRoot(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, EncryptionRoot{ID: id, Material: material})
	}
	return out, nil
}

type gatedRootKeySource struct {
	*MemoryKeySource
	mu      sync.Mutex
	calls   int
	blocked chan struct{}
	release chan struct{}
}

func (s *gatedRootKeySource) EncryptionRoot(ctx context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	if call == 1 {
		close(s.blocked)
		<-s.release
	}
	return s.MemoryKeySource.EncryptionRoot(ctx, id)
}

func newTestKeySource() *MemoryKeySource {
	return NewMemoryKeySource("index-v1", []byte("01234567890123456789012345678901"), map[string][]byte{
		"root-v1": []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}, "root-v1")
}

func openEncryptedTestStore(t *testing.T) (*GORMStore, *Database, *MemoryKeySource) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task6.db")})
	if err != nil {
		t.Fatal(err)
	}
	source := newTestKeySource()
	store := NewStore(db, WithKeySource(source))
	if err := store.SetReadiness(context.Background(), Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return store, db, source
}
func itemKeyHMAC(t *testing.T, source KeySource, extension, key string) []byte {
	t.Helper()
	index, err := a6HMAC(context.Background(), source, "plugin-key-index/v1", extension, key)
	if err != nil {
		t.Fatal(err)
	}
	return index
}
