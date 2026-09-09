package eventsourcing

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
)

const (
	manifestDomain = "event-sourcing-manifest/v1"
	MaxManifestRecords = 1_000_000
	MaxManifestBytes = 64 * 1024 * 1024
)

type ManifestRecord struct {
	Domain string
	Identity string
	IdentityDigest string
	Kind string
	SchemaVersion uint16
	ContentDigest []byte
	Size uint64
}

type SemanticManifest struct {
	Version uint16
	SourceIdentity string
	Records []ManifestRecord
}

func (m SemanticManifest) SortedRecords() []ManifestRecord {
	out := append([]ManifestRecord(nil), m.Records...)
	sort.SliceStable(out, func(i, j int) bool { return manifestRecordLess(out[i], out[j]) })
	return out
}

func manifestRecordLess(a, b ManifestRecord) bool {
	if a.Domain != b.Domain { return a.Domain < b.Domain }
	ai, bi := canonicalIdentity(a), canonicalIdentity(b)
	if ai != bi { return ai < bi }
	if a.Kind != b.Kind { return a.Kind < b.Kind }
	if a.SchemaVersion != b.SchemaVersion { return a.SchemaVersion < b.SchemaVersion }
	if bytes.Compare(a.ContentDigest, b.ContentDigest) != 0 { return bytes.Compare(a.ContentDigest, b.ContentDigest) < 0 }
	return a.Size < b.Size
}

// CanonicalManifest returns a deterministic, domain-tagged binary manifest
// and its SHA-256 digest. Identities are keyed by digest; raw values never
// appear in the returned bytes.
func CanonicalManifest(manifest SemanticManifest) ([]byte, []byte, error) {
	if manifest.Version == 0 { manifest.Version = 1 }
	if manifest.Version != 1 { return nil, nil, ErrValidation }
	if len(manifest.Records) > MaxManifestRecords { return nil, nil, ErrBatchLimit }
	records := manifest.SortedRecords()
	var out bytes.Buffer
	if err := appendField(&out, 'D', []byte(manifestDomain)); err != nil { return nil, nil, err }
	if err := appendField(&out, 'V', uint16Bytes(manifest.Version)); err != nil { return nil, nil, err }
	sourceDigest := sha256.Sum256([]byte(manifest.SourceIdentity))
	if err := appendField(&out, 'S', sourceDigest[:]); err != nil { return nil, nil, err }
	if len(records) > int(^uint32(0)) { return nil, nil, ErrBatchLimit }
	if err := appendField(&out, 'N', uint32Bytes(uint32(len(records)))); err != nil { return nil, nil, err }
	for _, record := range records {
		if err := appendManifestRecord(&out, record); err != nil { return nil, nil, err }
		if out.Len() > MaxManifestBytes { return nil, nil, ErrBatchLimit }
	}
	digest := sha256.Sum256(out.Bytes())
	return out.Bytes(), digest[:], nil
}

func appendManifestRecord(out *bytes.Buffer, record ManifestRecord) error {
	if strings.TrimSpace(record.Domain) == "" || strings.TrimSpace(record.Kind) == "" { return ErrValidation }
	if len(record.ContentDigest) != 0 && len(record.ContentDigest) != sha256.Size { return ErrValidation }
	identityDigest, err := identityDigestBytes(record)
	if err != nil { return err }
	for _, field := range []struct{ tag byte; value []byte }{
		{'d', []byte(record.Domain)}, {'i', identityDigest}, {'k', []byte(record.Kind)},
		{'v', uint16Bytes(record.SchemaVersion)}, {'c', append([]byte(nil), record.ContentDigest...)},
		{'z', uint64Bytes(record.Size)},
	} {
		if err := appendField(out, field.tag, field.value); err != nil { return err }
	}
	return nil
}

func identityDigestBytes(record ManifestRecord) ([]byte, error) {
	if record.IdentityDigest != "" {
		raw, err := hex.DecodeString(record.IdentityDigest)
		if err != nil || len(raw) != sha256.Size { return nil, ErrValidation }
		return raw, nil
	}
	if record.Identity == "" { return nil, ErrValidation }
	digest := sha256.Sum256([]byte(record.Identity))
	return digest[:], nil
}
func canonicalIdentity(record ManifestRecord) string {
	if record.IdentityDigest != "" { return record.IdentityDigest }
	digest := sha256.Sum256([]byte(record.Identity))
	return hex.EncodeToString(digest[:])
}

func appendField(out *bytes.Buffer, tag byte, value []byte) error {
	if len(value) > int(^uint32(0)) { return ErrBatchLimit }
	out.WriteByte(tag)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out.Write(length[:])
	out.Write(value)
	return nil
}
func uint16Bytes(value uint16) []byte { var out [2]byte; binary.BigEndian.PutUint16(out[:], value); return out[:] }
func uint32Bytes(value uint32) []byte { var out [4]byte; binary.BigEndian.PutUint32(out[:], value); return out[:] }
func uint64Bytes(value uint64) []byte { var out [8]byte; binary.BigEndian.PutUint64(out[:], value); return out[:] }

// DeterministicBatches partitions records without changing their semantic
// order. Every batch has at most 500 records and 8 MiB of encoded records.
func DeterministicBatches(records []ManifestRecord) ([][]ManifestRecord, error) {
	sorted := append([]ManifestRecord(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool { return manifestRecordLess(sorted[i], sorted[j]) })
	batches := make([][]ManifestRecord, 0, (len(sorted)+MaxBatchRecords-1)/MaxBatchRecords)
	current := make([]ManifestRecord, 0, MaxBatchRecords)
	currentBytes := 0
	for _, record := range sorted {
		var encoded bytes.Buffer
		if err := appendManifestRecord(&encoded, record); err != nil { return nil, err }
		size := encoded.Len()
		if size > MaxBatchBytes { return nil, ErrBatchLimit }
		if len(current) > 0 && (len(current) >= MaxBatchRecords || currentBytes > MaxBatchBytes-size) {
			batches = append(batches, current)
			current = make([]ManifestRecord, 0, MaxBatchRecords)
			currentBytes = 0
		}
		current = append(current, record)
		currentBytes += size
	}
	if len(current) != 0 { batches = append(batches, current) }
	return batches, nil
}
