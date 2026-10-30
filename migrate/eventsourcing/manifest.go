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
	manifestDomain     = "event-sourcing-manifest/v1"
	MaxManifestRecords = 2_000_000
	MaxManifestBytes   = 64 * 1024 * 1024
)

type ManifestRecord struct {
	RecordType     RecordType
	Domain         string
	Identity       string
	IdentityDigest string
	Kind           string
	SchemaVersion  uint16
	ContentDigest  []byte
	Size           uint64
	Sensitive      bool
	Version        uint64
}

type SemanticManifest struct {
	Version        uint16
	SourceIdentity string
	Records        []ManifestRecord
}

func (m SemanticManifest) SortedRecords() []ManifestRecord {
	out := append([]ManifestRecord(nil), m.Records...)
	for index := range out {
		if out[index].IdentityDigest == "" && out[index].Identity != "" {
			digest := sha256.Sum256([]byte(out[index].Identity))
			out[index].IdentityDigest = hex.EncodeToString(digest[:])
		}
	}
	sort.Slice(out, func(i, j int) bool { return manifestRecordLess(out[i], out[j]) })
	return out
}

func manifestRecordLess(a, b ManifestRecord) bool {
	if canonicalRecordType(a) != canonicalRecordType(b) {
		return canonicalRecordType(a) < canonicalRecordType(b)
	}
	if a.Domain != b.Domain {
		return a.Domain < b.Domain
	}
	if canonicalRecordType(a) == RecordTypeLogArchive && canonicalRecordType(b) == RecordTypeLogArchive {
		leftRank, leftOK := legacyStoryLogImportKindRank(a.Kind)
		rightRank, rightOK := legacyStoryLogImportKindRank(b.Kind)
		if leftOK != rightOK {
			return leftOK
		}
		if leftOK && leftRank != rightRank {
			return leftRank < rightRank
		}
	}
	ai, bi := canonicalIdentity(a), canonicalIdentity(b)
	if ai != bi {
		return ai < bi
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.SchemaVersion != b.SchemaVersion {
		return a.SchemaVersion < b.SchemaVersion
	}
	if !bytes.Equal(canonicalContentDigest(a), canonicalContentDigest(b)) {
		return bytes.Compare(canonicalContentDigest(a), canonicalContentDigest(b)) < 0
	}
	return canonicalManifestSize(a) < canonicalManifestSize(b)
}

// CanonicalManifest returns a deterministic, domain-tagged binary manifest
// and its SHA-256 digest. Identities are keyed by digest; raw values never
// appear in the returned bytes.
func CanonicalManifest(manifest SemanticManifest) ([]byte, []byte, error) {
	return canonicalManifest(manifest, MaxManifestBytes, false)
}

// canonicalImportManifest retains the canonical bytes only while they fit the
// readiness-record bound. Large imports publish the same canonical digest
// without persisting a multi-hundred-megabyte manifest blob.
func canonicalImportManifest(manifest SemanticManifest, maxEncodedBytes int) ([]byte, []byte, error) {
	return canonicalManifest(manifest, maxEncodedBytes, true)
}

func canonicalManifest(manifest SemanticManifest, maxEncodedBytes int, omitEncodedOnOverflow bool) ([]byte, []byte, error) {
	if manifest.Version == 0 {
		manifest.Version = 1
	}
	if manifest.Version != 1 {
		return nil, nil, ErrValidation
	}
	if len(manifest.Records) > MaxManifestRecords || maxEncodedBytes < 0 {
		return nil, nil, ErrBatchLimit
	}
	records := manifest.SortedRecords()
	digestWriter := sha256.New()
	var out bytes.Buffer
	retaining := true
	writeChunk := func(chunk []byte) error {
		_, _ = digestWriter.Write(chunk)
		if !retaining {
			return nil
		}
		if len(chunk) > maxEncodedBytes || out.Len() > maxEncodedBytes-len(chunk) {
			if !omitEncodedOnOverflow {
				return ErrBatchLimit
			}
			retaining = false
			out = bytes.Buffer{}
			return nil
		}
		_, _ = out.Write(chunk)
		return nil
	}
	var encoded bytes.Buffer
	writeField := func(tag byte, value []byte) error {
		encoded.Reset()
		if err := appendField(&encoded, tag, value); err != nil {
			return err
		}
		return writeChunk(encoded.Bytes())
	}
	if err := writeField('D', []byte(manifestDomain)); err != nil {
		return nil, nil, err
	}
	if err := writeField('V', uint16Bytes(manifest.Version)); err != nil {
		return nil, nil, err
	}
	sourceDigest := sha256.Sum256([]byte(manifest.SourceIdentity))
	if err := writeField('S', sourceDigest[:]); err != nil {
		return nil, nil, err
	}
	if len(records) > int(^uint32(0)) {
		return nil, nil, ErrBatchLimit
	}
	if err := writeField('N', uint32Bytes(uint32(len(records)))); err != nil {
		return nil, nil, err
	}
	for _, record := range records {
		encoded.Reset()
		if err := appendManifestRecord(&encoded, record); err != nil {
			return nil, nil, err
		}
		if err := writeChunk(encoded.Bytes()); err != nil {
			return nil, nil, err
		}
	}
	if !retaining {
		return nil, digestWriter.Sum(nil), nil
	}
	return out.Bytes(), digestWriter.Sum(nil), nil
}

func appendManifestRecord(out *bytes.Buffer, record ManifestRecord) error {
	if strings.TrimSpace(record.Domain) == "" || strings.TrimSpace(record.Kind) == "" {
		return ErrValidation
	}
	if !record.Sensitive && len(record.ContentDigest) != 0 && len(record.ContentDigest) != sha256.Size {
		return ErrValidation
	}
	if record.Sensitive && len(record.ContentDigest) != 0 {
		return ErrValidation
	}
	identityDigest, err := identityDigestBytes(record)
	if err != nil {
		return err
	}
	for _, field := range []struct {
		tag   byte
		value []byte
	}{
		{'t', []byte(canonicalRecordType(record))}, {'d', []byte(record.Domain)}, {'i', identityDigest},
		{'q', uint64Bytes(record.Version)}, {'k', []byte(record.Kind)}, {'v', uint16Bytes(record.SchemaVersion)},
		{'x', []byte{boolByte(record.Sensitive)}}, {'c', canonicalContentDigest(record)}, {'z', uint64Bytes(canonicalManifestSize(record))},
	} {
		if err := appendField(out, field.tag, field.value); err != nil {
			return err
		}
	}
	return nil
}

func canonicalRecordType(record ManifestRecord) RecordType {
	if record.RecordType == "" {
		return RecordTypeEvent
	}
	return record.RecordType
}

func canonicalContentDigest(record ManifestRecord) []byte {
	if record.Sensitive {
		return nil
	}
	return record.ContentDigest
}

func canonicalManifestSize(record ManifestRecord) uint64 {
	if record.Sensitive {
		return 0
	}
	return record.Size
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}
func identityDigestBytes(record ManifestRecord) ([]byte, error) {
	if record.IdentityDigest != "" {
		raw, err := hex.DecodeString(record.IdentityDigest)
		if err != nil || len(raw) != sha256.Size {
			return nil, ErrValidation
		}
		return raw, nil
	}
	if record.Identity == "" && canonicalRecordType(record) != RecordTypePluginKV {
		return nil, ErrValidation
	}
	digest := sha256.Sum256([]byte(record.Identity))
	return digest[:], nil
}
func canonicalIdentity(record ManifestRecord) string {
	if record.IdentityDigest != "" {
		return record.IdentityDigest
	}
	digest := sha256.Sum256([]byte(record.Identity))
	return hex.EncodeToString(digest[:])
}

func appendField(out *bytes.Buffer, tag byte, value []byte) error {
	if len(value) > int(^uint32(0)) {
		return ErrBatchLimit
	}
	out.WriteByte(tag)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out.Write(length[:])
	out.Write(value)
	return nil
}
func uint16Bytes(value uint16) []byte {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], value)
	return out[:]
}
func uint32Bytes(value uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return out[:]
}
func uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}

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
		if err := appendManifestRecord(&encoded, record); err != nil {
			return nil, err
		}
		if record.Size > MaxBatchBytes || uint64(encoded.Len()) > uint64(MaxBatchBytes)-record.Size {
			return nil, ErrBatchLimit
		}
		size := encoded.Len() + int(record.Size)
		if len(current) > 0 && (len(current) >= MaxBatchRecords || currentBytes > MaxBatchBytes-size) {
			batches = append(batches, current)
			current = make([]ManifestRecord, 0, MaxBatchRecords)
			currentBytes = 0
		}
		current = append(current, record)
		currentBytes += size
	}
	if len(current) != 0 {
		batches = append(batches, current)
	}
	return batches, nil
}
