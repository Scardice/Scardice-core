package eventstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/hkdf"
	"gorm.io/gorm"
)

const (
	MaxSecretBytes = 8 * 1024 * 1024
	MaxPluginKeyBytes = 1024
	MaxPluginValueBytes = 8 * 1024 * 1024
	MaxPluginKeys = 10000
	MaxPluginBytes = 64 * 1024 * 1024
	MaxPluginScan = 10000
	MaxPluginResults = 1000
	MaxPluginResponseBytes = 8 * 1024 * 1024
)

var a6Domains = []string{
	"adapter-secret/v1", "plugin-kv-key/v1", "plugin-kv-value/v1", "inbox/v1", "outbox/v1",
	"operation-private/v1", "artifact/v1", "lane-index/v1", "plugin-key-index/v1", "subject-index/v1",
	"target-index/v1", "content-digest/v1",
}

type UnixFileKeySource struct { IndexPath string; RootsDir string; CurrentID string }
func NewUnixFileKeySource(indexPath, rootsDir string) *UnixFileKeySource {
	return &UnixFileKeySource{IndexPath: indexPath, RootsDir: rootsDir}
}
func (f *UnixFileKeySource) IndexRootID(context.Context) (string, error) {
	if f == nil || filepath.Base(f.IndexPath) == "." || filepath.Base(f.IndexPath) == string(filepath.Separator) {
		return "", ErrKeySourceUnavailable
	}
	return filepath.Base(f.IndexPath), nil
}
func (f *UnixFileKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return readKeyFile(f.IndexPath)
}
func (f *UnixFileKeySource) CurrentEncryptionRoot(ctx context.Context) (EncryptionRoot, error) {
	if f == nil {
		return EncryptionRoot{}, ErrKeySourceUnavailable
	}
	id := strings.TrimSpace(f.CurrentID)
	if id == "" {
		raw, err := readSecureFile(filepath.Join(f.RootsDir, "current"), 256)
		if err != nil {
			return EncryptionRoot{}, ErrKeyUnavailable
		}
		id = strings.TrimSpace(string(raw))
	}
	if id == "" || strings.ContainsAny(id, `/\`) {
		return EncryptionRoot{}, ErrKeyUnavailable
	}
	material, err := f.EncryptionRoot(ctx, id)
	if err != nil {
		return EncryptionRoot{}, err
	}
	return EncryptionRoot{ID: id, Material: material}, nil
}
func (f *UnixFileKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if f == nil || strings.ContainsAny(id, `/\`) || id == "" {
		return nil, ErrKeyUnavailable
	}
	return readKeyFile(filepath.Join(f.RootsDir, id+".key"))
}
func (f *UnixFileKeySource) EncryptionRoots(ctx context.Context) ([]EncryptionRoot, error) {
	if runtime.GOOS == "windows" {
		return nil, ErrKeySourceUnavailable
	}
	entries, err := os.ReadDir(f.RootsDir)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	out := make([]EncryptionRoot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".key")
		material, err := f.EncryptionRoot(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, EncryptionRoot{ID: id, Material: material})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func CreateUnixKeyFile(path string, material []byte) error {
	if runtime.GOOS == "windows" || len(material) != 32 {
		return ErrKeyUnavailable
	}
	if err := ensureSecurePath(filepath.Dir(path)); err != nil {
		return err
	}
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrKeyUnavailable
	}
	defer fd.Close()
	if _, err = fd.Write(material); err != nil {
		return ErrKeyUnavailable
	}
	return nil
}
func ensureSecurePath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ErrKeyUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return ErrKeyUnavailable
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrKeyUnavailable
		}
	}
	return nil
}

func readSecureFile(path string, maxBytes int) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, ErrKeySourceUnavailable
	}
	if err := ensureSecurePath(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrKeyUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrKeyUnavailable
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return nil, ErrKeyUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(raw) > maxBytes {
		return nil, ErrKeyUnavailable
	}
	return raw, nil
}
func readKeyFile(path string) ([]byte, error) {
	raw, err := readSecureFile(path, 32)
	if err != nil || len(raw) != 32 {
		return nil, ErrKeyUnavailable
	}
	return raw, nil
}

func keySourceIndex(ctx context.Context, source KeySource)(string,[]byte,error){if source==nil{return "",nil,ErrKeySourceUnavailable};ids,ok:=source.(interface{IndexRootID(context.Context)(string,error)});if !ok{return "",nil,ErrKeySourceUnavailable};id,e:=ids.IndexRootID(ctx);if e!=nil||id==""{return "",nil,ErrKeySourceUnavailable};materials,ok:=source.(interface{IndexRootMaterial(context.Context)([]byte,error)});if !ok{return "",nil,ErrKeySourceUnavailable};material,e:=materials.IndexRootMaterial(ctx);if e!=nil||len(material)!=32{return "",nil,ErrKeySourceUnavailable};return id,material,nil}
func keySourceCurrent(ctx context.Context, source KeySource)(EncryptionRoot,error){if source==nil{return EncryptionRoot{},ErrKeySourceUnavailable};v,ok:=source.(interface{CurrentEncryptionRoot(context.Context)(EncryptionRoot,error)});if !ok{return EncryptionRoot{},ErrKeySourceUnavailable};root,e:=v.CurrentEncryptionRoot(ctx);if e!=nil||root.ID==""||len(root.Material)!=32{return EncryptionRoot{},ErrKeyUnavailable};return root,nil}
func keySourceRoot(ctx context.Context, source KeySource,id string)([]byte,error){if source==nil{return nil,ErrKeySourceUnavailable};v,ok:=source.(interface{EncryptionRoot(context.Context,string)([]byte,error)});if !ok{return nil,ErrKeySourceUnavailable};material,e:=v.EncryptionRoot(ctx,id);if e!=nil||len(material)!=32{return nil,ErrKeyUnavailable};return material,nil}
func deriveA6(root []byte,label string)([]byte,error){if len(root)!=32{return nil,ErrKeyUnavailable};out:=make([]byte,32);r:=hkdf.New(sha256.New,root,nil,[]byte(label));if _,e:=io.ReadFull(r,out);e!=nil{return nil,ErrKeyUnavailable};return out,nil}
func lengthField(dst []byte,v []byte)[]byte{var n [4]byte;binary.BigEndian.PutUint32(n[:],uint32(len(v)));dst=append(dst,n[:]...);return append(dst,v...)}
func a6AAD(domain,identity,owner string,version uint64,keyID string)[]byte{aad:=make([]byte,0,128);aad=lengthField(aad,[]byte(domain));aad=lengthField(aad,[]byte(identity));aad=lengthField(aad,[]byte(owner));var b [8]byte;binary.BigEndian.PutUint64(b[:],version);aad=append(aad,b[:]...);return lengthField(aad,[]byte(keyID))}
func a6SealWithRoot(root EncryptionRoot, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	sub, err := deriveA6(root.Material, domain)
	if err != nil {
		return nil, nil, "", err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, nil, "", ErrEncryptionUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, "", ErrEncryptionUnavailable
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, "", ErrEncryptionUnavailable
	}
	return gcm.Seal(nil, nonce, plaintext, a6AAD(domain, identity, owner, version, root.ID)), nonce, root.ID, nil
}

func a6Seal(ctx context.Context, source KeySource, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	root, err := keySourceCurrent(ctx, source)
	if err != nil {
		return nil, nil, "", err
	}
	return a6SealWithRoot(root, domain, identity, owner, version, plaintext)
}

func a6Open(ctx context.Context, source KeySource, domain, identity, owner string, version uint64, keyID string, ciphertext, nonce []byte) ([]byte, error) {
	root, err := keySourceRoot(ctx, source, keyID)
	if err != nil {
		return nil, err
	}
	sub, err := deriveA6(root, domain)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, ErrAuthenticationFailed
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, a6AAD(domain, identity, owner, version, keyID))
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plain, nil
}

func a6HMAC(ctx context.Context, source KeySource, domain string, parts ...string) ([]byte, error) {
	_, index, err := keySourceIndex(ctx, source)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, index)
	h.Write([]byte(domain))
	for _, part := range parts {
		h.Write([]byte(part))
	}
	return h.Sum(nil), nil
}

type a6PayloadCodec struct{ source KeySource }
func (c *a6PayloadCodec) Encrypt(ctx context.Context, plaintext []byte)([]byte,[]byte,string,error){return a6Seal(ctx,c.source,"artifact/v1","payload","",0,plaintext)}
func (c *a6PayloadCodec) Decrypt(ctx context.Context,ciphertext,nonce []byte,keyID string)([]byte,error){return a6Open(ctx,c.source,"artifact/v1","payload","",0,keyID,ciphertext,nonce)}
func (c *a6PayloadCodec) EncryptBound(ctx context.Context, domain, identity, owner string, version uint64, plaintext []byte)([]byte,[]byte,string,error){return a6Seal(ctx,c.source,domain,identity,owner,version,plaintext)}
func (c *a6PayloadCodec) DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string)([]byte,error){return a6Open(ctx,c.source,domain,identity,owner,version,keyID,ciphertext,nonce)}

func (s *GORMStore) GetReadiness(ctx context.Context)(Readiness,error){var row storeReadinessRow;if s==nil||s.db==nil{return Readiness{},ErrReadinessInvalid};if err:=s.db.GORM().WithContext(ctx).Where("singleton_id = ?","default").First(&row).Error;err!=nil{return Readiness{},ErrReadinessQuarantined};var roots []string;if len(row.EncryptionRootIDs)>0{if json.Unmarshal(row.EncryptionRootIDs,&roots)!=nil{return Readiness{},ErrReadinessInvalid}};return Readiness{Mode:row.Mode,SchemaVersion:parseSchemaVersion(row.SchemaVersion),DatabaseIdentity:row.DatabaseIdentity,IndexRootID:row.IndexRootID,EncryptionRootIDs:roots,SourceManifestDigest:append([]byte(nil),row.SourceManifestDigest...),TargetManifestDigest:append([]byte(nil),row.TargetManifestDigest...),TerminalGlobalPosition:row.TerminalGlobalPosition,TerminalProjectionPosition:row.TerminalProjectionPosition,CompletedAt:timeOrZero(row.CompletedAt)},nil}
func parseSchemaVersion(v string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func timeOrZero(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return *v
}
func validateReadinessValue(r Readiness) error {
	if r.Mode != "fresh" && r.Mode != "import" || r.SchemaVersion == 0 || strings.TrimSpace(r.DatabaseIdentity) == "" || strings.TrimSpace(r.IndexRootID) == "" {
		return ErrReadinessInvalid
	}
	if len(r.SourceManifestDigest) != 0 && len(r.SourceManifestDigest) != 32 || len(r.TargetManifestDigest) != 0 && len(r.TargetManifestDigest) != 32 {
		return ErrReadinessInvalid
	}
	if r.TerminalGlobalPosition == maxUint64 || r.TerminalProjectionPosition == maxUint64 {
		return ErrReadinessInvalid
	}
	if r.Mode == "import" && (len(r.SourceManifestDigest) != 32 || len(r.TargetManifestDigest) != 32 || r.TerminalGlobalPosition == 0 || r.TerminalProjectionPosition == 0 || r.CompletedAt.IsZero()) {
		return ErrReadinessInvalid
	}
	seen := make(map[string]struct{}, len(r.EncryptionRootIDs))
	for _, rootID := range r.EncryptionRootIDs {
		if strings.TrimSpace(rootID) == "" {
			return ErrReadinessInvalid
		}
		if _, ok := seen[rootID]; ok {
			return ErrReadinessInvalid
		}
		seen[rootID] = struct{}{}
	}
	if r.Mode == "import" && r.CompletedAt.IsZero() {
		return ErrReadinessInvalid
	}
	return nil
}

func readinessDatabaseNonEmpty(ctx context.Context, db *gorm.DB) (bool, error) {
	for _, model := range []any{&domainEventRow{}, &aggregateHeadRow{}, &projectionReadModelRow{}, &operationRow{}, &operationArtifactRow{}, &laneHeadRow{}, &inboxMessageRow{}, &outboxEffectRow{}, &adapterSecretRow{}, &pluginKVRow{}, &subjectFenceRow{}} {
		var count int64
		if err := db.WithContext(ctx).Model(model).Count(&count).Error; err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}
func readinessRootReferences(ctx context.Context, db *gorm.DB) (map[string]struct{}, error) {
	refs := make(map[string]struct{})
	queries := []struct {
		model any
		field string
		cipher string
	}{
		{&adapterSecretRow{}, "encryption_key_id", "ciphertext"},
		{&operationRow{}, "private_key_id", "private_context"},
		{&operationArtifactRow{}, "encryption_key_id", "ciphertext"},
		{&inboxMessageRow{}, "encryption_key_id", "payload_ciphertext"},
		{&outboxEffectRow{}, "encryption_key_id", "payload_ciphertext"},
		{&pluginKVRow{}, "encryption_key_id", "encrypted_value"},
	}
	for _, query := range queries {
		var ids []string
		where := query.cipher + " IS NOT NULL AND length(" + query.cipher + ") > 0"
		if err := db.WithContext(ctx).Model(query.model).Where(where).Distinct(query.field).Pluck(query.field, &ids).Error; err != nil {
			return nil, err
		}
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return nil, ErrReadinessQuarantined
			}
			refs[id] = struct{}{}
		}
	}
	return refs, nil
}

func readinessTerminalPositions(ctx context.Context, db *gorm.DB) (uint64, uint64, error) {
	var sequence eventGlobalSequenceRow
	if err := db.WithContext(ctx).Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
		return 0, 0, err
	}
	var control projectionControlRow
	if err := db.WithContext(ctx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return 0, 0, err
	}
	latest := uint64(0)
	if sequence.NextPosition > 0 {
		latest = sequence.NextPosition - 1
	}
	return latest, control.TerminalPosition, nil
}

func (s *GORMStore) ValidateReadiness(ctx context.Context) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrReadinessInvalid
	}
	r, err := s.GetReadiness(ctx)
	if err != nil {
		return err
	}
	if err = validateReadinessValue(r); err != nil {
		return err
	}
	nonempty, err := readinessDatabaseNonEmpty(ctx, s.db.GORM())
	if err != nil {
		return ErrReadinessQuarantined
	}
	if r.IndexRootID == "unconfigured" || r.Mode == "fresh" && nonempty {
		return ErrReadinessQuarantined
	}
	if expected := strings.TrimSpace(s.db.databaseIdentity); expected != "" && r.DatabaseIdentity != expected {
		return ErrReadinessQuarantined
	}
	if s.keySource == nil {
		return ErrKeySourceUnavailable
	}
	id, _, err := keySourceIndex(ctx, s.keySource)
	if err != nil || id != r.IndexRootID {
		return ErrReadinessQuarantined
	}
	if _, err = keySourceCurrent(ctx, s.keySource); err != nil {
		return ErrReadinessQuarantined
	}
	available := make(map[string]struct{}, len(r.EncryptionRootIDs))
	for _, rootID := range r.EncryptionRootIDs {
		if _, err = keySourceRoot(ctx, s.keySource, rootID); err != nil {
			return ErrReadinessQuarantined
		}
		available[rootID] = struct{}{}
	}
	if refs, refErr := readinessRootReferences(ctx, s.db.GORM()); refErr != nil {
		return ErrReadinessQuarantined
	} else {
		for rootID := range refs {
			if _, ok := available[rootID]; !ok {
				return ErrReadinessQuarantined
			}
		}
	}
	if nonempty && r.Mode == "import" {
		global, projection, terminalErr := readinessTerminalPositions(ctx, s.db.GORM())
		if terminalErr != nil || global != r.TerminalGlobalPosition || projection != r.TerminalProjectionPosition {
			return ErrReadinessQuarantined
		}
	}
	return nil
}
func (s *GORMStore) validateA6UnitOfWork(ctx context.Context, work UnitOfWork) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrParticipantFailure
	}
	return s.validateA6UnitOfWorkWithDB(ctx, s.db.GORM(), work)
}
func (s *GORMStore) validateA6UnitOfWorkWithDB(ctx context.Context, db *gorm.DB, work UnitOfWork) error {
	if s == nil || s.keySource == nil {
		return nil
	}
	if db == nil {
		return ErrParticipantFailure
	}
	if s == nil || s.keySource == nil {
		return nil
	}
	if err := s.requireA6BoundCodec(); err != nil {
		return err
	}
	for _, update := range work.Operations {
		if len(update.PrivateContextCiphertext) == 0 && len(update.PrivateContextNonce) == 0 {
			continue
		}
		if update.OperationID == "" || update.PrincipalID == "" || update.EncryptionKeyID == "" {
			return ErrInvalidMetadata
		}
		version := uint64(1)
		if _, err := openBoundPayload(ctx, s.codec, "operation-private/v1", update.OperationID, update.PrincipalID, version, update.PrivateContextCiphertext, update.PrivateContextNonce, update.EncryptionKeyID); err != nil {
			return ErrAuthenticationFailed
		}
	}
	for _, update := range work.InboxUpdates {
		if len(update.PayloadCiphertext) == 0 && len(update.PayloadNonce) == 0 {
			continue
		}
		if update.InboxID == "" || update.EndpointID == "" || update.DigestKeyID == "" {
			return ErrInvalidMetadata
		}
		version := uint64(1)
		if _, err := openBoundPayload(ctx, s.codec, "inbox/v1", update.InboxID, update.EndpointID, version, update.PayloadCiphertext, update.PayloadNonce, update.DigestKeyID); err != nil {
			return ErrAuthenticationFailed
		}
	}
	for _, effect := range work.Effects {
		if len(effect.PayloadCiphertext) == 0 && len(effect.PayloadNonce) == 0 {
			continue
		}
		if effect.EffectID == "" || effect.EndpointID == "" || effect.DigestKeyID == "" {
			return ErrInvalidMetadata
		}
		version := uint64(1)
		if _, err := openBoundPayload(ctx, s.codec, "outbox/v1", effect.EffectID, effect.EndpointID, version, effect.PayloadCiphertext, effect.PayloadNonce, effect.DigestKeyID); err != nil {
			return ErrAuthenticationFailed
		}
	}
	for _, update := range work.ArtifactUpdates {
		if len(update.Ciphertext) == 0 && len(update.Nonce) == 0 {
			continue
		}
		if update.ArtifactID == "" || update.EncryptionKeyID == "" {
			return ErrInvalidMetadata
		}
		owner := update.OwnerPrincipalID
		if owner == "" && update.OperationID != "" {
			var operation operationRow
			if err := db.WithContext(ctx).Select("principal_id").Where("operation_id = ?", update.OperationID).First(&operation).Error; err == nil {
				owner = operation.PrincipalID
			}
		}
		if owner == "" {
			return ErrInvalidMetadata
		}
		version := uint64(1)
		if _, err := openBoundPayload(ctx, s.codec, "artifact/v1", update.ArtifactID, owner, version, update.Ciphertext, update.Nonce, update.EncryptionKeyID); err != nil {
			return ErrAuthenticationFailed
		}
	}
	for _, update := range work.SecretUpdates {
		if strings.TrimSpace(update.SecretRef) == "" {
			return ErrInvalidMetadata
		}
		var latest adapterSecretRow
		query := db.WithContext(ctx).Where("secret_ref = ?", update.SecretRef).Order("secret_version DESC").First(&latest)
		existing := query.Error == nil
		if !existing && !errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		endpoint, adapter := update.EndpointID, update.AdapterID
		secretVersion := update.SecretVersion
		allCipher := len(update.Ciphertext) > 0 && len(update.Nonce) > 0 && update.EncryptionKeyID != ""
		anyCipher := len(update.Ciphertext) > 0 || len(update.Nonce) > 0 || update.EncryptionKeyID != ""
		if anyCipher && !allCipher {
			return ErrInvalidMetadata
		}
		if existing {
			if endpoint == "" {
				endpoint = latest.EndpointID
			}
			if adapter == "" {
				adapter = latest.AdapterID
			}
			if secretVersion == 0 {
				if latest.SecretVersion == maxUint64 {
					return ErrVersionExhausted
				}
				secretVersion = latest.SecretVersion + 1
			}
			if endpoint != latest.EndpointID || adapter != latest.AdapterID {
				return ErrInvalidMetadata
			}
		} else {
			if endpoint == "" || adapter == "" || !allCipher {
				return ErrInvalidMetadata
			}
			if secretVersion == 0 {
				secretVersion = 1
			}
		}
		if secretVersion == 0 || update.EncryptionKeyID == "" && !existing {
			return ErrInvalidMetadata
		}
		if allCipher {
			if _, err := a6Open(ctx, s.keySource, "adapter-secret/v1", update.SecretRef, endpoint+"/"+adapter, secretVersion, update.EncryptionKeyID, update.Ciphertext, update.Nonce); err != nil {
				return ErrAuthenticationFailed
			}
		} else {
			if !existing {
				return ErrInvalidMetadata
			}
			if _, err := a6Open(ctx, s.keySource, "adapter-secret/v1", latest.SecretRef, latest.EndpointID+"/"+latest.AdapterID, latest.SecretVersion, latest.EncryptionKeyID, latest.Ciphertext, latest.Nonce); err != nil {
				return ErrAuthenticationFailed
			}
		}
	}
	for _, update := range work.PluginKVUpdates {
		if update.Deleted {
			continue
		}
		if update.ExtensionID == "" || len(update.KeyHMAC) != sha256.Size || len(update.KeyCiphertext) == 0 || len(update.KeyNonce) == 0 || len(update.ValueCiphertext) == 0 || len(update.ValueNonce) == 0 || update.EncryptionKeyID == "" {
			return ErrInvalidMetadata
		}
		var existing pluginKVRow
		version := uint64(1)
		query := db.WithContext(ctx).Where("extension_id = ? AND key_hmac = ?", update.ExtensionID, update.KeyHMAC).First(&existing)
		if query.Error == nil {
			version = existing.RowVersion + 1
		} else if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		if update.Version != 0 {
			version = update.Version
		}
		key, err := a6Open(ctx, s.keySource, "plugin-kv-key/v1", string(update.KeyHMAC), update.ExtensionID, version, update.EncryptionKeyID, update.KeyCiphertext, update.KeyNonce)
		if err != nil {
			return ErrAuthenticationFailed
		}
		if len(key) == 0 || len(key) > MaxPluginKeyBytes {
			return ErrInvalidMetadata
		}
		value, err := a6Open(ctx, s.keySource, "plugin-kv-value/v1", string(update.KeyHMAC), update.ExtensionID, version, update.EncryptionKeyID, update.ValueCiphertext, update.ValueNonce)
		if err != nil {
			return ErrAuthenticationFailed
		}
		if len(value) > MaxPluginValueBytes || update.ValueSize != int64(len(value)) {
			return ErrInvalidMetadata
		}
	}
	return nil
}

func (s *GORMStore) SetReadiness(ctx context.Context, r Readiness) error {
	if err := validateReadinessValue(r); err != nil {
		return err
	}
	if s == nil || s.db == nil || s.keySource == nil {
		return ErrKeySourceUnavailable
	}
	id, _, err := keySourceIndex(ctx, s.keySource)
	if err != nil || id != r.IndexRootID {
		return ErrReadinessQuarantined
	}
	if _, err = keySourceCurrent(ctx, s.keySource); err != nil {
		return ErrKeyUnavailable
	}
	for _, rootID := range r.EncryptionRootIDs {
		if _, err = keySourceRoot(ctx, s.keySource, rootID); err != nil {
			return ErrKeyUnavailable
		}
	}
	if expected := strings.TrimSpace(s.db.databaseIdentity); expected != "" && r.DatabaseIdentity != expected {
		return ErrReadinessQuarantined
	}
	roots, err := json.Marshal(r.EncryptionRootIDs)
	if err != nil {
		return ErrReadinessInvalid
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrReadinessInvalid
	}
	defer tx.Rollback()
	var existing storeReadinessRow
	queryErr := locked(tx).Where("singleton_id = ?", "default").First(&existing).Error
	if queryErr == nil {
		if existing.IndexRootID != "" && existing.IndexRootID != "unconfigured" && existing.IndexRootID != r.IndexRootID {
			return ErrReadinessQuarantined
		}
		if existing.Mode == "import" && r.Mode == "fresh" {
			return ErrReadinessInvalid
		}
	} else if !errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return ErrParticipantFailure
	}
	var control projectionControlRow
	if lockErr := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; lockErr != nil {
		return ErrParticipantFailure
	}
	nonempty, countErr := readinessDatabaseNonEmpty(ctx, tx)
	if countErr != nil {
		return ErrParticipantFailure
	}
	if r.Mode == "fresh" && nonempty {
		return ErrReadinessQuarantined
	}
	if refs, refErr := readinessRootReferences(ctx, tx); refErr != nil {
		return ErrParticipantFailure
	} else {
		requested := make(map[string]struct{}, len(r.EncryptionRootIDs))
		for _, rootID := range r.EncryptionRootIDs {
			requested[rootID] = struct{}{}
		}
		for rootID := range refs {
			if _, ok := requested[rootID]; !ok {
				return ErrReadinessQuarantined
			}
		}
	}
	if nonempty && r.Mode == "import" {
		global, projection, terminalErr := readinessTerminalPositions(ctx, tx)
		if terminalErr != nil || control.PublicationState != "published" || global != r.TerminalGlobalPosition || projection != r.TerminalProjectionPosition {
			return ErrReadinessQuarantined
		}
	}
	row := storeReadinessRow{SingletonID: "default", Mode: r.Mode, SchemaVersion: fmt.Sprint(r.SchemaVersion), DatabaseIdentity: r.DatabaseIdentity, IndexRootID: r.IndexRootID, EncryptionRootIDs: roots, SourceManifestDigest: append([]byte(nil), r.SourceManifestDigest...), TargetManifestDigest: append([]byte(nil), r.TargetManifestDigest...), TerminalGlobalPosition: r.TerminalGlobalPosition, TerminalProjectionPosition: r.TerminalProjectionPosition}
	if !r.CompletedAt.IsZero() {
		completed := r.CompletedAt
		row.CompletedAt = &completed
	}
	if err = tx.Save(&row).Error; err != nil {
		return ErrReadinessInvalid
	}
	if err = tx.Commit().Error; err != nil {
		return ErrReadinessInvalid
	}
	return nil
}

func (s *GORMStore) PutSecret(ctx context.Context, req SecretPutRequest) (SecretResolution, error) {
	if strings.TrimSpace(req.SecretRef) == "" || strings.TrimSpace(req.EndpointID) == "" || strings.TrimSpace(req.AdapterID) == "" {
		return SecretResolution{}, ErrInvalidMetadata
	}
	if len(req.Plaintext) > MaxSecretBytes {
		return SecretResolution{}, ErrOversizeInput
	}
	now := s.task5Now()
	if _, err := keySourceCurrent(ctx, s.keySource); err != nil {
		return SecretResolution{}, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return SecretResolution{}, ErrEncryptionUnavailable
	}
	defer tx.Rollback()
	if err := lockPublication(tx); err != nil {
		return SecretResolution{}, err
	}
	var latest adapterSecretRow
	current := uint64(0)
	query := locked(tx).Where("secret_ref = ?", req.SecretRef).Order("row_version DESC").First(&latest)
	if query.Error == nil {
		current = latest.RowVersion
	} else if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return SecretResolution{}, ErrParticipantFailure
	}
	if req.ExpectedVersion != 0 && req.ExpectedVersion != current {
		return SecretResolution{}, ErrParticipantConflict
	}
	version := req.SecretVersion
	if version == 0 {
		version = 1
		if current > 0 {
			version = latest.SecretVersion + 1
		}
	} else if current > 0 && version <= latest.SecretVersion {
		return SecretResolution{}, ErrParticipantConflict
	}
	ciphertext, nonce, keyID, err := a6Seal(ctx, s.keySource, "adapter-secret/v1", req.SecretRef, req.EndpointID+"/"+req.AdapterID, version, req.Plaintext)
	if err != nil {
		return SecretResolution{}, err
	}
	row := adapterSecretRow{SecretRef: req.SecretRef, SecretVersion: version, EndpointID: req.EndpointID, AdapterID: req.AdapterID, AdapterType: "opaque", Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID, RowVersion: current + 1, CreatedAt: now, UpdatedAt: now}
	if err = tx.Create(&row).Error; err != nil {
		return SecretResolution{}, ErrParticipantFailure
	}
	if err = tx.Commit().Error; err != nil {
		return SecretResolution{}, ErrParticipantFailure
	}
	return SecretResolution{SecretRef: req.SecretRef, SecretVersion: version, Plaintext: append([]byte(nil), req.Plaintext...)}, nil
}
func (s *GORMStore) ResolveSecret(ctx context.Context,ref string,version uint64)(SecretResolution,error){if ref==""{return SecretResolution{},ErrNotFound};var row adapterSecretRow;q:=s.db.GORM().WithContext(ctx).Where("secret_ref = ?",ref);if version>0{q=q.Where("secret_version = ?",version)}else{q=q.Order("secret_version DESC")};if e:=q.First(&row).Error;e!=nil{return SecretResolution{},ErrNotFound};plain,e:=a6Open(ctx,s.keySource,"adapter-secret/v1",row.SecretRef,row.EndpointID+"/"+row.AdapterID,row.SecretVersion,row.EncryptionKeyID,row.Ciphertext,row.Nonce);if e!=nil{return SecretResolution{},ErrAuthenticationFailed};return SecretResolution{SecretRef:row.SecretRef,SecretVersion:row.SecretVersion,Plaintext:plain},nil}

func (s *GORMStore) pluginValueUsageOn(ctx context.Context, db *gorm.DB, extension string, exclude []byte) (int64, error) {
	var rows []pluginKVRow
	if err := db.WithContext(ctx).Where("extension_id = ?", extension).Order("key_hmac ASC").Limit(MaxPluginScan + 1).Find(&rows).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	if len(rows) > MaxPluginScan {
		return 0, ErrOversizeInput
	}
	var total int64
	for _, row := range rows {
		if string(row.KeyHMAC) == string(exclude) {
			continue
		}
		plain, err := a6Open(ctx, s.keySource, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedValue, row.ValueNonce)
		if err != nil {
			return 0, ErrAuthenticationFailed
		}
		if len(plain) > MaxPluginValueBytes || int64(len(plain)) != row.ValueSize {
			return 0, ErrInvalidMetadata
		}
		total += int64(len(plain))
		if total > MaxPluginBytes {
			return 0, ErrOversizeInput
		}
	}
	return total, nil
}

func (s *GORMStore) pluginValueUsage(ctx context.Context, extension string, exclude []byte) (int64, error) {
	return s.pluginValueUsageOn(ctx, s.db.GORM(), extension, exclude)
}

func lockPublication(tx *gorm.DB) error {
	var readiness storeReadinessRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&readiness).Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}
func lockPluginQuota(tx *gorm.DB) error {
	return lockPublication(tx)
}

func (s *GORMStore) SetPluginKV(ctx context.Context, req PluginKVPutRequest) (PluginKVItem, error) {
	if req.ExtensionID == "" || len(req.Key) == 0 || len(req.Key) > MaxPluginKeyBytes || len(req.Value) > MaxPluginValueBytes {
		return PluginKVItem{}, ErrOversizeInput
	}
	index, err := a6HMAC(ctx, s.keySource, "plugin-key-index/v1", req.ExtensionID, req.Key)
	if err != nil {
		return PluginKVItem{}, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := lockPluginQuota(tx); err != nil {
		return PluginKVItem{}, err
	}
	now := s.task5Now()
	var existing pluginKVRow
	q := locked(tx).Where("extension_id = ? AND key_hmac = ?", req.ExtensionID, index).First(&existing)
	current := uint64(0)
	if q.Error == nil {
		current = existing.RowVersion
	} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return PluginKVItem{}, ErrParticipantFailure
	}
	if req.ExpectedVersion != 0 && req.ExpectedVersion != current {
		return PluginKVItem{}, ErrParticipantConflict
	}
	if current == 0 {
		var count int64
		if err := tx.Model(&pluginKVRow{}).Where("extension_id = ?", req.ExtensionID).Count(&count).Error; err != nil {
			return PluginKVItem{}, ErrParticipantFailure
		}
		if count >= MaxPluginKeys {
			return PluginKVItem{}, ErrOversizeInput
		}
	}
	usage, err := s.pluginValueUsageOn(ctx, tx, req.ExtensionID, index)
	if err != nil {
		return PluginKVItem{}, err
	}
	if usage+int64(len(req.Value)) > MaxPluginBytes {
		return PluginKVItem{}, ErrOversizeInput
	}
	version, err := nextVersion(current)
	if err != nil {
		return PluginKVItem{}, err
	}
	root, err := keySourceCurrent(ctx, s.keySource)
	if err != nil {
		return PluginKVItem{}, err
	}
	keyCipher, keyNonce, keyID, err := a6SealWithRoot(root, "plugin-kv-key/v1", string(index), req.ExtensionID, version, []byte(req.Key))
	if err != nil {
		return PluginKVItem{}, err
	}
	valueCipher, valueNonce, valueKeyID, err := a6SealWithRoot(root, "plugin-kv-value/v1", string(index), req.ExtensionID, version, req.Value)
	if err != nil || valueKeyID != keyID {
		return PluginKVItem{}, ErrEncryptionUnavailable
	}
	row := pluginKVRow{ExtensionID: req.ExtensionID, KeyHMAC: index, EncryptedKey: keyCipher, KeyNonce: keyNonce, EncryptedValue: valueCipher, ValueNonce: valueNonce, ValueSize: int64(len(req.Value)), RowVersion: version, EncryptionKeyID: keyID, CreatedAt: now, UpdatedAt: now}
	if current > 0 {
		q = tx.Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ?", req.ExtensionID, index, current).Updates(map[string]any{"encrypted_key": keyCipher, "key_nonce": keyNonce, "encrypted_value": valueCipher, "value_nonce": valueNonce, "value_size": len(req.Value), "row_version": version, "encryption_key_id": keyID, "updated_at": now})
		if q.Error != nil {
			return PluginKVItem{}, ErrParticipantFailure
		}
		if q.RowsAffected != 1 {
			return PluginKVItem{}, ErrParticipantConflict
		}
	} else if err := tx.Create(&row).Error; err != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	if err := tx.Commit().Error; err != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	return PluginKVItem{ExtensionID: req.ExtensionID, Key: req.Key, Value: append([]byte(nil), req.Value...), Version: version}, nil
}

func (s *GORMStore) decodePluginKVRow(ctx context.Context, row pluginKVRow) (PluginKVItem, error) {
	key, err := a6Open(ctx, s.keySource, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedKey, row.KeyNonce)
	if err != nil {
		return PluginKVItem{}, ErrAuthenticationFailed
	}
	value, err := a6Open(ctx, s.keySource, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedValue, row.ValueNonce)
	if err != nil {
		return PluginKVItem{}, ErrAuthenticationFailed
	}
	if len(key) == 0 || len(key) > MaxPluginKeyBytes || len(value) > MaxPluginValueBytes || int64(len(value)) != row.ValueSize {
		return PluginKVItem{}, ErrInvalidMetadata
	}
	return PluginKVItem{ExtensionID: row.ExtensionID, Key: string(key), Value: value, Version: row.RowVersion}, nil
}

func (s *GORMStore) GetPluginKV(ctx context.Context, extension, key string) (PluginKVItem, error) {
	if extension == "" || key == "" {
		return PluginKVItem{}, ErrPluginKVNotFound
	}
	index, err := a6HMAC(ctx, s.keySource, "plugin-key-index/v1", extension, key)
	if err != nil {
		return PluginKVItem{}, err
	}
	var row pluginKVRow
	if err := s.db.GORM().WithContext(ctx).Where("extension_id = ? AND key_hmac = ?", extension, index).First(&row).Error; err != nil {
		return PluginKVItem{}, ErrPluginKVNotFound
	}
	item, err := s.decodePluginKVRow(ctx, row)
	if err != nil {
		return PluginKVItem{}, err
	}
	if item.Key != key {
		return PluginKVItem{}, ErrAuthenticationFailed
	}
	return item, nil
}

func (s *GORMStore) DeletePluginKV(ctx context.Context, extension, key string, expected uint64) error {
	if extension == "" || key == "" {
		return ErrPluginKVNotFound
	}
	index, err := a6HMAC(ctx, s.keySource, "plugin-key-index/v1", extension, key)
	if err != nil {
		return err
	}
	q := s.db.GORM().WithContext(ctx).Where("extension_id = ? AND key_hmac = ?", extension, index)
	if expected > 0 {
		q = q.Where("row_version = ?", expected)
	}
	result := q.Delete(&pluginKVRow{})
	if result.Error != nil {
		return ErrParticipantFailure
	}
	if result.RowsAffected != 1 {
		if expected > 0 {
			return ErrParticipantConflict
		}
		return ErrPluginKVNotFound
	}
	return nil
}

func (s *GORMStore) ListPluginKV(ctx context.Context, req PluginKVListRequest) ([]PluginKVItem, error) {
	if req.ExtensionID == "" {
		return nil, ErrParticipantFailure
	}
	limit := req.Limit
	if limit <= 0 || limit > MaxPluginResults {
		limit = MaxPluginResults
	}
	var rows []pluginKVRow
	if err := s.db.GORM().WithContext(ctx).Where("extension_id = ?", req.ExtensionID).Order("key_hmac ASC").Limit(MaxPluginScan + 1).Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	if len(rows) > MaxPluginScan {
		return nil, ErrOversizeInput
	}
	out := make([]PluginKVItem, 0, minInt(limit, len(rows)))
	responseBytes := 0
	for _, row := range rows {
		item, err := s.decodePluginKVRow(ctx, row)
		if err != nil {
			return nil, err
		}
		if req.Prefix != "" && !strings.HasPrefix(item.Key, req.Prefix) {
			continue
		}
		responseBytes += len(item.Key) + len(item.Value)
		if responseBytes > MaxPluginResponseBytes {
			return nil, ErrOversizeInput
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const rotationPageSize = 256

func (s *GORMStore) RotateEncryptionRoots(ctx context.Context) (EncryptionRotationResult, error) {
	root, err := keySourceCurrent(ctx, s.keySource)
	if err != nil {
		return EncryptionRotationResult{}, err
	}
	result := EncryptionRotationResult{CurrentRootID: root.ID}
	updated, skipped, err := s.rotateSecretRows(ctx, root)
	if err != nil {
		return result, err
	}
	result.Updated, result.Skipped = updated, skipped
	updated, skipped, err = s.rotateA6PayloadTables(ctx, root)
	if err != nil {
		return result, err
	}
	result.Updated += updated
	result.Skipped += skipped
	if err := s.refreshReadinessRoots(ctx, root.ID); err != nil {
		return result, err
	}
	return result, nil
}

func (s *GORMStore) rotateSecretRows(ctx context.Context, root EncryptionRoot) (updated, skipped int, err error) {
	var cursorRef string
	var cursorVersion uint64
	for {
		var rows []adapterSecretRow
		q := s.db.GORM().WithContext(ctx).Order("secret_ref ASC, secret_version ASC").Limit(rotationPageSize)
		if cursorRef != "" {
			q = q.Where("(secret_ref > ?) OR (secret_ref = ? AND secret_version > ?)", cursorRef, cursorRef, cursorVersion)
		}
		if err = q.Find(&rows).Error; err != nil {
			return
		}
		if len(rows) == 0 {
			return
		}
		for _, row := range rows {
			if row.EncryptionKeyID == root.ID {
				continue
			}
			plain, openErr := a6Open(ctx, s.keySource, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, row.EncryptionKeyID, row.Ciphertext, row.Nonce)
			if openErr != nil {
				err = openErr
				return
			}
			ciphertext, nonce, keyID, sealErr := a6SealWithRoot(root, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, plain)
			if sealErr != nil {
				err = sealErr
				return
			}
			q = s.db.GORM().WithContext(ctx).Model(&adapterSecretRow{}).Where("secret_ref = ? AND secret_version = ? AND row_version = ? AND encryption_key_id = ?", row.SecretRef, row.SecretVersion, row.RowVersion, row.EncryptionKeyID).Updates(map[string]any{"ciphertext": ciphertext, "nonce": nonce, "encryption_key_id": keyID, "row_version": row.RowVersion + 1, "updated_at": s.task5Now()})
			if q.Error != nil {
				err = ErrParticipantFailure
				return
			}
			if q.RowsAffected == 1 {
				updated++
			} else {
				skipped++
			}
		}
		last := rows[len(rows)-1]
		cursorRef, cursorVersion = last.SecretRef, last.SecretVersion
		if len(rows) < rotationPageSize {
			return
		}
	}
}
func (s *GORMStore) refreshReadinessRoots(ctx context.Context, currentID string) error {
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := lockPublication(tx); err != nil {
		return err
	}
	refs, err := readinessRootReferences(ctx, tx)
	if err != nil {
		return ErrParticipantFailure
	}
	if strings.TrimSpace(currentID) == "" {
		return ErrReadinessInvalid
	}
	refs[currentID] = struct{}{}
	ids := make([]string, 0, len(refs))
	for id := range refs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, err := json.Marshal(ids)
	if err != nil {
		return ErrReadinessInvalid
	}
	if err := tx.Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("encryption_root_ids", data).Error; err != nil {
		return ErrParticipantFailure
	}
	if err := tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}


func (s *GORMStore) rotateA6PayloadTables(ctx context.Context, root EncryptionRoot) (updated, skipped int, err error) {
	base := s.db.GORM().WithContext(ctx)
	var operationCursor string
	for {
		var rows []operationRow
		q := base.Where("private_context IS NOT NULL AND length(private_context) > 0")
		if operationCursor != "" {
			q = q.Where("operation_id > ?", operationCursor)
		}
		if err = q.Order("operation_id ASC").Limit(rotationPageSize).Find(&rows).Error; err != nil {
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if row.PrivateKeyID == root.ID {
				continue
			}
			plain, openErr := a6Open(ctx, s.keySource, "operation-private/v1", row.OperationID, row.PrincipalID, 1, row.PrivateKeyID, row.PrivateContext, row.PrivateNonce)
			if openErr != nil {
				err = openErr
				return
			}
			ciphertext, nonce, keyID, sealErr := a6SealWithRoot(root, "operation-private/v1", row.OperationID, row.PrincipalID, 1, plain)
			if sealErr != nil {
				err = sealErr
				return
			}
			q = base.Model(&operationRow{}).Where("operation_id = ? AND version = ? AND private_key_id = ?", row.OperationID, row.Version, row.PrivateKeyID).Updates(map[string]any{"private_context": ciphertext, "private_nonce": nonce, "private_key_id": keyID, "updated_at": s.task5Now()})
			if q.Error != nil {
				err = ErrParticipantFailure
				return
			}
			if q.RowsAffected == 1 {
				updated++
			} else {
				skipped++
			}
		}
		operationCursor = rows[len(rows)-1].OperationID
		if len(rows) < rotationPageSize {
			break
		}
	}
	var artifactCursor string
	for {
		var rows []operationArtifactRow
		q := base.Where("ciphertext IS NOT NULL AND length(ciphertext) > 0")
		if artifactCursor != "" {
			q = q.Where("artifact_id > ?", artifactCursor)
		}
		if err = q.Order("artifact_id ASC").Limit(rotationPageSize).Find(&rows).Error; err != nil {
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if row.EncryptionKeyID == root.ID {
				continue
			}
			plain, openErr := a6Open(ctx, s.keySource, "artifact/v1", row.ArtifactID, row.OwnerPrincipalID, 1, row.EncryptionKeyID, row.Ciphertext, row.Nonce)
			if openErr != nil {
				err = openErr
				return
			}
			ciphertext, nonce, keyID, sealErr := a6SealWithRoot(root, "artifact/v1", row.ArtifactID, row.OwnerPrincipalID, 1, plain)
			if sealErr != nil {
				err = sealErr
				return
			}
			q = base.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ? AND encryption_key_id = ?", row.ArtifactID, row.Version, row.EncryptionKeyID).Updates(map[string]any{"ciphertext": ciphertext, "nonce": nonce, "encryption_key_id": keyID})
			if q.Error != nil {
				err = ErrParticipantFailure
				return
			}
			if q.RowsAffected == 1 {
				updated++
			} else {
				skipped++
			}
		}
		artifactCursor = rows[len(rows)-1].ArtifactID
		if len(rows) < rotationPageSize {
			break
		}
	}
	var inboxCursor string
	for {
		var rows []inboxMessageRow
		q := base.Where("payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0")
		if inboxCursor != "" {
			q = q.Where("inbox_id > ?", inboxCursor)
		}
		if err = q.Order("inbox_id ASC").Limit(rotationPageSize).Find(&rows).Error; err != nil {
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if row.EncryptionKeyID == root.ID {
				continue
			}
			plain, openErr := a6Open(ctx, s.keySource, "inbox/v1", row.InboxID, row.EndpointID, 1, row.EncryptionKeyID, row.PayloadCiphertext, row.PayloadNonce)
			if openErr != nil {
				err = openErr
				return
			}
			ciphertext, nonce, keyID, sealErr := a6SealWithRoot(root, "inbox/v1", row.InboxID, row.EndpointID, 1, plain)
			if sealErr != nil {
				err = sealErr
				return
			}
			q = base.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ? AND encryption_key_id = ?", row.InboxID, row.Version, row.EncryptionKeyID).Updates(map[string]any{"payload_ciphertext": ciphertext, "payload_nonce": nonce, "encryption_key_id": keyID})
			if q.Error != nil {
				err = ErrParticipantFailure
				return
			}
			if q.RowsAffected == 1 {
				updated++
			} else {
				skipped++
			}
		}
		inboxCursor = rows[len(rows)-1].InboxID
		if len(rows) < rotationPageSize {
			break
		}
	}
	var effectCursor string
	for {
		var rows []outboxEffectRow
		q := base.Where("payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0")
		if effectCursor != "" {
			q = q.Where("effect_id > ?", effectCursor)
		}
		if err = q.Order("effect_id ASC").Limit(rotationPageSize).Find(&rows).Error; err != nil {
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if row.EncryptionKeyID == root.ID {
				continue
			}
			plain, openErr := a6Open(ctx, s.keySource, "outbox/v1", row.EffectID, row.EndpointID, 1, row.EncryptionKeyID, row.PayloadCiphertext, row.PayloadNonce)
			if openErr != nil {
				err = openErr
				return
			}
			ciphertext, nonce, keyID, sealErr := a6SealWithRoot(root, "outbox/v1", row.EffectID, row.EndpointID, 1, plain)
			if sealErr != nil {
				err = sealErr
				return
			}
			q = base.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND encryption_key_id = ?", row.EffectID, row.Version, row.EncryptionKeyID).Updates(map[string]any{"payload_ciphertext": ciphertext, "payload_nonce": nonce, "encryption_key_id": keyID})
			if q.Error != nil {
				err = ErrParticipantFailure
				return
			}
			if q.RowsAffected == 1 {
				updated++
			} else {
				skipped++
			}
		}
		effectCursor = rows[len(rows)-1].EffectID
		if len(rows) < rotationPageSize {
			break
		}
	}
	var extensionCursor string
	var pluginCursor []byte
	for {
		var rows []pluginKVRow
		q := base.Where("encrypted_key IS NOT NULL AND length(encrypted_key) > 0")
		if extensionCursor != "" {
			q = q.Where("(extension_id > ?) OR (extension_id = ? AND key_hmac > ?)", extensionCursor, extensionCursor, pluginCursor)
		}
		if err = q.Order("extension_id ASC, key_hmac ASC").Limit(rotationPageSize).Find(&rows).Error; err != nil {
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if row.EncryptionKeyID == root.ID {
				continue
			}
			key, openErr := a6Open(ctx, s.keySource, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedKey, row.KeyNonce)
			if openErr != nil {
				err = openErr
				return
			}
			value, openErr := a6Open(ctx, s.keySource, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedValue, row.ValueNonce)
			if openErr != nil {
				err = openErr
				return
			}
			newVersion, versionErr := nextVersion(row.RowVersion)
			if versionErr != nil {
				err = versionErr
				return
			}
			keyCipher, keyNonce, keyID, sealErr := a6SealWithRoot(root, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, newVersion, key)
			if sealErr != nil {
				err = sealErr
				return
			}
			valueCipher, valueNonce, valueKeyID, sealErr := a6SealWithRoot(root, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, newVersion, value)
			if sealErr != nil || valueKeyID != keyID {
				err = ErrEncryptionUnavailable
				return
			}
			q = base.Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ? AND encryption_key_id = ?", row.ExtensionID, row.KeyHMAC, row.RowVersion, row.EncryptionKeyID).Updates(map[string]any{"encrypted_key": keyCipher, "key_nonce": keyNonce, "encrypted_value": valueCipher, "value_nonce": valueNonce, "encryption_key_id": keyID, "row_version": newVersion, "updated_at": s.task5Now()})
			if q.Error != nil {
				err = ErrParticipantFailure
				return
			}
			if q.RowsAffected == 1 {
				updated++
			} else {
				skipped++
			}
		}
		last := rows[len(rows)-1]
		extensionCursor, pluginCursor = last.ExtensionID, append(pluginCursor[:0], last.KeyHMAC...)
		if len(rows) < rotationPageSize {
			break
		}
	}
	return
}

func (s *GORMStore) ValidateA6(ctx context.Context) error { if s.keySource==nil{return ErrKeySourceUnavailable};if _,_,e:=keySourceIndex(ctx,s.keySource);e!=nil{return e};if _,e:=keySourceCurrent(ctx,s.keySource);e!=nil{return e};return nil }

var _ SecretRepository = (*GORMStore)(nil)
var _ PluginKVRepository = (*GORMStore)(nil)
var _ ReadinessRepository = (*GORMStore)(nil)
var _ EncryptionRotator = (*GORMStore)(nil)
