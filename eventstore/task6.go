package eventstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

type MemoryKeySource struct {
	IndexID string
	IndexMaterial []byte
	Roots map[string][]byte
	CurrentID string
}
func NewMemoryKeySource(indexID string, indexMaterial []byte, roots map[string][]byte, currentID string) *MemoryKeySource {
	copyRoots := make(map[string][]byte, len(roots))
	for id, material := range roots { copyRoots[id] = append([]byte(nil), material...) }
	return &MemoryKeySource{IndexID:indexID, IndexMaterial:append([]byte(nil), indexMaterial...), Roots:copyRoots, CurrentID:currentID}
}
func (m *MemoryKeySource) IndexRootID(context.Context) (string, error) { if m == nil || m.IndexID == "" { return "", ErrKeySourceUnavailable }; return m.IndexID,nil }
func (m *MemoryKeySource) IndexRootMaterial(context.Context) ([]byte, error) { if m == nil || len(m.IndexMaterial) < 32 { return nil, ErrKeySourceUnavailable }; return append([]byte(nil),m.IndexMaterial...),nil }
func (m *MemoryKeySource) CurrentEncryptionRoot(context.Context) (EncryptionRoot,error) { if m == nil || m.CurrentID == "" { return EncryptionRoot{},ErrKeySourceUnavailable }; material,err:=m.EncryptionRoot(context.Background(),m.CurrentID); return EncryptionRoot{ID:m.CurrentID,Material:material},err }
func (m *MemoryKeySource) EncryptionRoot(_ context.Context,id string) ([]byte,error) { if m == nil { return nil,ErrKeySourceUnavailable }; material,ok:=m.Roots[id]; if !ok || len(material)!=32{return nil,ErrKeyUnavailable}; return append([]byte(nil),material...),nil }
func (m *MemoryKeySource) EncryptionRoots(context.Context) ([]EncryptionRoot,error) { if m==nil{return nil,ErrKeySourceUnavailable}; ids:=make([]string,0,len(m.Roots));for id:=range m.Roots{ids=append(ids,id)};sort.Strings(ids);out:=make([]EncryptionRoot,0,len(ids));for _,id:=range ids{v,e:=m.EncryptionRoot(context.Background(),id);if e!=nil{return nil,e};out=append(out,EncryptionRoot{ID:id,Material:v})};return out,nil }

type UnixFileKeySource struct { IndexPath string; RootsDir string }
func NewUnixFileKeySource(indexPath, rootsDir string) *UnixFileKeySource { return &UnixFileKeySource{IndexPath:indexPath,RootsDir:rootsDir} }
func (f *UnixFileKeySource) IndexRootID(context.Context) (string,error) { return filepath.Base(f.IndexPath),nil }
func (f *UnixFileKeySource) IndexRootMaterial(context.Context) ([]byte,error) { return readKeyFile(f.IndexPath) }
func (f *UnixFileKeySource) CurrentEncryptionRoot(ctx context.Context) (EncryptionRoot,error) { roots,e:=f.EncryptionRoots(ctx);if e!=nil||len(roots)==0{return EncryptionRoot{},ErrKeyUnavailable};return roots[len(roots)-1],nil }
func (f *UnixFileKeySource) EncryptionRoot(_ context.Context,id string) ([]byte,error) { if strings.ContainsAny(id,"/\\")||id==""{return nil,ErrKeyUnavailable};return readKeyFile(filepath.Join(f.RootsDir,id+".key")) }
func (f *UnixFileKeySource) EncryptionRoots(ctx context.Context) ([]EncryptionRoot,error) { if runtime.GOOS=="windows"{return nil,ErrKeySourceUnavailable}; entries,e:=os.ReadDir(f.RootsDir);if e!=nil{return nil,ErrKeyUnavailable};out:=make([]EncryptionRoot,0,len(entries));for _,entry:=range entries{if entry.IsDir()||!strings.HasSuffix(entry.Name(),".key"){continue};id:=strings.TrimSuffix(entry.Name(),".key");material,e:=f.EncryptionRoot(ctx,id);if e!=nil{return nil,e};out=append(out,EncryptionRoot{ID:id,Material:material})};sort.Slice(out,func(i,j int)bool{return out[i].ID<out[j].ID});return out,nil }
func CreateUnixKeyFile(path string, material []byte) error { if runtime.GOOS=="windows"||len(material)!=32{return ErrKeyUnavailable};fd,e:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if e!=nil{return ErrKeyUnavailable};defer fd.Close();if _,e=fd.Write(material);e!=nil{return ErrKeyUnavailable};return nil }
func readKeyFile(path string)([]byte,error){if runtime.GOOS=="windows"{return nil,ErrKeySourceUnavailable};info,e:=os.Lstat(path);if e!=nil||info.Mode()&os.ModeSymlink!=0{return nil,ErrKeyUnavailable};if info.Mode().Perm()!=0600{return nil,ErrKeyUnavailable};if stat,ok:=info.Sys().(*syscall.Stat_t);ok&&int(stat.Uid)!=os.Getuid(){return nil,ErrKeyUnavailable};material,e:=os.ReadFile(path);if e!=nil||len(material)!=32{return nil,ErrKeyUnavailable};return material,nil}

func keySourceIndex(ctx context.Context, source KeySource)(string,[]byte,error){if source==nil{return "",nil,ErrKeySourceUnavailable};ids,ok:=source.(interface{IndexRootID(context.Context)(string,error)});if !ok{return "",nil,ErrKeySourceUnavailable};id,e:=ids.IndexRootID(ctx);if e!=nil||id==""{return "",nil,ErrKeySourceUnavailable};materials,ok:=source.(interface{IndexRootMaterial(context.Context)([]byte,error)});if !ok{return "",nil,ErrKeySourceUnavailable};material,e:=materials.IndexRootMaterial(ctx);if e!=nil||len(material)!=32{return "",nil,ErrKeySourceUnavailable};return id,material,nil}
func keySourceCurrent(ctx context.Context, source KeySource)(EncryptionRoot,error){if source==nil{return EncryptionRoot{},ErrKeySourceUnavailable};v,ok:=source.(interface{CurrentEncryptionRoot(context.Context)(EncryptionRoot,error)});if !ok{return EncryptionRoot{},ErrKeySourceUnavailable};root,e:=v.CurrentEncryptionRoot(ctx);if e!=nil||root.ID==""||len(root.Material)!=32{return EncryptionRoot{},ErrKeyUnavailable};return root,nil}
func keySourceRoot(ctx context.Context, source KeySource,id string)([]byte,error){if source==nil{return nil,ErrKeySourceUnavailable};v,ok:=source.(interface{EncryptionRoot(context.Context,string)([]byte,error)});if !ok{return nil,ErrKeySourceUnavailable};material,e:=v.EncryptionRoot(ctx,id);if e!=nil||len(material)!=32{return nil,ErrKeyUnavailable};return material,nil}
func deriveA6(root []byte,label string)([]byte,error){if len(root)!=32{return nil,ErrKeyUnavailable};out:=make([]byte,32);r:=hkdf.New(sha256.New,root,nil,[]byte(label));if _,e:=io.ReadFull(r,out);e!=nil{return nil,ErrKeyUnavailable};return out,nil}
func lengthField(dst []byte,v []byte)[]byte{var n [4]byte;binary.BigEndian.PutUint32(n[:],uint32(len(v)));dst=append(dst,n[:]...);return append(dst,v...)}
func a6AAD(domain,identity,owner string,version uint64,keyID string)[]byte{aad:=make([]byte,0,128);aad=lengthField(aad,[]byte(domain));aad=lengthField(aad,[]byte(identity));aad=lengthField(aad,[]byte(owner));var b [8]byte;binary.BigEndian.PutUint64(b[:],version);aad=append(aad,b[:]...);return lengthField(aad,[]byte(keyID))}
func a6Seal(ctx context.Context, source KeySource, domain, identity, owner string, version uint64, plaintext []byte)([]byte,[]byte,string,error){root,e:=keySourceCurrent(ctx,source);if e!=nil{return nil,nil,"",e};sub,e:=deriveA6(root.Material,domain);if e!=nil{return nil,nil,"",e};block,e:=aes.NewCipher(sub);if e!=nil{return nil,nil,"",ErrEncryptionUnavailable};gcm,e:=cipher.NewGCM(block);if e!=nil{return nil,nil,"",ErrEncryptionUnavailable};nonce:=make([]byte,gcm.NonceSize());if _,e=rand.Read(nonce);e!=nil{return nil,nil,"",ErrEncryptionUnavailable};return gcm.Seal(nil,nonce,plaintext,a6AAD(domain,identity,owner,version,root.ID)),nonce,root.ID,nil}
func a6Open(ctx context.Context, source KeySource, domain, identity, owner string, version uint64,keyID string,ciphertext,nonce []byte)([]byte,error){root,e:=keySourceRoot(ctx,source,keyID);if e!=nil{return nil,e};sub,e:=deriveA6(root,domain);if e!=nil{return nil,e};block,e:=aes.NewCipher(sub);if e!=nil{return nil,ErrAuthenticationFailed};gcm,e:=cipher.NewGCM(block);if e!=nil||len(nonce)!=gcm.NonceSize(){return nil,ErrAuthenticationFailed};plain,e:=gcm.Open(nil,nonce,ciphertext,a6AAD(domain,identity,owner,version,keyID));if e!=nil{return nil,ErrAuthenticationFailed};return plain,nil}
func a6HMAC(ctx context.Context, source KeySource, domain string, parts ...string)([]byte,error){_,index,e:=keySourceIndex(ctx,source);if e!=nil{return nil,e};h:=hmac.New(sha256.New,index);h.Write(lengthField(nil,[]byte(domain)));for _,part:=range parts{h.Write(lengthField(nil,[]byte(part)))};return h.Sum(nil),nil}

type a6PayloadCodec struct{ source KeySource }
func (c *a6PayloadCodec) Encrypt(ctx context.Context, plaintext []byte)([]byte,[]byte,string,error){return a6Seal(ctx,c.source,"artifact/v1","payload","",0,plaintext)}
func (c *a6PayloadCodec) Decrypt(ctx context.Context,ciphertext,nonce []byte,keyID string)([]byte,error){return a6Open(ctx,c.source,"artifact/v1","payload","",0,keyID,ciphertext,nonce)}

func (s *GORMStore) GetReadiness(ctx context.Context)(Readiness,error){var row storeReadinessRow;if s==nil||s.db==nil{return Readiness{},ErrReadinessInvalid};if err:=s.db.GORM().WithContext(ctx).Where("singleton_id = ?","default").First(&row).Error;err!=nil{return Readiness{},ErrReadinessQuarantined};var roots []string;if len(row.EncryptionRootIDs)>0{if json.Unmarshal(row.EncryptionRootIDs,&roots)!=nil{return Readiness{},ErrReadinessInvalid}};return Readiness{Mode:row.Mode,SchemaVersion:parseSchemaVersion(row.SchemaVersion),DatabaseIdentity:row.DatabaseIdentity,IndexRootID:row.IndexRootID,EncryptionRootIDs:roots,SourceManifestDigest:append([]byte(nil),row.SourceManifestDigest...),TargetManifestDigest:append([]byte(nil),row.TargetManifestDigest...),TerminalGlobalPosition:row.TerminalGlobalPosition,TerminalProjectionPosition:row.TerminalProjectionPosition,CompletedAt:timeOrZero(row.CompletedAt)},nil}
func parseSchemaVersion(v string)uint32{var n uint64;fmt.Sscanf(v,"%d",&n);return uint32(n)}
func timeOrZero(v *time.Time)time.Time{if v==nil{return time.Time{}};return *v}
func validateReadinessValue(r Readiness)error{if r.Mode!="fresh"&&r.Mode!="import"||r.SchemaVersion==0||r.DatabaseIdentity==""||r.IndexRootID==""{return ErrReadinessInvalid};if len(r.SourceManifestDigest)!=0&&len(r.SourceManifestDigest)!=32||len(r.TargetManifestDigest)!=0&&len(r.TargetManifestDigest)!=32{return ErrReadinessInvalid};if r.Mode=="import"&&r.CompletedAt.IsZero(){return ErrReadinessInvalid};return nil}
func (s *GORMStore) ValidateReadiness(ctx context.Context)error{r,e:=s.GetReadiness(ctx);if e!=nil{return e};if e=validateReadinessValue(r);e!=nil{return e};if s.keySource==nil{return ErrKeySourceUnavailable};id,_,e:=keySourceIndex(ctx,s.keySource);if e!=nil||id!=r.IndexRootID{return ErrReadinessQuarantined};for _,rootID:=range r.EncryptionRootIDs{if _,e=keySourceRoot(ctx,s.keySource,rootID);e!=nil{return ErrReadinessQuarantined}};return nil}
func (s *GORMStore) SetReadiness(ctx context.Context,r Readiness)error{if e:=validateReadinessValue(r);e!=nil{return e};if s.keySource!=nil{if id,_,e:=keySourceIndex(ctx,s.keySource);e!=nil||id!=r.IndexRootID{return ErrReadinessQuarantined};for _,rootID:=range r.EncryptionRootIDs{if _,e:=keySourceRoot(ctx,s.keySource,rootID);e!=nil{return ErrKeyUnavailable}}};roots,_:=json.Marshal(r.EncryptionRootIDs);tx:=s.db.GORM().WithContext(ctx).Begin();if tx.Error!=nil{return ErrReadinessInvalid};defer tx.Rollback();var existing storeReadinessRow;if e:=tx.Where("singleton_id = ?","default").First(&existing).Error;e==nil{if existing.IndexRootID!=""&&existing.IndexRootID!="unconfigured"&&existing.IndexRootID!=r.IndexRootID{return ErrReadinessQuarantined};if existing.Mode=="import"&&r.Mode=="fresh"{return ErrReadinessInvalid}};row:=storeReadinessRow{SingletonID:"default",Mode:r.Mode,SchemaVersion:fmt.Sprint(r.SchemaVersion),DatabaseIdentity:r.DatabaseIdentity,IndexRootID:r.IndexRootID,EncryptionRootIDs:roots,SourceManifestDigest:r.SourceManifestDigest,TargetManifestDigest:r.TargetManifestDigest,TerminalGlobalPosition:r.TerminalGlobalPosition,TerminalProjectionPosition:r.TerminalProjectionPosition};if !r.CompletedAt.IsZero(){row.CompletedAt=&r.CompletedAt};if e:=tx.Save(&row).Error;e!=nil{return ErrReadinessInvalid};if e:=tx.Commit().Error;e!=nil{return ErrReadinessInvalid};return nil}

func (s *GORMStore) PutSecret(ctx context.Context,req SecretPutRequest)(SecretResolution,error){if req.SecretRef==""||len(req.Plaintext)>MaxSecretBytes{return SecretResolution{},ErrOversizeInput};now:=s.task5Now();_,e:=keySourceCurrent(ctx,s.keySource);if e!=nil{return SecretResolution{},e};tx:=s.db.GORM().WithContext(ctx).Begin();if tx.Error!=nil{return SecretResolution{},ErrEncryptionUnavailable};defer tx.Rollback();var latest adapterSecretRow;current:=uint64(0);if q:=tx.Where("secret_ref = ?",req.SecretRef).Order("row_version DESC").First(&latest);q.Error==nil{current=latest.RowVersion}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return SecretResolution{},ErrParticipantFailure};if req.ExpectedVersion!=0&&req.ExpectedVersion!=current{return SecretResolution{},ErrParticipantConflict};version:=req.SecretVersion;if version==0{version=1;if current>0{version=latest.SecretVersion+1}};ciphertext,nonce,keyID,e:=a6Seal(ctx,s.keySource,"adapter-secret/v1",req.SecretRef,req.EndpointID+"/"+req.AdapterID,version,req.Plaintext);if e!=nil{return SecretResolution{},e};row:=adapterSecretRow{SecretRef:req.SecretRef,SecretVersion:version,EndpointID:req.EndpointID,AdapterID:req.AdapterID,AdapterType:"opaque",Ciphertext:ciphertext,Nonce:nonce,EncryptionKeyID:keyID,RowVersion:current+1,CreatedAt:now,UpdatedAt:now};if e=tx.Create(&row).Error;e!=nil{return SecretResolution{},ErrParticipantFailure};if e=tx.Commit().Error;e!=nil{return SecretResolution{},ErrParticipantFailure};return SecretResolution{SecretRef:req.SecretRef,SecretVersion:version,Plaintext:append([]byte(nil),req.Plaintext...)},nil}
func (s *GORMStore) ResolveSecret(ctx context.Context,ref string,version uint64)(SecretResolution,error){if ref==""{return SecretResolution{},ErrNotFound};var row adapterSecretRow;q:=s.db.GORM().WithContext(ctx).Where("secret_ref = ?",ref);if version>0{q=q.Where("secret_version = ?",version)}else{q=q.Order("secret_version DESC")};if e:=q.First(&row).Error;e!=nil{return SecretResolution{},ErrNotFound};plain,e:=a6Open(ctx,s.keySource,"adapter-secret/v1",row.SecretRef,row.EndpointID+"/"+row.AdapterID,row.SecretVersion,row.EncryptionKeyID,row.Ciphertext,row.Nonce);if e!=nil{return SecretResolution{},ErrAuthenticationFailed};return SecretResolution{SecretRef:row.SecretRef,SecretVersion:row.SecretVersion,Plaintext:plain},nil}

func (s *GORMStore) SetPluginKV(ctx context.Context,req PluginKVPutRequest)(PluginKVItem,error){if req.ExtensionID==""||len(req.Key)==0||len([]byte(req.Key))>MaxPluginKeyBytes||len(req.Value)>MaxPluginValueBytes{return PluginKVItem{},ErrOversizeInput};index,e:=a6HMAC(ctx,s.keySource,"plugin-key-index/v1",req.ExtensionID,req.Key);if e!=nil{return PluginKVItem{},e};now:=s.task5Now();var existing pluginKVRow;q:=s.db.GORM().WithContext(ctx).Where("extension_id = ? AND key_hmac = ?",req.ExtensionID,index).First(&existing);current:=uint64(0);if q.Error==nil{current=existing.RowVersion}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return PluginKVItem{},ErrParticipantFailure};if req.ExpectedVersion!=0&&req.ExpectedVersion!=current{return PluginKVItem{},ErrParticipantConflict};root,e:=keySourceCurrent(ctx,s.keySource);if e!=nil{return PluginKVItem{},e};keyCipher,keyNonce,keyID,e:=a6Seal(ctx,s.keySource,"plugin-kv-key/v1",string(index),req.ExtensionID,current+1,[]byte(req.Key));if e!=nil{return PluginKVItem{},e};valueCipher,valueNonce,_,e:=a6Seal(ctx,s.keySource,"plugin-kv-value/v1",string(index),req.ExtensionID,current+1,req.Value);if e!=nil{return PluginKVItem{},e};_ = root;row:=pluginKVRow{ExtensionID:req.ExtensionID,KeyHMAC:index,EncryptedKey:keyCipher,KeyNonce:keyNonce,EncryptedValue:valueCipher,ValueNonce:valueNonce,ValueSize:int64(len(req.Value)),RowVersion:current+1,EncryptionKeyID:keyID,CreatedAt:now,UpdatedAt:now};if current>0{e=s.db.GORM().WithContext(ctx).Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ?",req.ExtensionID,index,current).Updates(map[string]any{"encrypted_key":keyCipher,"key_nonce":keyNonce,"encrypted_value":valueCipher,"value_nonce":valueNonce,"value_size":len(req.Value),"row_version":current+1,"encryption_key_id":keyID,"updated_at":now}).Error}else{e=s.db.GORM().WithContext(ctx).Create(&row).Error};if e!=nil{return PluginKVItem{},ErrParticipantFailure};return PluginKVItem{ExtensionID:req.ExtensionID,Key:req.Key,Value:append([]byte(nil),req.Value...),Version:current+1},nil}
func (s *GORMStore) GetPluginKV(ctx context.Context,extension,key string)(PluginKVItem,error){if extension==""||key==""{return PluginKVItem{},ErrPluginKVNotFound};index,e:=a6HMAC(ctx,s.keySource,"plugin-key-index/v1",extension,key);if e!=nil{return PluginKVItem{},e};var row pluginKVRow;if e=s.db.GORM().WithContext(ctx).Where("extension_id = ? AND key_hmac = ?",extension,index).First(&row).Error;e!=nil{return PluginKVItem{},ErrPluginKVNotFound};plainKey,e:=a6Open(ctx,s.keySource,"plugin-kv-key/v1",string(index),extension,row.RowVersion,row.EncryptionKeyID,row.EncryptedKey,row.KeyNonce);if e!=nil{return PluginKVItem{},ErrAuthenticationFailed};plainValue,e:=a6Open(ctx,s.keySource,"plugin-kv-value/v1",string(index),extension,row.RowVersion,row.EncryptionKeyID,row.EncryptedValue,row.ValueNonce);if e!=nil{return PluginKVItem{},ErrAuthenticationFailed};if len(plainKey)>MaxPluginKeyBytes||len(plainValue)>MaxPluginValueBytes||int64(len(plainValue))!=row.ValueSize{return PluginKVItem{},ErrInvalidMetadata};return PluginKVItem{ExtensionID:extension,Key:string(plainKey),Value:plainValue,Version:row.RowVersion},nil}
func (s *GORMStore) DeletePluginKV(ctx context.Context,extension,key string,expected uint64)error{index,e:=a6HMAC(ctx,s.keySource,"plugin-key-index/v1",extension,key);if e!=nil{return e};q:=s.db.GORM().WithContext(ctx).Where("extension_id = ? AND key_hmac = ?",extension,index);if expected>0{q=q.Where("row_version = ?",expected)};if e=q.Delete(&pluginKVRow{}).Error;e!=nil{return ErrParticipantFailure};return nil}
func (s *GORMStore) ListPluginKV(ctx context.Context,req PluginKVListRequest)([]PluginKVItem,error){if req.ExtensionID==""{return nil,ErrParticipantFailure};limit:=req.Limit;if limit<=0||limit>MaxPluginResults{limit=MaxPluginResults};var rows []pluginKVRow;if e:=s.db.GORM().WithContext(ctx).Where("extension_id = ?",req.ExtensionID).Order("key_hmac ASC").Limit(MaxPluginScan+1).Find(&rows).Error;e!=nil{return nil,ErrParticipantFailure};if len(rows)>MaxPluginScan{return nil,ErrOversizeInput};out:=make([]PluginKVItem,0,minInt(limit,len(rows)));bytes:=0;for _,row:=range rows{item,e:=s.GetPluginKV(ctx,req.ExtensionID,"__unavailable__");_ = item;if e!=nil{key,e:=a6Open(ctx,s.keySource,"plugin-kv-key/v1",string(row.KeyHMAC),req.ExtensionID,row.RowVersion,row.EncryptionKeyID,row.EncryptedKey,row.KeyNonce);if e!=nil{return nil,ErrAuthenticationFailed};value,e:=a6Open(ctx,s.keySource,"plugin-kv-value/v1",string(row.KeyHMAC),req.ExtensionID,row.RowVersion,row.EncryptionKeyID,row.EncryptedValue,row.ValueNonce);if e!=nil{return nil,ErrAuthenticationFailed};if req.Prefix!=""&&!strings.HasPrefix(string(key),req.Prefix){continue};bytes+=len(key)+len(value);if bytes>MaxPluginResponseBytes{return nil,ErrOversizeInput};out=append(out,PluginKVItem{ExtensionID:req.ExtensionID,Key:string(key),Value:value,Version:row.RowVersion});if len(out)>=limit{break}}};return out,nil}
func minInt(a,b int)int{if a<b{return a};return b}

func (s *GORMStore) RotateEncryptionRoots(ctx context.Context) (EncryptionRotationResult, error) {
	root, err := keySourceCurrent(ctx, s.keySource)
	if err != nil {
		return EncryptionRotationResult{}, err
	}
	result := EncryptionRotationResult{CurrentRootID: root.ID}
	var secrets []adapterSecretRow
	if err := s.db.GORM().WithContext(ctx).Find(&secrets).Error; err != nil {
		return result, ErrParticipantFailure
	}
	for _, row := range secrets {
		if row.EncryptionKeyID == root.ID { continue }
		plain, err := a6Open(ctx, s.keySource, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, row.EncryptionKeyID, row.Ciphertext, row.Nonce)
		if err != nil { return result, err }
		ciphertext, nonce, keyID, err := a6Seal(ctx, s.keySource, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, plain)
		if err != nil { return result, err }
		q := s.db.GORM().WithContext(ctx).Model(&adapterSecretRow{}).Where("secret_ref = ? AND secret_version = ? AND row_version = ? AND encryption_key_id = ?", row.SecretRef, row.SecretVersion, row.RowVersion, row.EncryptionKeyID).Updates(map[string]any{"ciphertext": ciphertext, "nonce": nonce, "encryption_key_id": keyID, "row_version": row.RowVersion + 1, "updated_at": s.task5Now()})
		if q.Error != nil { return result, ErrParticipantFailure }
		if q.RowsAffected == 1 { result.Updated++ } else { result.Skipped++ }
	}
	if updated, skipped, err := s.rotateA6PayloadTables(ctx, root.ID); err != nil {
		return result, err
	} else {
		result.Updated += updated
		result.Skipped += skipped
	}
	return result, nil
}

func (s *GORMStore) rotateA6PayloadTables(ctx context.Context, currentID string) (updated, skipped int, err error) {
	var operations []operationRow
	if err = s.db.GORM().WithContext(ctx).Where("private_context IS NOT NULL AND length(private_context) > 0").Find(&operations).Error; err != nil { return }
	for _, row := range operations {
		if row.PrivateKeyID == currentID { continue }
		plain, e := a6Open(ctx, s.keySource, "operation-private/v1", row.OperationID, row.PrincipalID, row.Version, row.PrivateKeyID, row.PrivateContext, row.PrivateNonce); if e != nil { err = e; return }
		newVersion := row.Version + 1
		ciphertext, nonce, keyID, e := a6Seal(ctx, s.keySource, "operation-private/v1", row.OperationID, row.PrincipalID, newVersion, plain); if e != nil { err = e; return }
		q := s.db.GORM().WithContext(ctx).Model(&operationRow{}).Where("operation_id = ? AND version = ? AND private_key_id = ?", row.OperationID, row.Version, row.PrivateKeyID).Updates(map[string]any{"private_context": ciphertext, "private_nonce": nonce, "private_key_id": keyID, "version": newVersion, "updated_at": s.task5Now()}); if q.Error != nil { err = ErrParticipantFailure; return }; if q.RowsAffected == 1 { updated++ } else { skipped++ }
	}
	var artifacts []operationArtifactRow
	if err = s.db.GORM().WithContext(ctx).Where("ciphertext IS NOT NULL AND length(ciphertext) > 0").Find(&artifacts).Error; err != nil { return }
	for _, row := range artifacts {
		plain, e := a6Open(ctx, s.keySource, "artifact/v1", row.ArtifactID, row.OwnerPrincipalID, row.Version, row.EncryptionKeyID, row.Ciphertext, row.Nonce); if e != nil { err = e; return }
		newVersion := row.Version + 1
		ciphertext, nonce, keyID, e := a6Seal(ctx, s.keySource, "artifact/v1", row.ArtifactID, row.OwnerPrincipalID, newVersion, plain); if e != nil { err = e; return }
		q := s.db.GORM().WithContext(ctx).Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ? AND encryption_key_id = ?", row.ArtifactID, row.Version, row.EncryptionKeyID).Updates(map[string]any{"ciphertext": ciphertext, "nonce": nonce, "encryption_key_id": keyID, "version": newVersion}); if q.Error != nil { err = ErrParticipantFailure; return }; if q.RowsAffected == 1 { updated++ } else { skipped++ }
	}
	var inboxes []inboxMessageRow
	if err = s.db.GORM().WithContext(ctx).Where("payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0").Find(&inboxes).Error; err != nil { return }
	for _, row := range inboxes {
		plain, e := a6Open(ctx, s.keySource, "inbox/v1", row.InboxID, row.EndpointID, row.Version, row.EncryptionKeyID, row.PayloadCiphertext, row.PayloadNonce); if e != nil { err = e; return }
		newVersion := row.Version + 1
		ciphertext, nonce, keyID, e := a6Seal(ctx, s.keySource, "inbox/v1", row.InboxID, row.EndpointID, newVersion, plain); if e != nil { err = e; return }
		q := s.db.GORM().WithContext(ctx).Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ? AND encryption_key_id = ?", row.InboxID, row.Version, row.EncryptionKeyID).Updates(map[string]any{"payload_ciphertext": ciphertext, "payload_nonce": nonce, "encryption_key_id": keyID, "version": newVersion}); if q.Error != nil { err = ErrParticipantFailure; return }; if q.RowsAffected == 1 { updated++ } else { skipped++ }
	}
	var effects []outboxEffectRow
	if err = s.db.GORM().WithContext(ctx).Where("payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0").Find(&effects).Error; err != nil { return }
	for _, row := range effects {
		plain, e := a6Open(ctx, s.keySource, "outbox/v1", row.EffectID, row.EndpointID, row.Version, row.EncryptionKeyID, row.PayloadCiphertext, row.PayloadNonce); if e != nil { err = e; return }
		newVersion := row.Version + 1
		ciphertext, nonce, keyID, e := a6Seal(ctx, s.keySource, "outbox/v1", row.EffectID, row.EndpointID, newVersion, plain); if e != nil { err = e; return }
		q := s.db.GORM().WithContext(ctx).Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND encryption_key_id = ?", row.EffectID, row.Version, row.EncryptionKeyID).Updates(map[string]any{"payload_ciphertext": ciphertext, "payload_nonce": nonce, "encryption_key_id": keyID, "version": newVersion}); if q.Error != nil { err = ErrParticipantFailure; return }; if q.RowsAffected == 1 { updated++ } else { skipped++ }
	}
	var plugins []pluginKVRow
	if err = s.db.GORM().WithContext(ctx).Where("encrypted_key IS NOT NULL AND length(encrypted_key) > 0").Find(&plugins).Error; err != nil { return }
	for _, row := range plugins {
		key, e := a6Open(ctx, s.keySource, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedKey, row.KeyNonce); if e != nil { err = e; return }
		value, e := a6Open(ctx, s.keySource, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedValue, row.ValueNonce); if e != nil { err = e; return }
		newVersion := row.RowVersion + 1
		keyCipher, keyNonce, keyID, e := a6Seal(ctx, s.keySource, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, newVersion, key); if e != nil { err = e; return }
		valueCipher, valueNonce, _, e := a6Seal(ctx, s.keySource, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, newVersion, value); if e != nil { err = e; return }
		q := s.db.GORM().WithContext(ctx).Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ? AND encryption_key_id = ?", row.ExtensionID, row.KeyHMAC, row.RowVersion, row.EncryptionKeyID).Updates(map[string]any{"encrypted_key": keyCipher, "key_nonce": keyNonce, "encrypted_value": valueCipher, "value_nonce": valueNonce, "encryption_key_id": keyID, "row_version": newVersion, "updated_at": s.task5Now()}); if q.Error != nil { err = ErrParticipantFailure; return }; if q.RowsAffected == 1 { updated++ } else { skipped++ }
	}
	return
}

func (s *GORMStore) ValidateA6(ctx context.Context) error { if s.keySource==nil{return ErrKeySourceUnavailable};if _,_,e:=keySourceIndex(ctx,s.keySource);e!=nil{return e};if _,e:=keySourceCurrent(ctx,s.keySource);e!=nil{return e};return nil }

var _ SecretRepository = (*GORMStore)(nil)
var _ PluginKVRepository = (*GORMStore)(nil)
var _ ReadinessRepository = (*GORMStore)(nil)
var _ EncryptionRotator = (*GORMStore)(nil)

func hexID(b []byte) string { return hex.EncodeToString(b) }
var _ = hexID
