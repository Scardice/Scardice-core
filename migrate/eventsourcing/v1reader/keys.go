// Package v1reader is a frozen, read-only reader for the encrypted (v1) event
// store. It exists only so that an installation which still runs on that
// format can be migrated once into the plaintext store; nothing else may
// import it, and it must not be extended with new features.
//
// The byte-level contracts below (key derivation, associated data, keyed
// digests) are copies of what the v1 eventstore wrote and are therefore fixed:
// changing any of them makes existing databases undecryptable.
package v1reader

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

var (
	// ErrKeyUnavailable means a key file is missing, unreadable or malformed.
	ErrKeyUnavailable = errors.New("v1reader: encryption key unavailable")
	// ErrAuthenticationFailed means a ciphertext did not authenticate: the key
	// is not the one that sealed it, or the row was altered.
	ErrAuthenticationFailed = errors.New("v1reader: encrypted data authentication failed")
)

const keyFileBytes = 32

// Keys reads the v1 local key files: one index root used for keyed digests and
// a directory of encryption roots, one 32-byte file per root ID.
type Keys struct {
	indexPath string
	rootsDir  string

	mu    sync.Mutex
	index []byte
	roots map[string][]byte
}

// OpenKeys returns a reader for the key files at the given locations. Nothing
// is read until a key is needed.
func OpenKeys(indexPath, rootsDir string) *Keys {
	return &Keys{indexPath: indexPath, rootsDir: rootsDir, roots: map[string][]byte{}}
}

func (k *Keys) indexRoot() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.index != nil {
		return k.index, nil
	}
	material, err := readKeyFile(k.indexPath)
	if err != nil {
		return nil, err
	}
	k.index = material
	return material, nil
}

func (k *Keys) encryptionRoot(id string) ([]byte, error) {
	if id == "" || strings.ContainsAny(id, `/\`) {
		return nil, ErrKeyUnavailable
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if material, ok := k.roots[id]; ok {
		return material, nil
	}
	material, err := readKeyFile(filepath.Join(k.rootsDir, id+".key"))
	if err != nil {
		return nil, err
	}
	k.roots[id] = material
	return material, nil
}

// open authenticates and decrypts one v1 ciphertext. domain, identity, owner
// and version are the values the v1 store bound into the associated data when
// it sealed the row; keyID names the encryption root.
func (k *Keys) open(domain, identity, owner string, version uint64, keyID string, ciphertext, nonce []byte) ([]byte, error) {
	root, err := k.encryptionRoot(keyID)
	if err != nil {
		return nil, err
	}
	sub := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, root, nil, []byte(domain)), sub); err != nil {
		return nil, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrAuthenticationFailed
	}
	plain, err := aead.Open(nil, nonce, ciphertext, associatedData(domain, identity, owner, version, keyID))
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plain, nil
}

func lengthField(dst, v []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(v)))
	return append(append(dst, n[:]...), v...)
}

func associatedData(domain, identity, owner string, version uint64, keyID string) []byte {
	aad := make([]byte, 0, 128)
	aad = lengthField(aad, []byte(domain))
	aad = lengthField(aad, []byte(identity))
	aad = lengthField(aad, []byte(owner))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], version)
	aad = append(aad, b[:]...)
	return lengthField(aad, []byte(keyID))
}

// keyedDigest is the index-root HMAC the v1 store used to derive opaque
// identifiers: HMAC-SHA256(index, domain || part || part ...).
func (k *Keys) keyedDigest(domain string, parts ...string) ([]byte, error) {
	index, err := k.indexRoot()
	if err != nil {
		return nil, err
	}
	if len(index) != sha256.Size {
		return nil, ErrKeyUnavailable
	}
	mac := hmac.New(sha256.New, index)
	mac.Write([]byte(domain))
	for _, part := range parts {
		mac.Write([]byte(part))
	}
	return mac.Sum(nil), nil
}

// canonical is the length-prefixed joining the v1 store applied to identity
// parts before hashing them.
func canonical(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return b.String()
}

// ScopeDigest is the opaque Story-log scope of one group of one Dice.
func (k *Keys) ScopeDigest(diceID, groupID string) ([]byte, error) {
	if strings.TrimSpace(diceID) == "" || strings.TrimSpace(groupID) == "" {
		return nil, errors.New("v1reader: dice and group IDs are required")
	}
	return k.keyedDigest("story-log-scope/v1", canonical(diceID, groupID))
}

// intentAADID is the number the v1 store bound into a Story-log intent's
// associated data in place of a row ID: the first 8 bytes of SHA-256 of the
// effect ID, big-endian.
func intentAADID(effectID string) uint64 {
	sum := sha256.Sum256([]byte(effectID))
	return binary.BigEndian.Uint64(sum[:8])
}

// GroupRef names one group of one Dice.
type GroupRef struct{ DiceID, GroupID string }

// ResolveScopes maps Story-log scope digests (as stored) back to the group
// they were derived from. A digest can only be reversed by recomputing it for
// a candidate, so the caller passes every group it knows of; digests matching
// no candidate are absent from the result.
func (k *Keys) ResolveScopes(candidates []GroupRef) (map[string]GroupRef, error) {
	out := make(map[string]GroupRef, len(candidates))
	for _, candidate := range candidates {
		digest, err := k.ScopeDigest(candidate.DiceID, candidate.GroupID)
		if err != nil {
			return nil, err
		}
		out[hex.EncodeToString(digest)] = candidate
	}
	return out, nil
}

// ResolveDice maps Story-log Dice digests back to Dice IDs, like ResolveScopes.
func (k *Keys) ResolveDice(diceIDs []string) (map[string]string, error) {
	out := make(map[string]string, len(diceIDs))
	for _, id := range diceIDs {
		digest, err := k.DiceDigest(id)
		if err != nil {
			return nil, err
		}
		out[hex.EncodeToString(digest)] = id
	}
	return out, nil
}

// DiceDigest is the opaque Story-log identifier of one Dice.
func (k *Keys) DiceDigest(diceID string) ([]byte, error) {
	if strings.TrimSpace(diceID) == "" {
		return nil, errors.New("v1reader: dice ID is required")
	}
	return k.keyedDigest("story-log-dice/v1", diceID)
}
