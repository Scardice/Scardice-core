package dice

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Milly/go-base2048"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/ed25519"

	"Scardice-core/logger"
	"Scardice-core/utils/crypto"
)

const trustedKeyBase64Prefix = "base64:"

type verifyLogger interface {
	Warn(...any)
	Warnf(string, ...any)
	Infof(string, ...any)
}

type keyLoadStatus int

const (
	keyLoadMissing keyLoadStatus = iota
	keyLoadLoaded
	keyLoadInvalid
)

var (
	// SealTrustedClientPrivateKey 可信客户端私钥
	SealTrustedClientPrivateKey = ``
	// SealSignClientPrivateKey 拉起 海豹v3 签名用私钥
	SealSignClientPrivateKey = ``
	verifyInitOnce           sync.Once
)

func initVerify() {
	log := logger.M()
	var trustedStatus keyLoadStatus
	SealTrustedClientPrivateKey, trustedStatus = loadTrustedPrivateKey(log)
	if trustedStatus == keyLoadMissing {
		log.Warn("SEAL_TRUSTED_PRIVATE_KEY not found, maybe in development mode")
	}
	var signStatus keyLoadStatus
	SealSignClientPrivateKey, signStatus = loadSignPrivateKey(log)
	if signStatus == keyLoadMissing {
		log.Warn("SEAL_SIGN_PRIVATE_KEY not found, maybe in development mode")
	}
}

func loadTrustedPrivateKey(log verifyLogger) (string, keyLoadStatus) {
	envRaw := os.Getenv("SEAL_TRUSTED_PRIVATE_KEY")
	if key, ok := normalizeTrustedPrivateKey(envRaw, log, "environment"); ok {
		return key, keyLoadLoaded
	}
	if strings.TrimSpace(envRaw) != "" {
		return "", keyLoadInvalid
	}
	if key, ok := normalizeTrustedPrivateKey(SealTrustedClientPrivateKey, log, "embedded"); ok {
		return key, keyLoadLoaded
	}
	if strings.TrimSpace(SealTrustedClientPrivateKey) != "" {
		return "", keyLoadInvalid
	}
	return "", keyLoadMissing
}

func normalizeTrustedPrivateKey(raw string, log verifyLogger, source string) (string, bool) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", false
	}

	if decoded, ok := decodeTrustedPrivateKeyBase64(key); ok {
		key = decoded
		if log != nil {
			log.Infof("可信客户端私钥已从%s base64 格式解码", source)
		}
	}

	if isTrustedPrivateKeyValid(key) {
		return key, true
	}

	repaired := repairTrustedPrivateKey(key)
	if repaired != key && isTrustedPrivateKeyValid(repaired) {
		if log != nil {
			log.Warnf("可信客户端私钥已自动修复%s中的 PEM 换行格式", source)
		}
		return repaired, true
	}

	if log != nil {
		log.Warnf("可信客户端私钥格式无效，已忽略%s中的配置", source)
	}
	return "", false
}

func decodeTrustedPrivateKeyBase64(key string) (string, bool) {
	if !strings.HasPrefix(key, trustedKeyBase64Prefix) {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(key, trustedKeyBase64Prefix))
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func repairTrustedPrivateKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if !strings.Contains(key, "\n") {
		key = strings.ReplaceAll(key, `\r\n`, "\n")
		key = strings.ReplaceAll(key, `\n`, "\n")
	}
	return key
}

func isTrustedPrivateKeyValid(key string) bool {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return false
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	_, ok := parsed.(*ecdsa.PrivateKey)
	return ok
}

func loadSignPrivateKey(log verifyLogger) (string, keyLoadStatus) {
	envRaw := os.Getenv("SEAL_SIGN_PRIVATE_KEY")
	if key, ok := normalizeSignPrivateKey(envRaw, log, "environment"); ok {
		return key, keyLoadLoaded
	}
	if strings.TrimSpace(envRaw) != "" {
		return "", keyLoadInvalid
	}
	if key, ok := normalizeSignPrivateKey(SealSignClientPrivateKey, log, "embedded"); ok {
		return key, keyLoadLoaded
	}
	if strings.TrimSpace(SealSignClientPrivateKey) != "" {
		return "", keyLoadInvalid
	}
	return "", keyLoadMissing
}

func normalizeSignPrivateKey(raw string, log verifyLogger, source string) (string, bool) {
	key := strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
	if key == "" {
		return "", false
	}
	decoded, err := hex.DecodeString(key)
	if err != nil {
		if log != nil {
			log.Warnf("签名私钥格式无效，已忽略%s中的配置: %v", source, err)
		}
		return "", false
	}
	if len(decoded) != ed25519.PrivateKeySize {
		if log != nil {
			log.Warnf("签名私钥长度无效，已忽略%s中的配置: got=%d want=%d", source, len(decoded), ed25519.PrivateKeySize)
		}
		return "", false
	}
	if log != nil && key != strings.TrimSpace(raw) {
		log.Warnf("签名私钥已自动修复%s中的空白格式", source)
	}
	return key, true
}

func ensureVerifyInitialized() {
	verifyInitOnce.Do(initVerify)
}

type payload struct {
	Version   string `msgpack:"version,omitempty"`
	Timestamp int64  `msgpack:"timestamp,omitempty"`
	Platform  string `msgpack:"platform,omitempty"`
	Uid       string `msgpack:"uid,omitempty"`
	Username  string `msgpack:"username,omitempty"`
}

type data struct {
	Payload []byte `msgpack:"payload,omitempty"`
	Sign    []byte `msgpack:"sign,omitempty"`
}

// GenerateVerificationCode 生成海豹校验码
func GenerateVerificationCode(platform string, userID string, username string, useBase64 bool) string {
	ensureVerifyInitialized()
	if len(SealTrustedClientPrivateKey) == 0 {
		return ""
	}
	// 海豹校验码格式：SEAL<data>
	p := payload{
		Version:   VERSION.String(),
		Timestamp: time.Now().Unix(),
		Platform:  platform,
		Uid:       userID,
		Username:  username,
	}
	pp, _ := msgpack.Marshal(p)
	sign, err := crypto.EcdsaSignRow(pp, SealTrustedClientPrivateKey)
	if err != nil {
		return ""
	}

	d := data{
		Payload: pp,
		Sign:    sign,
	}
	dp, _ := msgpack.Marshal(d)
	if useBase64 {
		return fmt.Sprintf("SEAL#%s", base64.StdEncoding.EncodeToString(dp))
	} else {
		return fmt.Sprintf("SEAL%%%s", base2048.DefaultEncoding.EncodeToString(dp))
	}
}

type payloadPublicDice struct {
	Version string `msgpack:"version,omitempty"`
	Sign    []byte `msgpack:"sign,omitempty"`
}

func GenerateVerificationKeyForPublicDice(data any) string {
	ensureVerifyInitialized()
	doEcdsaSign := len(SealTrustedClientPrivateKey) > 0
	pp, _ := msgpack.Marshal(data)

	var sign []byte
	if doEcdsaSign {
		var err error
		sign, err = crypto.EcdsaSignRow(pp, SealTrustedClientPrivateKey)
		if err != nil {
			return ""
		}
	} else {
		h := sha256.New()
		h.Write(pp)
		sign = h.Sum(nil)
	}

	d := payloadPublicDice{
		Version: VERSION.String(),
		Sign:    sign,
	}

	dp, _ := msgpack.Marshal(d)
	if doEcdsaSign {
		return fmt.Sprintf("SEAL#%s", base64.StdEncoding.EncodeToString(dp))
	}
	return fmt.Sprintf("SEAL~%s", base64.StdEncoding.EncodeToString(dp))
}

func BuildSignature(uin uint64) string {
	ensureVerifyInitialized()
	decoded, err2 := hex.DecodeString(strings.TrimSpace(SealSignClientPrivateKey))
	if err2 != nil {
		return ""
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return ""
	}
	var msg [16]byte
	binary.BigEndian.PutUint64(msg[0:8], uin)
	binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().Unix()))

	sig := ed25519.Sign(decoded, msg[:])

	var sigPayload [80]byte
	copy(sigPayload[0:16], msg[:])
	copy(sigPayload[16:80], sig)

	return base64.StdEncoding.EncodeToString(sigPayload[:])
}
