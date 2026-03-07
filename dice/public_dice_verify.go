package dice

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/vmihailenco/msgpack"

	"Scardice-core/utils/crypto"
)

var (
	// SealTrustedClientPrivateKey 可信客户端私钥，可通过 -ldflags -X 注入
	SealTrustedClientPrivateKey = ""
)

type payloadPublicDice struct {
	Version string `msgpack:"version,omitempty"`
	Sign    []byte `msgpack:"sign,omitempty"`
}

// GenerateVerificationKeyForPublicDice 生成公骰请求校验字段。
// 若环境变量 SEAL_TRUSTED_PRIVATE_KEY 存在，则使用 ECDSA 私钥签名并返回 "SEAL#..."；
// 否则退化为 SHA256 摘要并返回 "SEAL~..."
func GenerateVerificationKeyForPublicDice(data any) string {
	privateKey := os.Getenv("SEAL_TRUSTED_PRIVATE_KEY")
	if privateKey == "" {
		privateKey = SealTrustedClientPrivateKey
	}
	privateKey = strings.ReplaceAll(privateKey, `\n`, "\n")

	pp, _ := msgpack.Marshal(data)

	var sign []byte
	if privateKey != "" {
		var err error
		sign, err = crypto.EcdsaSignRow(pp, privateKey)
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
	if privateKey != "" {
		return fmt.Sprintf("SEAL#%s", base64.StdEncoding.EncodeToString(dp))
	}
	return fmt.Sprintf("SEAL~%s", base64.StdEncoding.EncodeToString(dp))
}
