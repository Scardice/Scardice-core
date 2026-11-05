package eventstore

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
)

// Digest 计算带域前缀的无密钥 SHA-256(32 字节)。
// 输入为"定长前缀的 domain + 定长前缀的各 part",拼接后不会产生歧义。
func Digest(domain string, parts ...string) []byte {
	h := sha256.New()
	writeDigestField(h, domain)
	for _, part := range parts {
		writeDigestField(h, part)
	}
	return h.Sum(nil)
}

// DigestBytes 与 Digest 相同,但负载是原始字节,避免转成字符串。
func DigestBytes(domain string, payload []byte) []byte {
	h := sha256.New()
	writeDigestField(h, domain)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(payload)
	return h.Sum(nil)
}

func writeDigestField(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = io.WriteString(h, value)
}
