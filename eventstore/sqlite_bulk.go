package eventstore

import (
	"encoding/hex"
	"strconv"
	"strings"
)

func writeSQLiteBlobLiteral(query *strings.Builder, value []byte) {
	if value == nil {
		query.WriteString("NULL")
		return
	}
	query.WriteString("X'")
	var encoded [1024]byte
	for len(value) != 0 {
		size := min(len(value), len(encoded)/2)
		hex.Encode(encoded[:size*2], value[:size])
		query.Write(encoded[:size*2])
		value = value[size:]
	}
	query.WriteByte('\'')
}

func writeSQLiteTextLiteral(query *strings.Builder, value string) {
	const digits = "0123456789abcdef"
	query.WriteString("CAST(X'")
	for index := range len(value) {
		current := value[index]
		query.WriteByte(digits[current>>4])
		query.WriteByte(digits[current&0x0f])
	}
	query.WriteString("' AS TEXT)")
}

func writeSQLiteUint(query *strings.Builder, value uint64) {
	var encoded [20]byte
	query.Write(strconv.AppendUint(encoded[:0], value, 10))
}

func writeSQLiteInt(query *strings.Builder, value int64) {
	var encoded [20]byte
	query.Write(strconv.AppendInt(encoded[:0], value, 10))
}
