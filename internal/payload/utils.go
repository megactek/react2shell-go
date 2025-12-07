package payload

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

func generateJunkData(sizeKB int) (string, string) {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	paramName := make([]byte, 12)
	for i := range paramName {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		paramName[i] = charset[idx.Int64()]
	}

	size := sizeKB * 1024
	junk := make([]byte, size)
	const fullCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range junk {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(fullCharset))))
		junk[i] = fullCharset[idx.Int64()]
	}

	return string(paramName), string(junk)
}

func encodeUnicode(data string) string {
	var result strings.Builder
	inString := false

	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '"' {
			inString = !inString
			result.WriteByte(c)
		} else if !inString {
			result.WriteByte(c)
		} else if c == '\\' && i+1 < len(data) {
			result.WriteByte(c)
			result.WriteByte(data[i+1])
			i++
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", c))
		}
	}

	return result.String()
}

