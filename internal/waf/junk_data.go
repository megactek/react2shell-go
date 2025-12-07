package waf

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type JunkDataBypass struct {
	sizeKB int
}

func NewJunkDataBypass(sizeKB int) *JunkDataBypass {
	return &JunkDataBypass{sizeKB: sizeKB}
}

func (b *JunkDataBypass) Apply(payload string) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	paramName := make([]byte, 12)
	for i := range paramName {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		paramName[i] = charset[idx.Int64()]
	}

	size := b.sizeKB * 1024
	junk := make([]byte, size)
	const fullCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range junk {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(fullCharset))))
		junk[i] = fullCharset[idx.Int64()]
	}

	return fmt.Sprintf(
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"%s\"\r\n\r\n"+
			"%s\r\n%s",
		string(paramName), string(junk), payload,
	)
}

