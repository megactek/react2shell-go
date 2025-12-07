package waf

import (
	"fmt"
	"strings"
)

type UnicodeBypass struct{}

func NewUnicodeBypass() *UnicodeBypass {
	return &UnicodeBypass{}
}

func (b *UnicodeBypass) Apply(payload string) string {
	var result strings.Builder
	inString := false

	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c == '"' {
			inString = !inString
			result.WriteByte(c)
		} else if !inString {
			result.WriteByte(c)
		} else if c == '\\' && i+1 < len(payload) {
			result.WriteByte(c)
			result.WriteByte(payload[i+1])
			i++
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", c))
		}
	}

	return result.String()
}

