package payload

const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

type SafeBuilder struct{}

func NewSafeBuilder() *SafeBuilder {
	return &SafeBuilder{}
}

func (b *SafeBuilder) Build() Payload {
	body := "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
		"Content-Disposition: form-data; name=\"1\"\r\n\r\n" +
		"{}\r\n" +
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
		"Content-Disposition: form-data; name=\"0\"\r\n\r\n" +
		"[\"$1:aa:aa\"]\r\n" +
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"

	return Payload{
		Body:        body,
		ContentType: "multipart/form-data; boundary=" + boundary,
	}
}

