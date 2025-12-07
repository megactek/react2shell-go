package waf

type VercelBypass struct{}

func NewVercelBypass() *VercelBypass {
	return &VercelBypass{}
}

func (b *VercelBypass) Apply(payload string) string {
	return payload
}

