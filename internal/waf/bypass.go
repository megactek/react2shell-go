package waf

type BypassStrategy interface {
	Apply(payload string) string
}

