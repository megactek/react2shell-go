package models

import "time"

type ScanResult struct {
	URL             string    `json:"url"`
	Vulnerable      *bool     `json:"vulnerable,omitempty"`
	Version         string    `json:"version,omitempty"`
	StatusCode      int       `json:"status_code,omitempty"`
	DetectionMethod string    `json:"detection_method,omitempty"`
	WAFDetected     bool      `json:"waf_detected"`
	WAFBypassed     bool      `json:"waf_bypassed"`
	Error           string    `json:"error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	RawResponse     string    `json:"raw_response,omitempty"`
}

type ScanOptions struct {
	Windows          bool
	WAFBypass        bool
	WAFBypassSizeKB  int
	UnicodeEncode    bool
	VercelBypass     bool
	Timeout          int
	VerifySSL        bool
	Proxy            string
	UserAgent        string
}

type ScanMode int

const (
	ModeVersion ScanMode = iota
	ModeSafe
	ModeRCE
	ModeComprehensive
)

type VersionInfo struct {
	Major    int
	Minor    int
	Patch    int
	IsCanary bool
	CanaryNum int
}

