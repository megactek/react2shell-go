package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type httpClient struct {
	client  *http.Client
	timeout time.Duration
}

func NewHTTPClient(timeout int, verifySSL bool, proxyURL string) HTTPClient {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifySSL,
		},
	}

	if proxyURL != "" {
		parsedProxy, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsedProxy)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	return &httpClient{
		client:  client,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (c *httpClient) Get(ctx context.Context, reqURL string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (c *httpClient) Post(ctx context.Context, reqURL string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}
