package client

import (
	"context"
	"io"
	"net/http"
)

type HTTPClient interface {
	Get(ctx context.Context, url string, headers map[string]string) (*http.Response, error)
	Post(ctx context.Context, url string, headers map[string]string, body io.Reader) (*http.Response, error)
}
