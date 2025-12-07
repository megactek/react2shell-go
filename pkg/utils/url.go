package utils

import (
	"strings"
)

func NormalizeURL(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return strings.TrimSuffix(url, "/")
}

