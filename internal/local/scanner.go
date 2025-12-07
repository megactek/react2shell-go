package local

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/react2shell/scanner/pkg/models"
	"github.com/react2shell/scanner/pkg/utils"
)

func ScanLocalProject(path string) ([]*models.ScanResult, error) {
	var results []*models.ScanResult

	lockfiles := []string{
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"bun.lockb",
	}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() && strings.Contains(filePath, "node_modules") {
			return filepath.SkipDir
		}

		fileName := info.Name()
		for _, lockfile := range lockfiles {
			if fileName == lockfile {
				version := extractVersion(filePath, lockfile)
				if version != "" {
					result := &models.ScanResult{
						URL:             filePath,
						Version:         version,
						DetectionMethod: "local_lockfile",
						Timestamp:       time.Now(),
					}
					vuln, _ := utils.IsVulnerable(version)
					result.Vulnerable = &vuln
					results = append(results, result)
				}
			}
		}

		return nil
	})

	return results, err
}

func extractVersion(filePath, lockfile string) string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	text := string(content)

	switch lockfile {
	case "package.json":
		re := regexp.MustCompile(`"next"\s*:\s*"([^"]+)"`)
		matches := re.FindStringSubmatch(text)
		if len(matches) > 1 {
			version := matches[1]
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			return version
		}

	case "package-lock.json":
		re := regexp.MustCompile(`"next"[^}]*"version"\s*:\s*"([^"]+)"`)
		matches := re.FindStringSubmatch(text)
		if len(matches) > 1 {
			return matches[1]
		}

	case "yarn.lock":
		re := regexp.MustCompile(`next@[^:]+:\s*\n\s*version\s+"([^"]+)"`)
		matches := re.FindStringSubmatch(text)
		if len(matches) > 1 {
			return matches[1]
		}

	case "pnpm-lock.yaml":
		re := regexp.MustCompile(`next@([0-9.]+(?:-canary\.\d+)?)`)
		matches := re.FindStringSubmatch(text)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}
