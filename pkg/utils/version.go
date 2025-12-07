package utils

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/react2shell/scanner/pkg/models"
)

var versionRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-canary\.(\d+))?$`)

func ParseVersion(version string) models.VersionInfo {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	
	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) < 4 {
		return models.VersionInfo{}
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	
	isCanary := strings.Contains(strings.ToLower(version), "canary")
	canaryNum := 0
	if len(matches) > 4 && matches[4] != "" {
		canaryNum, _ = strconv.Atoi(matches[4])
	}

	return models.VersionInfo{
		Major:     major,
		Minor:     minor,
		Patch:     patch,
		IsCanary:  isCanary,
		CanaryNum: canaryNum,
	}
}

var patchedVersions = map[int]map[int]int{
	15: {0: 5, 1: 9, 2: 6, 3: 6, 4: 8, 5: 7},
	16: {0: 7},
}

func IsVulnerable(version string) (bool, string) {
	vi := ParseVersion(version)
	if vi.Major == 0 {
		return false, "Unable to parse version"
	}

	if vi.Major == 16 {
		if vi.Minor == 0 && vi.Patch >= 7 {
			return false, "Patched in 16.0.7+"
		}
		if vi.Minor > 0 {
			return false, "16.x is patched"
		}
		return true, "16.0.0-16.0.6 are vulnerable"
	}

	if vi.Major == 15 {
		if minorPatches, exists := patchedVersions[15]; exists {
			if patchedPatch, exists := minorPatches[vi.Minor]; exists {
				if vi.Patch >= patchedPatch {
					return false, "Patched in 15.x.x+"
				}
			}
		}
		return true, "15.x without patch is vulnerable"
	}

	if vi.Major == 14 && vi.IsCanary {
		if vi.Minor > 3 {
			return true, "14.x canary (minor > 3) is vulnerable"
		}
		if vi.Minor == 3 && vi.Patch == 0 && vi.CanaryNum >= 77 {
			return true, "14.3.0-canary.77+ is vulnerable"
		}
		if vi.Minor == 3 && vi.Patch > 0 {
			return true, "14.3.x canary is vulnerable"
		}
		return false, "Pre-vulnerability canary version"
	}

	return false, "Version not affected"
}

