package scanner

import (
	"github.com/react2shell/scanner/pkg/utils"
)

func CheckVulnerability(version string) (bool, string) {
	return utils.IsVulnerable(version)
}

