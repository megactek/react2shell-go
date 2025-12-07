package output

import (
	"io"

	"github.com/react2shell/scanner/pkg/models"
)

type Formatter interface {
	Format(result *models.ScanResult, w io.Writer) error
	FormatBatch(results []*models.ScanResult, w io.Writer) error
}

