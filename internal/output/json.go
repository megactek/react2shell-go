package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/react2shell/scanner/pkg/models"
)

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

type JSONOutput struct {
	Tool         string               `json:"tool"`
	Version      string               `json:"version"`
	CVEIDs       []string             `json:"cve_ids"`
	ScanTime     time.Time            `json:"scan_time"`
	TotalResults int                  `json:"total_results"`
	Results      []*models.ScanResult `json:"results"`
}

func (f *JSONFormatter) Format(result *models.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (f *JSONFormatter) FormatBatch(results []*models.ScanResult, w io.Writer) error {
	output := JSONOutput{
		Tool:         "React2Shell Ultimate CVE-2025-66478 Scanner",
		Version:      "1.1.0",
		CVEIDs:       []string{"CVE-2025-55182", "CVE-2025-66478"},
		ScanTime:     time.Now(),
		TotalResults: len(results),
		Results:      results,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
