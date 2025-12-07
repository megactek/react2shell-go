package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/react2shell/scanner/pkg/models"
)

const (
	colorReset  = "\033[0m"
	colorRed     = "\033[91m"
	colorGreen   = "\033[92m"
	colorYellow  = "\033[93m"
	colorBlue    = "\033[94m"
	colorMagenta = "\033[95m"
	colorCyan    = "\033[96m"
	colorWhite   = "\033[97m"
	colorBold    = "\033[1m"
)

type ConsoleFormatter struct {
	verbose bool
	color   bool
}

func NewConsoleFormatter(verbose, color bool) *ConsoleFormatter {
	return &ConsoleFormatter{
		verbose: verbose,
		color:   color,
	}
}

func (f *ConsoleFormatter) colorize(text, color string) string {
	if !f.color {
		return text
	}
	return color + text + colorReset
}

func (f *ConsoleFormatter) Format(result *models.ScanResult, w io.Writer) error {
	var status string
	if result.Vulnerable != nil {
		if *result.Vulnerable {
			status = f.colorize("[VULNERABLE]", colorRed+colorBold)
		} else {
			status = f.colorize("[NOT VULNERABLE]", colorGreen)
		}
	} else if result.WAFDetected {
		status = f.colorize("[WAF BLOCKED]", colorYellow)
	} else if result.Error != "" {
		status = f.colorize("[ERROR]", colorYellow)
	} else {
		status = f.colorize("[UNKNOWN]", colorBlue)
	}

	versionStr := result.Version
	if versionStr == "" {
		versionStr = "N/A"
	}

	statusCodeStr := "-"
	if result.StatusCode > 0 {
		statusCodeStr = fmt.Sprintf("%d", result.StatusCode)
	}

	fmt.Fprintf(w, "%s %s\n", status, result.URL)
	fmt.Fprintf(w, "    Version: %s | Status: %s | Method: %s\n",
		versionStr, statusCodeStr, result.DetectionMethod)

	if result.WAFBypassed {
		fmt.Fprintf(w, "    %s\n", f.colorize("WAF Bypass: SUCCESS", colorMagenta))
	} else if result.WAFDetected {
		fmt.Fprintf(w, "    %s\n", f.colorize("WAF Detected: Exploit blocked", colorYellow))
	}

	if result.Error != "" {
		fmt.Fprintf(w, "    %s\n", f.colorize(fmt.Sprintf("Error: %s", result.Error), colorYellow))
	}

	if f.verbose && result.RawResponse != "" {
		fmt.Fprintf(w, "    %s\n", f.colorize("Response snippet:", colorCyan))
		lines := strings.Split(result.RawResponse, "\n")
		maxLines := 5
		if len(lines) < maxLines {
			maxLines = len(lines)
		}
		for i := 0; i < maxLines; i++ {
			line := lines[i]
			if len(line) > 100 {
				line = line[:100]
			}
			fmt.Fprintf(w, "      %s\n", line)
		}
	}

	fmt.Fprintln(w)
	return nil
}

func (f *ConsoleFormatter) FormatBatch(results []*models.ScanResult, w io.Writer) error {
	for _, result := range results {
		if err := f.Format(result, w); err != nil {
			return err
		}
	}
	return nil
}

