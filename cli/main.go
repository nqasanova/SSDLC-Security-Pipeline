// cli/main.go
//
// ssdlc-scan — a Go CLI wrapper for the SSDLC Security Pipeline.
//
// Usage:
//
//	ssdlc-scan [flags]
//
// Examples:
//
//	ssdlc-scan --target ./myproject
//	ssdlc-scan --target . --tools bandit --fail-on HIGH
//	ssdlc-scan --target . --no-dashboard --format json
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nqasanova/ssdlc-security-pipeline/cli/internal/runner"
	"github.com/nqasanova/ssdlc-security-pipeline/cli/internal/summary"
)

const version = "1.0.0"

const banner = `
╔══════════════════════════════════════════════╗
║         SSDLC Security Pipeline CLI          ║
║              Go wrapper v%s               ║
╚══════════════════════════════════════════════╝
`

func main() {
	// ── Flags ────────────────────────────────────────────────────────────
	target      := flag.String("target",      ".",            "Target directory to scan")
	tools       := flag.String("tools",       "all",          "Comma-separated tools: bandit,semgrep,all")
	outputDir   := flag.String("output-dir",  "security-reports", "Output directory for reports")
	severity    := flag.String("severity",    "LOW",          "Minimum severity to include: LOW|MEDIUM|HIGH|CRITICAL")
	failOn      := flag.String("fail-on",     "HIGH",         "Exit non-zero if findings at this level exist: LOW|MEDIUM|HIGH|CRITICAL|none")
	format      := flag.String("format",      "both",         "Report format: markdown|json|both")
	fpConfig    := flag.String("fp-config",   "filters/fp_rules.yaml", "Path to false-positive rules YAML")
	noDashboard := flag.Bool("no-dashboard",  false,          "Skip HTML dashboard generation")
	showVersion := flag.Bool("version",       false,          "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ssdlc-scan version %s\n", version)
		os.Exit(0)
	}

	fmt.Printf(banner, version)

	// ── Validate inputs ───────────────────────────────────────────────────
	if err := validateSeverity(*severity); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid --severity: %v\n", err)
		os.Exit(2)
	}
	if err := validateFailOn(*failOn); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid --fail-on: %v\n", err)
		os.Exit(2)
	}
	if _, err := os.Stat(*target); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[!] Target directory does not exist: %s\n", *target)
		os.Exit(2)
	}

	// ── Build config ──────────────────────────────────────────────────────
	cfg := runner.Config{
		Target:      *target,
		Tools:       strings.Split(*tools, ","),
		OutputDir:   *outputDir,
		Severity:    strings.ToUpper(*severity),
		FailOn:      strings.ToUpper(*failOn),
		Format:      *format,
		FPConfig:    *fpConfig,
		NoDashboard: *noDashboard,
	}

	printConfig(cfg)

	// ── Run the Python pipeline via subprocess ────────────────────────────
	r := runner.New(cfg)
	result, err := r.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Pipeline execution error: %v\n", err)
		os.Exit(1)
	}

	// ── Print summary ──────────────────────────────────────────────────────
	summary.Print(result)

	// ── Exit code for CI/CD ────────────────────────────────────────────────
	if result.BlockingFindings > 0 {
		fmt.Fprintf(os.Stderr,
			"\n[✗] PIPELINE BLOCKED: %d finding(s) at or above %s severity.\n",
			result.BlockingFindings, cfg.FailOn,
		)
		os.Exit(1)
	}

	fmt.Println("\n[✓] Security scan complete. No blocking issues found.")
	os.Exit(0)
}

func printConfig(cfg runner.Config) {
	fmt.Println("  Configuration")
	fmt.Println("  " + strings.Repeat("─", 42))
	fmt.Printf("  Target      : %s\n", cfg.Target)
	fmt.Printf("  Tools       : %s\n", strings.Join(cfg.Tools, ", "))
	fmt.Printf("  Min severity: %s\n", cfg.Severity)
	fmt.Printf("  Fail on     : %s\n", cfg.FailOn)
	fmt.Printf("  Output dir  : %s\n", cfg.OutputDir)
	fmt.Printf("  Format      : %s\n", cfg.Format)
	fmt.Printf("  Dashboard   : %v\n", !cfg.NoDashboard)
	fmt.Println("  " + strings.Repeat("─", 42))
	fmt.Println()
}

func validateSeverity(s string) error {
	valid := map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	if !valid[strings.ToUpper(s)] {
		return fmt.Errorf("must be one of LOW, MEDIUM, HIGH, CRITICAL — got %q", s)
	}
	return nil
}

func validateFailOn(s string) error {
	valid := map[string]bool{
		"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true, "NONE": true,
	}
	if !valid[strings.ToUpper(s)] {
		return fmt.Errorf("must be one of LOW, MEDIUM, HIGH, CRITICAL, none — got %q", s)
	}
	return nil
}
