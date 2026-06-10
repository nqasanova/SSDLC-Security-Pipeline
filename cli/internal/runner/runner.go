// cli/internal/runner/runner.go
//
// Invokes the Python SSDLC pipeline as a subprocess and parses
// the JSON report it produces into a structured Result.
package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config holds all CLI flags passed through to the Python pipeline.
type Config struct {
	Target      string
	Tools       []string
	OutputDir   string
	Severity    string
	FailOn      string
	Format      string
	FPConfig    string
	NoDashboard bool
}

// Finding mirrors the normalized finding schema from the Python scanner.
type Finding struct {
	Tool        string `json:"tool"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	CodeSnippet string `json:"code_snippet"`
	CWE         *int   `json:"cwe"`
	MoreInfo    string `json:"more_info"`
}

// Report mirrors the JSON report structure written by reporter/report_generator.py.
type Report struct {
	Generated string            `json:"generated"`
	Total     int               `json:"total"`
	Summary   map[string]int    `json:"summary"`
	ByTool    map[string]int    `json:"by_tool"`
	Findings  []Finding         `json:"findings"`
}

// Result is what the CLI uses after parsing the report.
type Result struct {
	Report           Report
	BlockingFindings int
	FailOn           string
	ReportPath       string
	DashboardPath    string
}

// Runner builds and executes the pipeline command.
type Runner struct {
	cfg Config
}

// New creates a new Runner.
func New(cfg Config) *Runner {
	return &Runner{cfg: cfg}
}

// Run executes the Python pipeline and returns a parsed Result.
func (r *Runner) Run() (*Result, error) {
	args := r.buildArgs()

	fmt.Printf("[*] Invoking Python pipeline...\n")
	fmt.Printf("    python %s\n\n", strings.Join(args, " "))

	cmd := exec.Command("python", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// We intentionally ignore the exit code here and read the JSON report ourselves - the Go CLI owns the final exit code decision.
	_ = cmd.Run()

	// Parse the JSON report produced by the Python pipeline
	reportPath := filepath.Join(r.cfg.OutputDir, "vulnerability-report.json")
	report, err := parseReport(reportPath)
	if err != nil {
		// If JSON report doesn't exist (e.g. no tools installed), return empty
		fmt.Printf("[!] Could not read JSON report (%v) — returning empty result\n", err)
		return &Result{FailOn: r.cfg.FailOn}, nil
	}

	blocking := countBlocking(report.Findings, r.cfg.FailOn)

	dashPath := filepath.Join(r.cfg.OutputDir, "dashboard.html")
	if r.cfg.NoDashboard {
		dashPath = ""
	}

	return &Result{
		Report:           *report,
		BlockingFindings: blocking,
		FailOn:           r.cfg.FailOn,
		ReportPath:       reportPath,
		DashboardPath:    dashPath,
	}, nil
}

// buildArgs constructs the argument list for main.py.
func (r *Runner) buildArgs() []string {
	args := []string{
		"main.py",
		"--target", r.cfg.Target,
		"--tools",
	}
	args = append(args, r.cfg.Tools...)
	args = append(args,
		"--output-dir", r.cfg.OutputDir,
		"--severity", r.cfg.Severity,
		"--fail-on", strings.ToLower(r.cfg.FailOn),
		"--format", r.cfg.Format,
		"--fp-config", r.cfg.FPConfig,
	)
	if r.cfg.NoDashboard {
		args = append(args, "--no-dashboard")
	}
	return args
}

func parseReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return &report, nil
}

// severityLevel maps severity strings to comparable integers.
func severityLevel(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// countBlocking returns the number of findings at or above the fail-on threshold.
func countBlocking(findings []Finding, failOn string) int {
	if strings.ToUpper(failOn) == "NONE" {
		return 0
	}
	threshold := severityLevel(failOn)
	count := 0
	for _, f := range findings {
		if severityLevel(f.Severity) >= threshold {
			count++
		}
	}
	return count
}
