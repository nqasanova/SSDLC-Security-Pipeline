// cli/internal/runner/runner_test.go
package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ── severityLevel tests ────────────────────────────────────────────────────

func TestSeverityLevel(t *testing.T) {
	cases := []struct {
		input    string
		expected int
	}{
		{"CRITICAL", 4},
		{"HIGH", 3},
		{"MEDIUM", 2},
		{"LOW", 1},
		{"critical", 4}, // case insensitive
		{"unknown", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := severityLevel(tc.input)
		if got != tc.expected {
			t.Errorf("severityLevel(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

// ── countBlocking tests ───────────────────────────────────────────────────

func TestCountBlocking_HighThreshold(t *testing.T) {
	findings := []Finding{
		{Severity: "LOW"},
		{Severity: "MEDIUM"},
		{Severity: "HIGH"},
		{Severity: "CRITICAL"},
	}
	got := countBlocking(findings, "HIGH")
	if got != 2 {
		t.Errorf("expected 2 blocking findings (HIGH+CRITICAL), got %d", got)
	}
}

func TestCountBlocking_NoneThreshold(t *testing.T) {
	findings := []Finding{
		{Severity: "HIGH"},
		{Severity: "CRITICAL"},
	}
	got := countBlocking(findings, "none")
	if got != 0 {
		t.Errorf("expected 0 blocking findings for threshold=none, got %d", got)
	}
}

func TestCountBlocking_CriticalOnly(t *testing.T) {
	findings := []Finding{
		{Severity: "LOW"},
		{Severity: "MEDIUM"},
		{Severity: "HIGH"},
		{Severity: "CRITICAL"},
	}
	got := countBlocking(findings, "CRITICAL")
	if got != 1 {
		t.Errorf("expected 1 blocking finding, got %d", got)
	}
}

func TestCountBlocking_EmptyFindings(t *testing.T) {
	got := countBlocking([]Finding{}, "HIGH")
	if got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

// ── buildArgs tests ───────────────────────────────────────────────────────

func TestBuildArgs_ContainsTarget(t *testing.T) {
	r := New(Config{
		Target:    "./myproject",
		Tools:     []string{"bandit"},
		OutputDir: "reports",
		Severity:  "MEDIUM",
		FailOn:    "HIGH",
		Format:    "json",
		FPConfig:  "filters/fp_rules.yaml",
	})
	args := r.buildArgs()

	assertContains(t, args, "--target")
	assertContains(t, args, "./myproject")
	assertContains(t, args, "--severity")
	assertContains(t, args, "MEDIUM")
	assertContains(t, args, "--fail-on")
}

func TestBuildArgs_NoDashboardFlag(t *testing.T) {
	r := New(Config{
		Target:      ".",
		Tools:       []string{"all"},
		OutputDir:   "reports",
		Severity:    "LOW",
		FailOn:      "HIGH",
		Format:      "both",
		FPConfig:    "filters/fp_rules.yaml",
		NoDashboard: true,
	})
	args := r.buildArgs()
	assertContains(t, args, "--no-dashboard")
}

func TestBuildArgs_DashboardNotSuppressedByDefault(t *testing.T) {
	r := New(Config{
		Target:      ".",
		Tools:       []string{"all"},
		OutputDir:   "reports",
		Severity:    "LOW",
		FailOn:      "HIGH",
		Format:      "both",
		FPConfig:    "filters/fp_rules.yaml",
		NoDashboard: false,
	})
	args := r.buildArgs()
	for _, a := range args {
		if a == "--no-dashboard" {
			t.Error("--no-dashboard should not be present when NoDashboard=false")
		}
	}
}

// ── parseReport tests ─────────────────────────────────────────────────────

func TestParseReport_ValidJSON(t *testing.T) {
	tmp := t.TempDir()
	report := Report{
		Generated: "2025-01-01 00:00 UTC",
		Total:     2,
		Summary:   map[string]int{"HIGH": 1, "LOW": 1},
		ByTool:    map[string]int{"bandit": 2},
		Findings: []Finding{
			{Tool: "bandit", RuleID: "B602", Severity: "HIGH"},
			{Tool: "bandit", RuleID: "B311", Severity: "LOW"},
		},
	}
	data, _ := json.Marshal(report)
	path := filepath.Join(tmp, "vulnerability-report.json")
	os.WriteFile(path, data, 0644)

	parsed, err := parseReport(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Total != 2 {
		t.Errorf("expected Total=2, got %d", parsed.Total)
	}
	if len(parsed.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(parsed.Findings))
	}
}

func TestParseReport_MissingFile(t *testing.T) {
	_, err := parseReport("/nonexistent/path/report.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseReport_InvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad.json")
	os.WriteFile(path, []byte("not valid json {{{"), 0644)
	_, err := parseReport(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func assertContains(t *testing.T, slice []string, item string) {
	t.Helper()
	for _, s := range slice {
		if s == item {
			return
		}
	}
	t.Errorf("expected %q in args %v", item, slice)
}
