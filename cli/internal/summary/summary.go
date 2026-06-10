// cli/internal/summary/summary.go
//
// Prints a formatted vulnerability summary table to stdout after the scan.
package summary

import (
	"fmt"
	"strings"

	"github.com/nqasanova/ssdlc-security-pipeline/cli/internal/runner"
)

// severityIcon maps severity levels to a visual indicator for the terminal.
func severityIcon(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "[CRIT]"
	case "HIGH":
		return "[HIGH]"
	case "MEDIUM":
		return "[MED] "
	case "LOW":
		return "[LOW] "
	default:
		return "[?]   "
	}
}

// Print renders the scan summary to stdout.
func Print(result *runner.Result) {
	if result == nil {
		return
	}

	r := result.Report
	div := strings.Repeat("─", 52)

	fmt.Println()
	fmt.Println("  " + div)
	fmt.Println("  SCAN SUMMARY")
	fmt.Println("  " + div)
	fmt.Printf("  Generated   : %s\n", r.Generated)
	fmt.Printf("  Total       : %d finding(s)\n", r.Total)
	fmt.Println("  " + div)

	// Severity breakdown
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		count := r.Summary[sev]
		bar := strings.Repeat("█", count)
		if count == 0 {
			bar = "·"
		}
		fmt.Printf("  %s  %-8s %s (%d)\n", severityIcon(sev), sev, bar, count)
	}

	fmt.Println("  " + div)

	// By-tool breakdown
	if len(r.ByTool) > 0 {
		fmt.Println("  By tool:")
		for tool, count := range r.ByTool {
			fmt.Printf("    %-12s %d\n", tool, count)
		}
		fmt.Println("  " + div)
	}

	// Top 5 highest-severity findings
	if len(r.Findings) > 0 {
		fmt.Println("  Top findings:")
		limit := 5
		if len(r.Findings) < limit {
			limit = len(r.Findings)
		}
		for i, f := range r.Findings[:limit] {
			cwe := ""
			if f.CWE != nil {
				cwe = fmt.Sprintf(" [CWE-%d]", *f.CWE)
			}
			fmt.Printf("  %2d. %s %-10s %s%s\n",
				i+1,
				severityIcon(f.Severity),
				f.RuleID,
				truncate(f.Message, 42),
				cwe,
			)
			fmt.Printf("      %s:%d\n", f.File, f.Line)
		}
		fmt.Println("  " + div)
	}

	// Output paths
	if result.ReportPath != "" {
		fmt.Printf("  Report      : %s\n", result.ReportPath)
	}
	if result.DashboardPath != "" {
		fmt.Printf("  Dashboard   : %s\n", result.DashboardPath)
	}
	fmt.Println("  " + div)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
