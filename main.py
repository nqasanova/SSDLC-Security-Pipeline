#!/usr/bin/env python3
"""
SSDLC Security Pipeline - Main CLI Entry Point
Runs security scans, filters false positives, and generates reports/dashboards.
"""

import argparse
import sys
import os
from scanner.runner import ScannerRunner
from reporter.report_generator import ReportGenerator
from dashboard.dashboard_generator import DashboardGenerator
from filters.false_positive_filter import FalsePositiveFilter
from scanner.metrics import MetricsTracker


def parse_args():
    parser = argparse.ArgumentParser(
        description="SSDLC Security Pipeline - Automated vulnerability scanning and reporting"
    )
    parser.add_argument(
        "--target",
        type=str,
        default=".",
        help="Target directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=["bandit", "semgrep", "all"],
        default=["all"],
        help="Security tools to run (default: all)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="security-reports",
        help="Output directory for reports and dashboard (default: security-reports)"
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity to include in report (default: LOW)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "none"],
        default="HIGH",
        help="Exit with error code if issues of this severity or above are found (default: HIGH)"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip HTML dashboard generation"
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "both"],
        default="both",
        help="Report output format (default: both)"
    )
    parser.add_argument(
        "--fp-config",
        type=str,
        default="filters/fp_rules.yaml",
        help="Path to false positive rules config (default: filters/fp_rules.yaml)"
    )
    parser.add_argument(
        "--metrics-file",
        type=str,
        default="security-reports/metrics_history.json",
        help="Path to metrics history file for trend tracking"
    )
    return parser.parse_args()


def severity_level(s: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(s.upper(), 0)


def main():
    args = parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("\n" + "="*60)
    print("  SSDLC Security Pipeline")
    print("="*60)
    print(f"  Target   : {args.target}")
    print(f"  Tools    : {args.tools}")
    print(f"  Min sev  : {args.severity}")
    print(f"  Fail on  : {args.fail_on}")
    print(f"  Output   : {args.output_dir}")
    print("="*60 + "\n")

    # 1. Run scanners
    runner = ScannerRunner(target=args.target, tools=args.tools)
    raw_findings = runner.run()
    print(f"[+] Raw findings collected: {len(raw_findings)}")

    # 2. Filter false positives
    fp_filter = FalsePositiveFilter(config_path=args.fp_config)
    findings = fp_filter.filter(raw_findings)
    filtered_count = len(raw_findings) - len(findings)
    print(f"[+] False positives removed: {filtered_count}")
    print(f"[+] Confirmed findings     : {len(findings)}")

    # 3. Apply minimum severity filter
    findings = [
        f for f in findings
        if severity_level(f.get("severity", "LOW")) >= severity_level(args.severity)
    ]
    print(f"[+] Findings after severity filter: {len(findings)}")

    # 4. Track metrics history
    tracker = MetricsTracker(metrics_file=args.metrics_file)
    tracker.record(findings)
    metrics = tracker.load_history()

    # 5. Generate reports
    generator = ReportGenerator(
        findings=findings,
        output_dir=args.output_dir,
        fmt=args.format
    )
    generator.generate()
    print(f"[+] Reports written to: {args.output_dir}/")

    # 6. Generate HTML dashboard
    if not args.no_dashboard:
        dash = DashboardGenerator(
            findings=findings,
            metrics_history=metrics,
            output_dir=args.output_dir
        )
        dash.generate()
        print(f"[+] Dashboard written to: {args.output_dir}/dashboard.html")

    # 7. Exit code for CI/CD enforcement
    if args.fail_on != "none":
        critical_findings = [
            f for f in findings
            if severity_level(f.get("severity", "LOW")) >= severity_level(args.fail_on)
        ]
        if critical_findings:
            print(
                f"\n[!] PIPELINE FAILED: {len(critical_findings)} finding(s) "
                f"at or above {args.fail_on} severity."
            )
            sys.exit(1)

    print("\n[✓] Security scan complete. No blocking issues found.\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
