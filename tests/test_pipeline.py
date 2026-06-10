"""
tests/test_pipeline.py
Unit tests for the SSDLC Security Pipeline components.
"""

import pytest
import json
import os
import tempfile
from filters.false_positive_filter import FalsePositiveFilter, DEFAULT_RULES
from reporter.report_generator import ReportGenerator
from scanner.metrics import MetricsTracker


# Fixtures

SAMPLE_FINDINGS = [
    {
        "tool": "bandit",
        "rule_id": "B311",
        "rule_name": "blacklist",
        "severity": "LOW",
        "confidence": "HIGH",
        "message": "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        "file": "sample_app/vulnerable_app.py",
        "line": 38,
        "code_snippet": "return random.choice(chars)",
        "cwe": 330,
        "more_info": "https://bandit.readthedocs.io/en/1.8.3/blacklists/blacklist_calls.html#bandit-B311-random",
    },
    {
        "tool": "bandit",
        "rule_id": "B608",
        "rule_name": "hardcoded_sql_expressions",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "message": "Possible SQL injection via string-based query construction.",
        "file": "sample_app/vulnerable_app.py",
        "line": 25,
        "code_snippet": "cursor.execute(query)",
        "cwe": 89,
        "more_info": "",
    },
    {
        "tool": "bandit",
        "rule_id": "B602",
        "rule_name": "subprocess_popen_with_shell_equals_true",
        "severity": "HIGH",
        "confidence": "HIGH",
        "message": "subprocess call with shell=True identified, security issue.",
        "file": "sample_app/vulnerable_app.py",
        "line": 46,
        "code_snippet": 'result = subprocess.run(f"echo {user_input}", shell=True)',
        "cwe": 78,
        "more_info": "",
    },
    {
        "tool": "bandit",
        "rule_id": "B101",
        "rule_name": "assert_used",
        "severity": "LOW",
        "confidence": "HIGH",
        "message": "Use of assert detected.",
        "file": "tests/test_something.py",
        "line": 10,
        "code_snippet": "assert result == expected",
        "cwe": None,
        "more_info": "",
    },
]


# FalsePositiveFilter tests

class TestFalsePositiveFilter:
    def _make_filter(self):
        """Create a filter using built-in default rules (no YAML file needed)."""
        fp = FalsePositiveFilter.__new__(FalsePositiveFilter)
        fp.rules = DEFAULT_RULES
        return fp

    def test_suppresses_test_file_finding(self):
        fp = self._make_filter()
        test_finding = {**SAMPLE_FINDINGS[3]}  # B101 in tests/
        assert fp._is_false_positive(test_finding), \
            "Findings in test files should be suppressed"

    def test_keeps_production_finding(self):
        fp = self._make_filter()
        prod_finding = {**SAMPLE_FINDINGS[2]}  # B602 in sample_app/
        assert not fp._is_false_positive(prod_finding), \
            "High-severity production findings must NOT be suppressed"

    def test_filter_removes_false_positives(self):
        fp = self._make_filter()
        confirmed = fp.filter(SAMPLE_FINDINGS)
        rule_ids = [f["rule_id"] for f in confirmed]
        assert "B101" not in rule_ids, "B101 from test file should be filtered"
        assert "B602" in rule_ids, "B602 should remain"

    def test_filter_preserves_count(self):
        fp = self._make_filter()
        confirmed = fp.filter(SAMPLE_FINDINGS)
        # At least one finding should be suppressed (B101 from test file)
        assert len(confirmed) < len(SAMPLE_FINDINGS)

    def test_file_pattern_glob(self):
        fp = self._make_filter()
        doc_finding = {
            **SAMPLE_FINDINGS[0],
            "file": "docs/example.py",
        }
        assert fp._is_false_positive(doc_finding)

    def test_rule_id_prefix_match(self):
        """B105, B106, B107 should all be caught by a B10 prefix rule."""
        fp = FalsePositiveFilter.__new__(FalsePositiveFilter)
        fp.rules = [{"description": "test", "rule_id": "B10"}]
        finding = {**SAMPLE_FINDINGS[0], "rule_id": "B105", "file": "anywhere.py"}
        assert fp._is_false_positive(finding)


# ReportGenerator tests

class TestReportGenerator:
    def test_markdown_report_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                findings=SAMPLE_FINDINGS[:3],
                output_dir=tmp,
                fmt="markdown"
            )
            gen.generate()
            assert os.path.exists(os.path.join(tmp, "vulnerability-report.md"))

    def test_json_report_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                findings=SAMPLE_FINDINGS[:3],
                output_dir=tmp,
                fmt="json"
            )
            gen.generate()
            path = os.path.join(tmp, "vulnerability-report.json")
            assert os.path.exists(path)
            with open(path) as fh:
                data = json.load(fh)
            assert data["total"] == 3

    def test_both_formats_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                findings=SAMPLE_FINDINGS[:3],
                output_dir=tmp,
                fmt="both"
            )
            gen.generate()
            assert os.path.exists(os.path.join(tmp, "vulnerability-report.md"))
            assert os.path.exists(os.path.join(tmp, "vulnerability-report.json"))

    def test_json_report_severity_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                findings=SAMPLE_FINDINGS[:3],
                output_dir=tmp,
                fmt="json"
            )
            gen.generate()
            with open(os.path.join(tmp, "vulnerability-report.json")) as fh:
                data = json.load(fh)
            assert data["summary"]["HIGH"] == 1
            assert data["summary"]["MEDIUM"] == 1
            assert data["summary"]["LOW"] == 1

    def test_empty_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(findings=[], output_dir=tmp, fmt="both")
            gen.generate()
            with open(os.path.join(tmp, "vulnerability-report.json")) as fh:
                data = json.load(fh)
            assert data["total"] == 0

    def test_findings_sorted_by_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                findings=SAMPLE_FINDINGS[:3],
                output_dir=tmp,
                fmt="json"
            )
            gen.generate()
            with open(os.path.join(tmp, "vulnerability-report.json")) as fh:
                data = json.load(fh)
            severities = [f["severity"] for f in data["findings"]]
            order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            scores = [order[s] for s in severities]
            assert scores == sorted(scores, reverse=True), \
                "Findings should be sorted from highest to lowest severity"



# MetricsTracker tests

class TestMetricsTracker:
    def test_record_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "metrics.json")
            tracker = MetricsTracker(metrics_file=path)
            tracker.record(SAMPLE_FINDINGS[:3])
            assert os.path.exists(path)

    def test_record_appends_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "metrics.json")
            tracker = MetricsTracker(metrics_file=path)
            tracker.record(SAMPLE_FINDINGS[:3])
            tracker.record(SAMPLE_FINDINGS[:1])
            history = tracker.load_history()
            assert len(history) == 2

    def test_record_correct_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "metrics.json")
            tracker = MetricsTracker(metrics_file=path)
            tracker.record(SAMPLE_FINDINGS[:3])
            history = tracker.load_history()
            assert history[0]["counts"]["total"] == 3
            assert history[0]["counts"]["HIGH"] == 1

    def test_load_history_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "metrics.json")
            tracker = MetricsTracker(metrics_file=path)
            assert tracker.load_history() == []
