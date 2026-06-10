"""
reporter/report_generator.py
Generates Markdown and JSON vulnerability reports from confirmed findings.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class ReportGenerator:
    def __init__(self, findings: List[Dict[str, Any]], output_dir: str, fmt: str):
        self.findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "LOW").upper(), 0),
            reverse=True,
        )
        self.output_dir = output_dir
        self.fmt = fmt
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def generate(self) -> None:
        if self.fmt in ("markdown", "both"):
            self._write_markdown()
        if self.fmt in ("json", "both"):
            self._write_json()

    # Markdown report
    def _write_markdown(self) -> None:
        path = os.path.join(self.output_dir, "vulnerability-report.md")
        lines = []

        lines.append("# 🔒 SSDLC Security Scan Report")
        lines.append(f"\n**Generated:** {self.timestamp}  ")
        lines.append(f"**Total findings:** {len(self.findings)}\n")

        # Summary table
        counts = self._count_by_severity()
        lines.append("## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev} | {counts.get(sev, 0)} |")
        lines.append("")

        # By-tool breakdown
        by_tool = self._count_by_tool()
        lines.append("## Findings by Tool\n")
        lines.append("| Tool | Count |")
        lines.append("|------|-------|")
        for tool, count in sorted(by_tool.items()):
            lines.append(f"| {tool} | {count} |")
        lines.append("")

        # Detailed findings
        lines.append("## Findings\n")
        if not self.findings:
            lines.append("✅ No confirmed findings after false-positive filtering.\n")
        else:
            for i, f in enumerate(self.findings, start=1):
                sev = f.get("severity", "LOW").upper()
                emoji = SEVERITY_EMOJI.get(sev, "")
                lines.append(f"### {i}. {emoji} [{sev}] {f.get('rule_name', f.get('rule_id', 'Unknown'))}")
                lines.append(f"\n**Tool:** `{f.get('tool', 'unknown')}`  ")
                lines.append(f"**Rule ID:** `{f.get('rule_id', 'N/A')}`  ")
                lines.append(f"**File:** `{f.get('file', 'N/A')}` (line {f.get('line', '?')})  ")
                if f.get("cwe"):
                    lines.append(f"**CWE:** CWE-{f['cwe']}  ")
                lines.append(f"**Confidence:** {f.get('confidence', 'MEDIUM')}  \n")
                lines.append(f"**Description:** {f.get('message', 'No description')}  \n")
                snippet = f.get("code_snippet", "")
                if snippet:
                    lines.append("**Code:**")
                    lines.append("```python")
                    lines.append(snippet)
                    lines.append("```")
                if f.get("more_info"):
                    lines.append(f"\n📖 [More info]({f['more_info']})\n")
                lines.append("---\n")

        lines.append("## Remediation Guidelines\n")
        lines.append(self._remediation_section())

        with open(path, "w") as fh:
            fh.write("\n".join(lines))
        print(f"  [report] Markdown report → {path}")

    def _remediation_section(self) -> str:
        seen_rules = {f.get("rule_id", "") for f in self.findings}
        tips = []

        if any(r.startswith("B3") for r in seen_rules):
            tips.append(
                "- **Insecure randomness (B3xx):** Use `secrets` module instead of `random` "
                "for security-sensitive operations (tokens, passwords, session IDs)."
            )
        if "B501" in seen_rules or "B502" in seen_rules or "B503" in seen_rules:
            tips.append(
                "- **Weak SSL/TLS:** Enforce TLS 1.2+ and strong cipher suites. "
                "Never disable certificate verification."
            )
        if "B608" in seen_rules:
            tips.append(
                "- **SQL injection (B608):** Use parameterized queries or ORM abstractions. "
                "Never interpolate user input directly into SQL strings."
            )
        if "B105" in seen_rules or "B106" in seen_rules or "B107" in seen_rules:
            tips.append(
                "- **Hardcoded credentials:** Store secrets in environment variables or a secrets "
                "manager (e.g., HashiCorp Vault, AWS Secrets Manager). "
                "Never commit credentials to source control."
            )
        if not tips:
            tips.append("- No specific remediation tips for current finding set.")

        tips.append(
            "\n**General secure coding practices:**\n"
            "- Validate and sanitize all external inputs.\n"
            "- Apply the principle of least privilege for file and network access.\n"
            "- Keep dependencies up to date and scan with `pip audit` / `npm audit`.\n"
            "- Enable and review security linter warnings in your IDE.\n"
            "- Follow [OWASP Top 10](https://owasp.org/www-project-top-ten/) guidelines."
        )
        return "\n".join(tips)

    # JSON report
    def _write_json(self) -> None:
        path = os.path.join(self.output_dir, "vulnerability-report.json")
        payload = {
            "generated": self.timestamp,
            "total": len(self.findings),
            "summary": self._count_by_severity(),
            "by_tool": self._count_by_tool(),
            "findings": self.findings,
        }
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"  [report] JSON report     → {path}")

    # Helpers
    def _count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            sev = f.get("severity", "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_tool(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            tool = f.get("tool", "unknown")
            counts[tool] = counts.get(tool, 0) + 1
        return counts
