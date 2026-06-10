# SSDLC Security Pipeline

**Automated Secure Software Development Lifecycle (SSDLC) pipeline** that integrates static security analysis into CI/CD workflows, filters false positives, generates vulnerability reports, and renders a live security metrics dashboard — with a Go CLI wrapper for developer ergonomics.

> Built as a practical implementation of SSDLC best practices covering threat modeling support, automated attack surface scanning, false-positive triage, developer security awareness, and CI/CD pipeline enforcement.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Multi-tool SAST scanning** | Runs Bandit (Python) and Semgrep (multi-language) and normalizes findings into a unified schema |
| 🧹 **False-positive filtering** | Rule-based YAML config suppresses known-safe patterns (test files, sample code, docs) |
| 📊 **HTML security dashboard** | Self-contained dashboard with severity cards, findings-by-tool bar chart, vulnerability trend line chart, and a searchable/sortable findings table |
| 📝 **Markdown + JSON reports** | Machine-readable JSON for downstream tooling; human-readable Markdown for PR summaries |
| 📈 **Metrics trend tracking** | Persists vulnerability counts across runs to visualize improvement over time |
| ⚙️ **GitHub Actions CI/CD** | Two workflows — security scan (blocks PRs on HIGH+) and unit tests — with artifact upload and job summary integration |
| 🐹 **Go CLI wrapper** | `ssdlc-scan` binary written in Go provides a clean developer interface with structured terminal output and strict input validation |
| 🛡️ **Security guidelines** | Documented secure coding standards and a developer awareness guide covering OWASP Top 10 patterns |

---

## Project Structure

```
ssdlc-security-pipeline/
│
├── main.py                          # Python pipeline entry point
├── requirements.txt
│
├── scanner/
│   ├── runner.py                    # Runs Bandit & Semgrep, normalizes output
│   └── metrics.py                   # Tracks vulnerability counts over time
│
├── filters/
│   ├── false_positive_filter.py     # Rule-based FP suppression engine
│   └── fp_rules.yaml                # Configurable suppression rules
│
├── reporter/
│   └── report_generator.py          # Markdown + JSON report generation
│
├── dashboard/
│   └── dashboard_generator.py       # Self-contained HTML dashboard
│
├── cli/                             # Go CLI wrapper
│   ├── main.go                      # CLI entry point (flags, validation, exit codes)
│   ├── go.mod
│   └── internal/
│       ├── runner/
│       │   ├── runner.go            # Invokes Python pipeline, parses JSON report
│       │   └── runner_test.go       # Go unit tests
│       └── summary/
│           └── summary.go           # Terminal summary printer
│
├── tests/
│   └── test_pipeline.py             # Python unit tests (pytest)
│
├── sample_app/
│   └── vulnerable_app.py            # Intentionally vulnerable demo app
│
├── docs/
│   ├── SECURE_DEVELOPMENT_GUIDELINES.md
│   └── SECURITY_AWARENESS.md
│
└── .github/
    └── workflows/
        ├── security-pipeline.yml    # Main SSDLC scan workflow
        └── tests.yml                # Unit test workflow
```

---

## Quickstart

### Prerequisites

```bash
pip install bandit semgrep pyyaml pytest
```

For the Go CLI (optional):
```bash
# requires Go 1.22+
cd cli && go build -o ssdlc-scan .
```

### Run a scan (Python)

```bash
# Scan current directory, fail on HIGH or above
python main.py --target .

# Scan a specific project, JSON output only, no dashboard
python main.py --target ./myproject --format json --no-dashboard

# Change the blocking threshold
python main.py --target . --fail-on CRITICAL
```

### Run a scan (Go CLI)

```bash
# From the repo root after building the CLI
./cli/ssdlc-scan --target .

# All options
./cli/ssdlc-scan \
  --target ./myproject \
  --tools bandit \
  --severity MEDIUM \
  --fail-on HIGH \
  --format both \
  --output-dir security-reports
```

### Run tests

```bash
# Python tests
pytest tests/ -v

# Go tests
cd cli && go test ./...
```

---

## CLI Reference

### Python (`main.py`)

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | `.` | Directory to scan |
| `--tools` | `all` | `bandit`, `semgrep`, or `all` |
| `--output-dir` | `security-reports` | Output directory |
| `--severity` | `LOW` | Minimum severity to include |
| `--fail-on` | `HIGH` | Exit non-zero if findings at this level exist |
| `--format` | `both` | `markdown`, `json`, or `both` |
| `--fp-config` | `filters/fp_rules.yaml` | False-positive rules path |
| `--no-dashboard` | `false` | Skip HTML dashboard |

### Go CLI (`ssdlc-scan`)

Same flags, plus:

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit |

---

## False Positive Rules

Edit `filters/fp_rules.yaml` to customise suppression. Each rule can combine:

```yaml
rules:
  - description: "Suppress assert_used in test files"
    rule_id: "B101"
    file_pattern: "*test*"

  - description: "Suppress all findings in docs"
    file_pattern: "docs/*"

  - description: "Suppress secrets warning in example configs"
    rule_id: "generic.secrets"
    message_contains: "example"
    file_pattern: "*.example"
```

All conditions in a rule must match for suppression to apply.

---

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/security-pipeline.yml`) runs automatically on every push and pull request.

```
Push / PR
    │
    ▼
┌─────────────────────────────────┐
│  1. Install dependencies        │
│  2. Run ssdlc pipeline          │
│  3. Filter false positives      │
│  4. Generate reports            │
│  5. Upload artifacts (90 days)  │
│  6. Post summary to GH UI       │
│  7. Exit 1 if HIGH+ findings    │
└─────────────────────────────────┘
```

Findings at HIGH or CRITICAL severity **block merges** by default. Override via the `severity_threshold` workflow input for manual runs.

---

## Dashboard

Open `security-reports/dashboard.html` in any browser after a scan.

- **Summary cards** — total, critical, high, medium, low counts at a glance
- **Bar chart** — findings broken down by scanner tool
- **Trend chart** — high/medium/low counts over time (persisted across CI runs)
- **Findings table** — searchable by keyword, filterable by severity, sortable by any column

---

## Security Guidelines

See [`docs/SECURE_DEVELOPMENT_GUIDELINES.md`](docs/SECURE_DEVELOPMENT_GUIDELINES.md) for the full secure coding standard covering:

- Input validation and SQL injection prevention
- Secrets management
- Cryptography requirements
- Dependency management
- Shell injection prevention
- Deserialization safety
- CI/CD enforcement thresholds

See [`docs/SECURITY_AWARENESS.md`](docs/SECURITY_AWARENESS.md) for a developer-friendly quick reference mapping the top scanner findings to concrete fixes.

---

## Sample App

`sample_app/vulnerable_app.py` is a deliberately insecure Python file that demonstrates the pipeline catching real issues:

| Finding | Rule | Severity |
|---------|------|----------|
| Shell injection (`shell=True`) | B602 | HIGH |
| SQL injection | B608 | MEDIUM |
| Insecure deserialization (pickle) | B301 | MEDIUM |
| Weak hash (MD5) | B324 | MEDIUM |
| Insecure random for tokens | B311 | LOW |
| Hardcoded credentials | B105/B106 | LOW |

**Do not deploy sample_app code in production.**

---

## Tech Stack

| Layer | Technology |
|---|---|
| Core pipeline | Python 3.11 |
| Static analysis | Bandit, Semgrep |
| False-positive config | YAML |
| Reports | Markdown, JSON |
| Dashboard | Self-contained HTML + Chart.js |
| CI/CD | GitHub Actions |
| CLI wrapper | Go 1.22 |
| Python tests | pytest |
| Go tests | `testing` (stdlib) |

---

## License

MIT
