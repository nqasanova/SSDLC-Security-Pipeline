# Secure Development Guidelines

This document outlines security requirements and best practices for all code
contributed to this repository. It is maintained as part of the
Secure Software Development Lifecycle (SSDLC).

---

## 1. Input Validation

- **Never trust external input.** Validate all data from users, APIs, files, or
  environment variables before use.
- Use allowlists (permitted patterns) rather than blocklists where possible.
- Reject input that does not conform to expected format, length, and type.

```python
# BAD
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# GOOD — parameterized query
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
```

---

## 2. Secrets Management

- **Never hardcode secrets** (passwords, API keys, tokens) in source code.
- Store secrets in environment variables or a dedicated secrets manager
  (e.g., HashiCorp Vault, AWS Secrets Manager, GitHub Actions Secrets).
- Add `.env` files to `.gitignore` and commit only `.env.example` templates.

```python
# BAD
API_KEY = "sk-abc123secret"

# GOOD
import os
API_KEY = os.environ["API_KEY"]
```

---

## 3. Cryptography

- Use **modern, vetted algorithms** only:
  - Hashing: SHA-256 or SHA-3 (never MD5 or SHA-1 for security)
  - Symmetric encryption: AES-256-GCM
  - Asymmetric: RSA-2048+ or Ed25519
- Use the `secrets` module (not `random`) for security-sensitive randomness.

```python
# BAD
import random
token = random.randint(0, 999999)

# GOOD
import secrets
token = secrets.token_hex(32)
```

---

## 4. Dependency Management

- Pin dependency versions in `requirements.txt` / `pyproject.toml`.
- Run `pip audit` regularly to detect known vulnerabilities.
- Update dependencies on a scheduled basis (monthly minimum).
- Review changelogs before upgrading security-critical packages.

```bash
# Check for known vulnerabilities
pip audit

# Update a specific package
pip install --upgrade <package>
```

---

## 5. Secure Use of subprocess / Shell

- Avoid `shell=True` in `subprocess` calls.
- Never interpolate user-controlled data into shell commands.
- Prefer library-based alternatives to shelling out where possible.

```python
# BAD
subprocess.run(f"ls {user_path}", shell=True)

# GOOD
subprocess.run(["ls", user_path], shell=False)
```

---

## 6. Deserialization

- Never deserialize untrusted data with `pickle`, `marshal`, or `yaml.load`.
- Use `json.loads` for data exchange; use `yaml.safe_load` if YAML is required.

```python
# BAD
data = pickle.loads(user_supplied_bytes)

# GOOD
data = json.loads(user_supplied_string)
```

---

## 7. Error Handling and Logging

- Do not expose stack traces, internal paths, or secrets in error messages
  returned to users.
- Log security-relevant events (authentication, access control decisions,
  configuration changes) with sufficient context for forensic analysis.
- Sanitize any user-provided data before including it in log messages
  (log injection prevention).

---

## 8. Access Control

- Apply the **principle of least privilege**: request only the permissions
  required for the task.
- Validate authorization on the server side for every sensitive operation.
- Use role-based access control (RBAC) for multi-user systems.

---

## 9. CI/CD Security Requirements

All pull requests to `main` must pass the automated security scan
(`.github/workflows/security-pipeline.yml`) before merging.

| Threshold | Action |
|-----------|--------|
| CRITICAL  | Build fails immediately |
| HIGH      | Build fails (default) |
| MEDIUM    | Warning in summary; does not block |
| LOW       | Informational only |

To override for a specific finding (with justification), add a `# nosec B<id>`
comment inline and document the reason in your PR description.

---

## 10. Security Review Checklist (PR Authors)

Before opening a pull request, confirm:

- [ ] No secrets or credentials are committed.
- [ ] All external inputs are validated and sanitized.
- [ ] No use of deprecated or weak cryptographic functions.
- [ ] `subprocess` calls do not use `shell=True` with dynamic input.
- [ ] Dependencies have been checked with `pip audit`.
- [ ] Error messages do not leak internal implementation details.
- [ ] The security scanner passes locally (`python main.py --target .`).

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Python Security Best Practices — Bandit docs](https://bandit.readthedocs.io/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/Projects/ssdf)
