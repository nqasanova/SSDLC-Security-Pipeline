# Security Awareness: Top 5 Issues We Catch in Code Review

A quick-reference guide for developers. Each section maps to a real finding
class produced by this pipeline and explains **why it matters** and
**how to fix it in under 5 minutes**.

---

## 1. SQL Injection (CWE-89) — Bandit B608

**Why it matters:** An attacker can manipulate a poorly formed query to
dump your entire database, bypass authentication, or destroy data.
It is the #1 web application vulnerability (OWASP A03:2021).

**Spot it:**
```python
# Dangerous — user input ends up in the query string
query = f"SELECT * FROM orders WHERE id = '{user_id}'"
cursor.execute(query)
```

**Fix it — parameterized queries:**
```python
cursor.execute("SELECT * FROM orders WHERE id = ?", (user_id,))
```

---

## 2. Shell Injection (CWE-78) — Bandit B602 / B603

**Why it matters:** `shell=True` with dynamic input lets attackers execute
arbitrary operating system commands on your server.

**Spot it:**
```python
subprocess.run(f"convert {filename}", shell=True)
```

**Fix it:**
```python
subprocess.run(["convert", filename], shell=False)
```

---

## 3. Hardcoded Credentials (CWE-798) — Bandit B105 / B106

**Why it matters:** Secrets committed to Git are permanent — even after
deletion they exist in history. Automated bots scrape public repos
for leaked credentials within seconds of a push.

**Spot it:**
```python
DB_PASSWORD = "mySuperSecret123"
```

**Fix it:**
```python
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

Add `pip audit` and [git-secrets](https://github.com/awslabs/git-secrets)
as pre-commit hooks to catch this before it reaches the repo.

---

## 4. Weak Cryptography (CWE-327) — Bandit B303 / B324

**Why it matters:** MD5 and SHA-1 are broken for security purposes.
Collisions can be computed in seconds on commodity hardware.

**Spot it:**
```python
hashlib.md5(password.encode()).hexdigest()
```

**Fix it:**
```python
# For password storage — use bcrypt or argon2
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# For non-password integrity checks — use SHA-256
hashlib.sha256(data).hexdigest()
```

---

## 5. Insecure Randomness (CWE-330) — Bandit B311

**Why it matters:** `random` is designed for statistical simulation,
not security. Its output is predictable given the seed.

**Spot it:**
```python
token = ''.join(random.choices(string.ascii_letters, k=32))
```

**Fix it:**
```python
import secrets
token = secrets.token_urlsafe(32)
```

---

## Quick Reference: Bandit Rule → Fix

| Rule | Issue | Fix |
|------|-------|-----|
| B105/B106 | Hardcoded password | Use env var / secrets manager |
| B301 | `pickle.loads` | Use `json.loads` or `yaml.safe_load` |
| B303/B324 | MD5 / SHA-1 | Use SHA-256 / bcrypt / argon2 |
| B311 | `random` for secrets | Use `secrets` module |
| B501–B504 | Weak TLS/SSL | Enforce TLS 1.2+, valid certs |
| B602/B603 | `shell=True` | Pass list, `shell=False` |
| B608 | SQL injection | Parameterized queries / ORM |