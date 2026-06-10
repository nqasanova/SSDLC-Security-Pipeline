"""
sample_app/vulnerable_app.py

A deliberately insecure sample application used to demonstrate
that the SSDLC Security Pipeline correctly detects real issues.

DO NOT deploy this code in production.
"""

import subprocess
import hashlib
import random
import sqlite3
import pickle


# B105 - Hardcoded password (intentional demo)
SECRET_KEY = "supersecret123"
DB_PASSWORD = "admin"


def get_user(username: str, db_conn: sqlite3.Connection):
    """B608 - SQL injection vulnerability (intentional demo)."""
    cursor = db_conn.cursor()
    # INSECURE: user input interpolated directly into query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(password: str) -> str:
    """B324 - Use of weak MD5 hash (intentional demo)."""
    return hashlib.md5(password.encode()).hexdigest()  # noqa


def generate_token(length: int = 16) -> str:
    """B311 - Use of insecure random for security token (intentional demo)."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))  # noqa


def run_command(user_input: str) -> str:
    """B602 - Shell injection via subprocess (intentional demo)."""
    result = subprocess.run(
        f"echo {user_input}",
        shell=True,          # INSECURE
        capture_output=True,
        text=True,
    )
    return result.stdout


def load_data(data: bytes):
    """B301 - Insecure deserialization with pickle (intentional demo)."""
    return pickle.loads(data)  # noqa


def connect_db(host: str) -> sqlite3.Connection:
    """Connects to SQLite (safe here, but demonstrates DB connection pattern)."""
    conn = sqlite3.connect(f"/tmp/{host}.db")
    return conn
