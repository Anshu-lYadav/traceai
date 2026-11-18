"""Officer accounts, admin approval, password hashing, and JWT sessions.

Flow
----
1. An officer registers with email + password. The account starts as ``pending``.
2. An admin reviews the request and approves (or rejects / disables) it.
3. Only ``approved`` accounts can sign in. A successful sign-in returns a signed
   JWT (HS256) that the app verifies on every rerun. The user row is re-checked
   on every verification, so disabling an account takes effect immediately.

The first admin is created from the command line, never from the web page:

    python -m modules.auth create-admin
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from modules import database

ROLES = ("officer", "admin")
STATUSES = ("pending", "approved", "rejected", "disabled")

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "trace-ai"
TOKEN_TTL = timedelta(hours=int(os.environ.get("TRACE_SESSION_HOURS", "8")))

MAX_FAILED_ATTEMPTS = 5
LOCKOUT = timedelta(minutes=15)
MIN_PASSWORD_LENGTH = 10

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


class AuthError(Exception):
    """A user-facing authentication or authorization failure."""


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
def initialize_auth() -> None:
    with database._connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                badge_number TEXT NOT NULL DEFAULT '',
                police_station TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'officer',
                status TEXT NOT NULL DEFAULT 'pending',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                token_version INTEGER NOT NULL DEFAULT 0,
                approved_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS auth_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_email TEXT,
                created_at TEXT NOT NULL
            );
            """
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(connection, email: str, event_type: str, actor_email: str | None = None) -> None:
    connection.execute(
        "INSERT INTO auth_log(email,event_type,actor_email,created_at) VALUES(?,?,?,?)",
        (email, event_type, actor_email, _now().isoformat()),
    )


# --------------------------------------------------------------------------- #
# Passwords (stdlib scrypt, salted, constant-time compare)
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=64, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), dklen=len(digest_hex) // 2,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        raise AuthError("Password must contain both letters and numbers.")


# --------------------------------------------------------------------------- #
# Email policy
# --------------------------------------------------------------------------- #
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def allowed_email_domains() -> list[str]:
    """Optional allow-list, e.g. TRACE_ALLOWED_EMAIL_DOMAINS="gov.in,police.gov.in"."""
    raw = os.environ.get("TRACE_ALLOWED_EMAIL_DOMAINS", "")
    return [d.strip().lower().lstrip("@") for d in raw.split(",") if d.strip()]


def validate_email(email: str) -> str:
    email = normalize_email(email)
    if not _EMAIL_RE.match(email):
        raise AuthError("Enter a valid email address.")
    domains = allowed_email_domains()
    if domains:
        domain = email.rsplit("@", 1)[1]
        if not any(domain == d or domain.endswith("." + d) for d in domains):
            raise AuthError("Only official department email addresses can register.")
    return email


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def _jwt_secret() -> str:
    secret = os.environ.get("TRACE_JWT_SECRET")
    if secret:
        return secret
    secret_path = database.DATA_DIR / ".jwt_secret"
    if secret_path.exists():
        return secret_path.read_text().strip()
    database.DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(64)
    fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(secret)
    return secret


def issue_token(user: dict[str, Any]) -> str:
    now = _now()
    payload = {
        "sub": user["user_id"],
        "email": user["email"],
        "role": user["role"],
        "ver": user["token_version"],
        "iss": JWT_ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALGORITHM)


def verify_token(token: str | None) -> dict[str, Any] | None:
    """Return the current user for a valid token, or None.

    The signature, expiry and issuer are checked, then the user row is read
    again so that disabled accounts, role changes and forced sign-outs apply
    immediately instead of waiting for the token to expire.
    """
    if not token:
        return None
    try:
        claims = jwt.decode(
            token, _jwt_secret(), algorithms=[JWT_ALGORITHM], issuer=JWT_ISSUER,
            options={"require": ["sub", "exp", "iat", "iss"]},
        )
    except jwt.PyJWTError:
        return None
    user = get_user(claims["sub"])
    if not user or user["status"] != "approved":
        return None
    if claims.get("ver") != user["token_version"]:
        return None
    return user


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
_PUBLIC_COLUMNS = (
    "user_id,email,full_name,badge_number,police_station,role,status,"
    "token_version,approved_by,created_at,last_login_at"
)


def get_user(user_id: str) -> dict[str, Any] | None:
    with database._connect() as connection:
        row = connection.execute(
            f"SELECT {_PUBLIC_COLUMNS} FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def list_users(status: str | None = None) -> list[dict[str, Any]]:
    query = f"SELECT {_PUBLIC_COLUMNS} FROM users"
    params: tuple = ()
    if status:
        query += " WHERE status=?"
        params = (status,)
    with database._connect() as connection:
        rows = connection.execute(query + " ORDER BY created_at", params).fetchall()
    return [dict(row) for row in rows]


def admin_exists() -> bool:
    with database._connect() as connection:
        return connection.execute(
            "SELECT 1 FROM users WHERE role='admin' AND status='approved' LIMIT 1"
        ).fetchone() is not None


def register_officer(email: str, password: str, full_name: str,
                     badge_number: str, police_station: str) -> None:
    email = validate_email(email)
    validate_password(password)
    full_name = full_name.strip()
    badge_number = badge_number.strip()
    if not full_name or not badge_number:
        raise AuthError("Full name and badge / employee number are required.")
    timestamp = _now().isoformat()
    with database._connect() as connection:
        if connection.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            # Same message as success, so the form cannot be used to discover accounts.
            return
        connection.execute(
            "INSERT INTO users(user_id,email,full_name,badge_number,police_station,password_hash,"
            "role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, email, full_name, badge_number, police_station.strip(),
             hash_password(password), "officer", "pending", timestamp, timestamp),
        )
        _audit(connection, email, "registered")


def create_admin(email: str, password: str, full_name: str, badge_number: str = "ADMIN") -> None:
    email = validate_email(email)
    validate_password(password)
    timestamp = _now().isoformat()
    with database._connect() as connection:
        existing = connection.execute("SELECT user_id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            connection.execute(
                "UPDATE users SET role='admin',status='approved',password_hash=?,failed_attempts=0,"
                "locked_until=NULL,token_version=token_version+1,updated_at=? WHERE email=?",
                (hash_password(password), timestamp, email),
            )
        else:
            connection.execute(
                "INSERT INTO users(user_id,email,full_name,badge_number,password_hash,role,status,"
                "approved_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, email, full_name.strip() or "Administrator", badge_number,
                 hash_password(password), "admin", "approved", "cli", timestamp, timestamp),
            )
        _audit(connection, email, "admin_created", "cli")


_GENERIC_LOGIN_ERROR = "Incorrect email or password."


def authenticate(email: str, password: str) -> str:
    """Check credentials and return a signed JWT. Raises AuthError otherwise.

    Errors are raised only after the connection commits, so failed-attempt
    counters and audit entries are never rolled back.
    """
    email = normalize_email(email)
    now = _now()
    error: str | None = None
    user: dict[str, Any] | None = None
    with database._connect() as connection:
        row = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row is None:
            # Spend the same time hashing so response time doesn't reveal unknown emails.
            verify_password(password, hash_password("timing-equalizer"))
            _audit(connection, email, "login_failed_unknown")
            error = _GENERIC_LOGIN_ERROR
        elif row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > now:
            _audit(connection, email, "login_blocked_locked")
            error = "Too many failed attempts. Try again in 15 minutes."
        elif not verify_password(password, row["password_hash"]):
            attempts = row["failed_attempts"] + 1
            locked_until = (now + LOCKOUT).isoformat() if attempts >= MAX_FAILED_ATTEMPTS else None
            connection.execute(
                "UPDATE users SET failed_attempts=?,locked_until=? WHERE user_id=?",
                (0 if locked_until else attempts, locked_until, row["user_id"]),
            )
            _audit(connection, email, "login_locked" if locked_until else "login_failed")
            error = _GENERIC_LOGIN_ERROR
        elif row["status"] == "pending":
            error = "Your account is waiting for admin approval."
        elif row["status"] != "approved":
            _audit(connection, email, "login_blocked_inactive")
            error = "This account is not active. Contact your administrator."
        else:
            connection.execute(
                "UPDATE users SET failed_attempts=0,locked_until=NULL,last_login_at=? WHERE user_id=?",
                (now.isoformat(), row["user_id"]),
            )
            _audit(connection, email, "login_success")
            user = dict(row)
    if error or user is None:
        raise AuthError(error or _GENERIC_LOGIN_ERROR)
    return issue_token(user)


# --------------------------------------------------------------------------- #
# Admin actions
# --------------------------------------------------------------------------- #
def _require_admin(actor: dict[str, Any]) -> None:
    if not actor or actor.get("role") != "admin" or actor.get("status") != "approved":
        raise AuthError("Admin permission required.")


def set_user_status(actor: dict[str, Any], user_id: str, status: str) -> None:
    _require_admin(actor)
    if status not in STATUSES:
        raise AuthError("Unknown status.")
    if user_id == actor["user_id"] and status != "approved":
        raise AuthError("You cannot disable your own admin account.")
    with database._connect() as connection:
        row = connection.execute("SELECT email FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.")
        connection.execute(
            "UPDATE users SET status=?,approved_by=CASE WHEN ?='approved' THEN ? ELSE approved_by END,"
            "token_version=token_version+1,failed_attempts=0,locked_until=NULL,updated_at=? WHERE user_id=?",
            (status, status, actor["email"], _now().isoformat(), user_id),
        )
        _audit(connection, row["email"], f"status_{status}", actor["email"])


def set_user_role(actor: dict[str, Any], user_id: str, role: str) -> None:
    _require_admin(actor)
    if role not in ROLES:
        raise AuthError("Unknown role.")
    if user_id == actor["user_id"] and role != "admin":
        raise AuthError("You cannot remove your own admin role.")
    with database._connect() as connection:
        row = connection.execute("SELECT email FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.")
        connection.execute(
            "UPDATE users SET role=?,token_version=token_version+1,updated_at=? WHERE user_id=?",
            (role, _now().isoformat(), user_id),
        )
        _audit(connection, row["email"], f"role_{role}", actor["email"])


def list_auth_log(limit: int = 200) -> list[dict[str, Any]]:
    with database._connect() as connection:
        rows = connection.execute(
            "SELECT email,event_type,actor_email,created_at FROM auth_log ORDER BY log_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------- #
# CLI: python -m modules.auth create-admin
# --------------------------------------------------------------------------- #
def _cli() -> None:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="TRACE AI account administration")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="Create or reset an admin account")
    create.add_argument("--email")
    create.add_argument("--name", default="Administrator")
    args = parser.parse_args()

    database.initialize_database()
    initialize_auth()
    if args.command == "create-admin":
        email = args.email or input("Admin email: ")
        password = getpass.getpass("Password (min 10 chars, letters + numbers): ")
        if password != getpass.getpass("Repeat password: "):
            raise SystemExit("Passwords do not match.")
        try:
            create_admin(email, password, args.name)
        except AuthError as exc:
            raise SystemExit(str(exc))
        print(f"Admin account ready: {normalize_email(email)}")


if __name__ == "__main__":
    _cli()
