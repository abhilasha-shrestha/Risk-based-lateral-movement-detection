"""Shared helpers for the ETL loaders.

Run with `python -I` when processing the downloaded dataset, per the
environment's untrusted-data guidance. The loaders take paths as
arguments / env and never import from the data directory.
"""
from __future__ import annotations
import hashlib
import os
from datetime import datetime
from pathlib import Path

# repo root = parent of this etl/ dir; data lives in <root>/archive
ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("CERT_DATA", ROOT / "archive"))

CERT_TS_FMT = "%m/%d/%Y %H:%M:%S"   # e.g. 08/12/2010 19:08:21


def parse_ts(s: str) -> datetime:
    """Parse a CERT timestamp. Explicit format — never let the DB guess,
    or MM/DD vs DD/MM will silently corrupt every time-based signal."""
    return datetime.strptime(s.strip(), CERT_TS_FMT)


def h(s: str | None) -> str | None:
    """Short, stable pseudonymising hash (names/emails)."""
    if not s:
        return None
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:32]


def dsn() -> str:
    """libpq connection string from env (.env is loaded by the caller)."""
    return (
        f"host={os.environ.get('PGHOST', 'localhost')} "
        f"port={os.environ.get('PGPORT', '5432')} "
        f"dbname={os.environ.get('PGDATABASE', 'lateral')} "
        f"user={os.environ.get('PGUSER', 'lmd')} "
        f"password={os.environ.get('PGPASSWORD', 'lmd_pass')}"
    )


def load_env() -> None:
    """Load <root>/.env if python-dotenv is available (optional)."""
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except Exception:
        pass


def connect():
    """Open a psycopg connection. Imported lazily so --dry-run works
    without psycopg or a running database."""
    import psycopg
    load_env()
    return psycopg.connect(dsn())
