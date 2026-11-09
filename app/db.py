"""SQLite access. One connection per request, explicit transactions."""
import contextlib
import os
import sqlite3

from .config import BASE, settings
from .errors import Refused
from .security import hash_password
from .util import utcnow


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    c = sqlite3.connect(settings.db_path, isolation_level=None,
                        check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA journal_mode = WAL")
    return c


def get_db():
    c = connect()
    try:
        yield c
    finally:
        c.close()


@contextlib.contextmanager
def tx(db: sqlite3.Connection):
    """BEGIN IMMEDIATE ... COMMIT. Re-entrant: if a transaction is already open the
    outermost one decides. IMMEDIATE takes the write lock up front, so an authorisation
    check and the write that depends on it are atomic (no check-then-act race), and
    audit rows are chained without interleaving."""
    if db.in_transaction:
        yield db
        return
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except Refused:
        db.execute("COMMIT")
        raise
    except BaseException:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")


def init_db() -> None:
    c = connect()
    with open(os.path.join(BASE, "schema.sql"), encoding="utf-8") as f:
        c.executescript(f.read())
    c.close()


def create_user(db, username: str, display_name: str, password: str, role: str) -> int:
    cur = db.execute(
        "INSERT INTO users(username, display_name, password_hash, role, created_at) "
        "VALUES (?,?,?,?,?)",
        (username.lower(), display_name, hash_password(password), role, utcnow()))
    return cur.lastrowid
