"""Backend selection and compatibility helpers for VulnTrace storage."""

from pathlib import Path
import os
import sqlite3

import psycopg
from psycopg.rows import dict_row


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database" / "vulntrace.db"

INTEGRITY_ERRORS = (sqlite3.IntegrityError, psycopg.IntegrityError)


def using_postgres():
    """Return whether the Neon backend is configured."""

    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


def connect_postgres():
    """Open a TLS-protected Neon/PostgreSQL connection.

    The URL is read from Replit Secrets and is never printed or logged here.
    """

    connection_url = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not connection_url:
        raise RuntimeError("NEON_DATABASE_URL is not configured.")

    connection = psycopg.connect(
        connection_url,
        row_factory=dict_row,
        connect_timeout=10,
        sslmode="require",
    )
    return DatabaseConnection(connection, backend="postgres")


class DatabaseConnection:
    """Small adapter retaining SQLite-style query calls on both backends."""

    def __init__(self, connection, backend):
        self.connection = connection
        self.backend = backend

    def execute(self, query, params=None):
        if self.backend == "postgres":
            query = convert_qmark_placeholders(query)
        return self.connection.execute(query, () if params is None else params)

    def insert_id(self, query, params=()):
        """Execute an INSERT and return its generated ``id``."""

        if self.backend == "postgres":
            statement = query.rstrip().rstrip(";")
            row = self.execute(f"{statement} RETURNING id", params).fetchone()
            if row is None:
                raise RuntimeError("The database did not return an inserted id.")
            return row["id"]

        return self.execute(query, params).lastrowid

    def executescript(self, script):
        """Run a SQLite schema script; PostgreSQL setup is explicit."""

        if self.backend != "sqlite":
            raise RuntimeError(
                "PostgreSQL schema setup is performed by migrate_to_postgres.py."
            )
        return self.connection.executescript(script)

    def commit(self):
        return self.connection.commit()

    def rollback(self):
        return self.connection.rollback()

    def close(self):
        return self.connection.close()


def get_db():
    """Connect to Neon when configured; otherwise retain SQLite fallback."""

    if using_postgres():
        return connect_postgres()

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return DatabaseConnection(connection, backend="sqlite")


def convert_qmark_placeholders(query):
    """Translate SQLite ``?`` parameters to Psycopg ``%s`` parameters.

    Question marks inside quoted strings, quoted identifiers, and SQL comments
    are left unchanged.
    """

    output = []
    index = 0
    quote = None
    in_line_comment = False
    in_block_comment = False

    while index < len(query):
        char = query[index]
        following = query[index + 1] if index + 1 < len(query) else ""

        if in_line_comment:
            output.append(char)
            if char == "\n":
                in_line_comment = False
            index += 1
            continue

        if in_block_comment:
            output.append(char)
            if char == "*" and following == "/":
                output.append(following)
                index += 2
                in_block_comment = False
            else:
                index += 1
            continue

        if quote:
            output.append(char)
            if char == quote:
                if following == quote:
                    output.append(following)
                    index += 2
                    continue
                quote = None
            elif char == "\\" and following:
                output.append(following)
                index += 2
                continue
            index += 1
            continue

        if char == "-" and following == "-":
            output.extend((char, following))
            index += 2
            in_line_comment = True
        elif char == "/" and following == "*":
            output.extend((char, following))
            index += 2
            in_block_comment = True
        elif char in ("'", '"'):
            quote = char
            output.append(char)
            index += 1
        elif char == "?":
            output.append("%s")
            index += 1
        else:
            output.append(char)
            index += 1

    return "".join(output)
