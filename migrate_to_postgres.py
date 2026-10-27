"""Safely initialize Neon and copy VulnTrace rows from SQLite.

This command is intentionally explicit:
    python migrate_to_postgres.py check
    python migrate_to_postgres.py migrate

The migration refuses to write if any VulnTrace table already exists in the
destination. It opens the SQLite source read-only and never prints row contents
or the Neon connection string.
"""

import argparse
from pathlib import Path
import sqlite3
import sys

from db import DATABASE, connect_postgres


SCHEMA_FILE = Path(__file__).resolve().parent / "database" / "schema.postgres.sql"

TABLE_ORDER = (
    "users",
    "reports",
    "findings",
    "analyses",
    "remediation",
    "verifications",
)

TABLE_COLUMNS = {
    "users": ("id", "username", "password_hash", "created_at"),
    "reports": ("id", "user_id", "name", "source_format", "uploaded_at"),
    "findings": (
        "id",
        "report_id",
        "title",
        "severity",
        "confidence",
        "description",
        "evidence",
        "asset",
        "status",
        "created_at",
        "evidence_quality",
        "risk_score",
        "duplicate_key",
        "duplicate_of",
        "duplicate_count",
        "verification_status",
        "verification_evidence",
        "verified_at",
    ),
    "analyses": (
        "id",
        "finding_id",
        "analysis_type",
        "content",
        "source",
        "created_at",
    ),
    "remediation": (
        "id",
        "finding_id",
        "recommendation",
        "verification",
        "created_at",
    ),
    "verifications": (
        "id",
        "finding_id",
        "evidence",
        "result",
        "ai_assessment",
        "created_at",
    ),
}

REQUIRED_COLUMNS = {
    "users": {"id", "username", "password_hash"},
    "reports": {"id", "user_id", "name", "source_format"},
    "findings": {"id", "report_id", "title", "severity"},
    "analyses": {"id", "finding_id", "analysis_type", "content", "source"},
    "remediation": {"id", "finding_id", "recommendation"},
    "verifications": {"id", "finding_id", "evidence"},
}

FIND_TABLES_SQL = """
    SELECT table_name
    FROM information_schema.tables
    WHERE table_type = 'BASE TABLE'
      AND table_schema NOT IN ('pg_catalog', 'information_schema')
      AND table_name = ANY(%s::text[])
    ORDER BY table_name
"""


class TargetNotEmptyError(RuntimeError):
    """Raised when a destination already has VulnTrace tables."""

    def __init__(self, tables):
        self.tables = tuple(tables)
        super().__init__("The target already contains VulnTrace tables.")


def _find_target_tables(connection):
    rows = connection.execute(FIND_TABLES_SQL, (list(TABLE_ORDER),)).fetchall()
    return [row["table_name"] for row in rows]


def preflight_target(connection):
    """Check VulnTrace table names in a rolled-back read-only transaction."""

    try:
        connection.execute("SET TRANSACTION READ ONLY")
        return _find_target_tables(connection)
    finally:
        connection.rollback()


def _read_source_schema(source):
    source_tables = {
        row["name"]
        for row in source.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    unknown_tables = source_tables - set(TABLE_ORDER)
    missing_tables = set(TABLE_ORDER) - source_tables
    if unknown_tables or missing_tables:
        raise RuntimeError(
            "The SQLite schema has missing or unrecognized tables; "
            "migration stopped to avoid omitting data."
        )

    source_columns = {}
    for table in TABLE_ORDER:
        columns = {
            row["name"]
            for row in source.execute(f"PRAGMA table_info({table})").fetchall()
        }
        extra = columns - set(TABLE_COLUMNS[table])
        missing = REQUIRED_COLUMNS[table] - columns
        if extra or missing:
            raise RuntimeError(
                f"The SQLite schema for {table} is incompatible; "
                "migration stopped to avoid omitting data."
            )
        source_columns[table] = [
            column for column in TABLE_COLUMNS[table] if column in columns
        ]
    return source_columns


def _open_sqlite_read_only(path):
    uri = f"{Path(path).resolve().as_uri()}?mode=ro"
    source = sqlite3.connect(uri, uri=True)
    source.row_factory = sqlite3.Row
    return source


def _sql_statements(script):
    # The checked-in schema has no semicolons inside literals or procedural SQL.
    return [statement.strip() for statement in script.split(";") if statement.strip()]


def _copy_table(source, destination, table, columns):
    column_list = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))
    insert_sql = (
        f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})"
    )
    select_sql = f"SELECT {column_list} FROM {table} ORDER BY id"
    cursor = source.execute(select_sql)
    destination_cursor = destination.cursor()
    copied = 0

    while True:
        batch = cursor.fetchmany(500)
        if not batch:
            break
        destination_cursor.executemany(
            insert_sql,
            [tuple(row[column] for column in columns) for row in batch],
        )
        copied += len(batch)
    return copied


def _reset_identity_sequences(connection):
    for table in TABLE_ORDER:
        connection.execute(
            f"""
            SELECT setval(
                pg_get_serial_sequence('public.{table}', 'id'),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM public.{table}
            """
        )


def migrate_sqlite_to_postgres(connection, sqlite_path=DATABASE):
    """Copy all supported SQLite data after two safe target-empty checks."""

    existing = preflight_target(connection)
    if existing:
        raise TargetNotEmptyError(existing)

    source = _open_sqlite_read_only(sqlite_path)
    try:
        source_columns = _read_source_schema(source)
        source_counts = {
            table: source.execute(
                f"SELECT COUNT(*) AS count FROM {table}"
            ).fetchone()["count"]
            for table in TABLE_ORDER
        }

        # Recheck in the write transaction immediately before any DDL. Plain
        # CREATE statements then fail (and roll back) if another writer races.
        existing = _find_target_tables(connection)
        if existing:
            connection.rollback()
            raise TargetNotEmptyError(existing)

        schema = SCHEMA_FILE.read_text(encoding="utf-8")
        for statement in _sql_statements(schema):
            connection.execute(statement)

        copied_counts = {
            table: _copy_table(
                source,
                connection,
                table,
                source_columns[table],
            )
            for table in TABLE_ORDER
        }
        _reset_identity_sequences(connection)

        if copied_counts != source_counts:
            raise RuntimeError("Row count verification failed; transaction rolled back.")

        connection.commit()
        return copied_counts
    except Exception:
        connection.rollback()
        raise
    finally:
        source.close()


def _format_failure(error):
    if isinstance(error, TargetNotEmptyError):
        return (
            "Target already contains VulnTrace tables: "
            + ", ".join(error.tables)
            + ". No changes were made."
        )
    return (
        f"Operation failed ({type(error).__name__}); "
        "connection details are suppressed."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("check", "migrate"),
        help="check is read-only; migrate creates tables and copies SQLite data",
    )
    args = parser.parse_args(argv)

    connection = None
    try:
        connection = connect_postgres()
        existing = preflight_target(connection)
        if existing:
            print(_format_failure(TargetNotEmptyError(existing)))
            return 2

        if args.command == "check":
            print("Read-only preflight passed: no VulnTrace tables found.")
            return 0

        counts = migrate_sqlite_to_postgres(connection)
        print("Migration committed. Rows copied by table:")
        for table in TABLE_ORDER:
            print(f"  {table}: {counts[table]}")
        return 0
    except Exception as error:
        print(_format_failure(error), file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
