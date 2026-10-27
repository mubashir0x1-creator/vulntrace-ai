import os
import sys
import unittest
from unittest.mock import patch

import psycopg

import db


class FakeCursor:
    def __init__(self, row=None, rows=None, lastrowid=None):
        self.row = row
        self.rows = rows or []
        self.lastrowid = lastrowid

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursor=None):
        self.cursor = cursor or FakeCursor(row={"id": 42})
        self.calls = []
        self.closed = False

    def execute(self, query, params=()):
        self.calls.append((query, params))
        return self.cursor

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = True


class FakeSQLiteConnection(FakeConnection):
    row_factory = None


class DatabaseAdapterTests(unittest.TestCase):
    def test_qmark_conversion_skips_strings_and_comments(self):
        query = """SELECT '?', "?", value FROM items
        WHERE id = ? /* ? */ -- ?
        AND owner_id = ?"""
        expected = """SELECT '?', "?", value FROM items
        WHERE id = %s /* ? */ -- ?
        AND owner_id = %s"""
        self.assertEqual(db.convert_qmark_placeholders(query), expected)

    def test_postgres_execute_converts_placeholders_and_binds_values(self):
        raw = FakeConnection()
        connection = db.DatabaseConnection(raw, backend="postgres")

        connection.execute(
            "SELECT id FROM users WHERE username = ?",
            ("sample",),
        )

        self.assertEqual(
            raw.calls,
            [("SELECT id FROM users WHERE username = %s", ("sample",))],
        )

    def test_postgres_insert_id_uses_returning(self):
        raw = FakeConnection(cursor=FakeCursor(row={"id": 73}))
        connection = db.DatabaseConnection(raw, backend="postgres")

        result = connection.insert_id(
            "INSERT INTO users (username) VALUES (?)",
            ("sample",),
        )

        self.assertEqual(result, 73)
        self.assertEqual(
            raw.calls[0],
            ("INSERT INTO users (username) VALUES (%s) RETURNING id", ("sample",)),
        )

    def test_sqlite_insert_id_remains_supported(self):
        raw = FakeSQLiteConnection(cursor=FakeCursor(lastrowid=19))
        connection = db.DatabaseConnection(raw, backend="sqlite")

        result = connection.insert_id(
            "INSERT INTO users (username) VALUES (?)",
            ("sample",),
        )

        self.assertEqual(result, 19)
        self.assertEqual(
            raw.calls[0],
            ("INSERT INTO users (username) VALUES (?)", ("sample",)),
        )

    def test_get_db_selects_postgres_without_opening_a_database(self):
        raw = FakeConnection()
        with (
            patch.dict(os.environ, {"NEON_DATABASE_URL": "mocked-url"}),
            patch("db.psycopg.connect", return_value=raw) as connect,
        ):
            wrapped = db.get_db()

        self.assertEqual(wrapped.backend, "postgres")
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args, ("mocked-url",))
        self.assertEqual(connect.call_args.kwargs["sslmode"], "require")
        self.assertEqual(connect.call_args.kwargs["connect_timeout"], 10)

    def test_get_db_selects_sqlite_with_connection_mocked(self):
        raw = FakeSQLiteConnection()
        with (
            patch.dict(os.environ, {"NEON_DATABASE_URL": ""}),
            patch("db.sqlite3.connect", return_value=raw) as connect,
        ):
            wrapped = db.get_db()

        self.assertEqual(wrapped.backend, "sqlite")
        connect.assert_called_once_with(db.DATABASE)
        self.assertEqual(raw.calls, [("PRAGMA foreign_keys = ON", ())])

    def test_integrity_error_tuple_covers_both_backends(self):
        self.assertIsInstance(sqlite_error(), db.INTEGRITY_ERRORS)
        self.assertIsInstance(psycopg.IntegrityError(), db.INTEGRITY_ERRORS)


def sqlite_error():
    import sqlite3

    return sqlite3.IntegrityError()


class ApplicationRouteTests(unittest.TestCase):
    def test_public_auth_pages_do_not_connect_to_either_database(self):
        with patch.dict(os.environ, {"VULNTRACE_SECRET_KEY": "offline-test-only"}):
            with patch("db.get_db") as get_db:
                sys.modules.pop("app", None)
                import app

                client = app.app.test_client()
                self.assertEqual(client.get("/").status_code, 200)
                self.assertEqual(client.get("/login").status_code, 200)
                self.assertEqual(client.get("/register").status_code, 200)
                get_db.assert_not_called()
                sys.modules.pop("app", None)


if __name__ == "__main__":
    unittest.main()
