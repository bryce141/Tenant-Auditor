"""Tests for schema preparation at startup.

The schema used to come from db.create_all(), which creates missing tables and
silently ignores missing columns — so adding a field worked on a fresh install
and failed on a real one, at query time, with client data already in it.

The subtle failure guarded here: stamping an existing database at *head* rather
than at the baseline. It looks right, the app starts, and every migration after
the first is skipped permanently.
"""
import os
import sqlite3
import tempfile

import pytest

from app.schema import baseline_revision, database_state


@pytest.fixture
def app():
    """A real on-disk database, since migrations don't apply to :memory:."""
    from app import create_app

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)

    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{path}"
    try:
        application = create_app()
        application.config["_db_path"] = path
        yield application
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        if os.path.exists(path):
            os.unlink(path)


def columns(path, table):
    conn = sqlite3.connect(path)
    try:
        return [r[1] for r in conn.execute(f"pragma table_info({table})")]
    finally:
        conn.close()


def stamp_of(path):
    conn = sqlite3.connect(path)
    try:
        return list(conn.execute("select version_num from alembic_version"))[0][0]
    except Exception:
        return None
    finally:
        conn.close()


def test_a_fresh_database_is_built_and_stamped(app):
    path = app.config["_db_path"]

    assert "reports" in sqlite3.connect(path).execute(
        "select name from sqlite_master where type='table' and name='reports'").fetchone()
    assert stamp_of(path) is not None, "a new database should be recorded as migrated"


def test_new_columns_are_present_on_a_fresh_database(app):
    """The column added after the baseline must exist, not just the baseline ones."""
    assert "client_name" in columns(app.config["_db_path"], "tenants")


def test_startup_is_idempotent(app):
    """Restarting must not re-run migrations or disturb the stamp."""
    from app import create_app

    before = stamp_of(app.config["_db_path"])
    create_app()
    assert stamp_of(app.config["_db_path"]) == before


def test_baseline_is_the_first_revision_not_the_latest(app):
    """Stamping head on an old database would skip every later migration."""
    from flask_migrate import current

    with app.app_context():
        base = baseline_revision(app)

    assert base is not None
    assert base != stamp_of(app.config["_db_path"]), (
        "baseline must differ from head, or the guard proves nothing — "
        "add a second migration if this fails")


def test_state_detection(app):
    from app import db

    with app.app_context():
        assert database_state(db.engine) == "managed"


def test_unstamped_database_is_detected_and_brought_forward():
    """A database created the old way: tables present, no alembic_version."""
    from app import create_app, db

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)

    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{path}"
    try:
        # Build the schema the old way, then strip the stamp to simulate a
        # database that predates migrations.
        app = create_app()
        conn = sqlite3.connect(path)
        conn.execute("drop table if exists alembic_version")
        conn.execute("alter table tenants drop column client_name")
        conn.commit()
        conn.close()

        assert stamp_of(path) is None
        assert "client_name" not in columns(path, "tenants")

        app = create_app()   # startup should stamp the baseline, then upgrade

        assert stamp_of(path) is not None, "should have been stamped"
        assert "client_name" in columns(path, "tenants"), (
            "post-baseline migrations must be applied, not skipped — this is "
            "what stamping head instead of base would break")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        if os.path.exists(path):
            os.unlink(path)


def test_existing_rows_survive_being_brought_forward():
    """The whole point: no data loss when the schema moves."""
    from app import create_app, db
    from app.models.report import Report

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)

    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{path}"
    try:
        app = create_app()
        with app.app_context():
            for i in range(5):
                db.session.add(Report(tenant_id="dir-1", report_type="full",
                                      status="complete", score=40 + i))
            db.session.commit()

        conn = sqlite3.connect(path)
        conn.execute("drop table if exists alembic_version")
        conn.execute("alter table tenants drop column client_name")
        conn.commit()
        conn.close()

        app = create_app()
        with app.app_context():
            assert Report.query.count() == 5, "rows must survive the upgrade"
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        if os.path.exists(path):
            os.unlink(path)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
