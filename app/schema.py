"""Bringing the database schema up to date at startup.

Until now the schema came from db.create_all(), which creates missing *tables*
and silently ignores missing *columns*. Adding a field to an existing model
would therefore work on a fresh install and fail on a real one, at query time,
in production — which is exactly the moment there is client data to lose.

Alembic owns the schema now. Startup handles three cases:

  fresh database      no tables          -> upgrade to head
  existing database   tables, unstamped  -> stamp head, do not re-run migrations
  managed database    already stamped    -> upgrade to head

The middle case is the one that matters. A database built by create_all()
already has the tables the first migration would create, so running that
migration would fail. Stamping records "you are already here" without
executing anything.

Upgrading at startup suits a single-operator, single-worker deployment. It
would need rethinking behind several workers, where two could migrate at once.
"""
import logging
from pathlib import Path

from alembic.migration import MigrationContext
from flask_migrate import stamp as alembic_stamp
from flask_migrate import upgrade as alembic_upgrade
from sqlalchemy import inspect

log = logging.getLogger(__name__)

# Present in every schema this app has ever had, so its existence is a reliable
# signal that a database predates migrations rather than being empty.
SENTINEL_TABLE = "reports"


def database_state(engine):
    """One of: 'empty', 'unstamped', 'managed'."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    if not tables - {"alembic_version"}:
        return "empty"

    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()

    return "managed" if current else "unstamped"


def migrations_directory(app):
    return Path(app.root_path).parent / "migrations"


def migrations_available(app):
    """Whether a migrations directory exists to run against."""
    return (migrations_directory(app) / "env.py").exists()


def baseline_revision(app):
    """The first migration in the chain — the one with no predecessor.

    A database created by create_all() before migrations existed has exactly
    the schema this revision describes, so it is the honest place to stamp.
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    directory = migrations_directory(app)
    config = Config(str(directory / "alembic.ini"))
    config.set_main_option("script_location", str(directory))
    script = ScriptDirectory.from_config(config)

    bases = script.get_bases()
    return bases[0] if bases else None


def prepare(app, db):
    """Make the schema current. Never raises — startup shouldn't die on this.

    Catches BaseException rather than Exception on purpose: flask_migrate's
    helpers call sys.exit() on failure, and SystemExit doesn't inherit from
    Exception. Letting that through kills the process — including `flask db
    init`, which runs this hook while loading the app and would exit before it
    could create the directory it was complaining about.
    """
    if not migrations_available(app):
        # A checkout without migrations, or the moment before `flask db init`.
        log.info("No migrations directory; creating tables directly.")
        db.create_all()
        return "created"

    try:
        state = database_state(db.engine)

        if state == "unstamped":
            # Built by create_all() before migrations existed. Its schema
            # matches the first migration, so record that revision — NOT head.
            # Stamping head would claim every later migration had already run,
            # and their columns would be missing forever, failing at query time.
            baseline = baseline_revision(app)
            if baseline is None:
                log.warning("No baseline migration found; leaving schema as-is.")
                return "unknown"
            log.info("Existing database found without a stamp; marking baseline %s.", baseline)
            alembic_stamp(revision=baseline)
            # Then apply everything after the baseline.
            alembic_upgrade()
            return "stamped-and-upgraded"

        alembic_upgrade()
        log.info("Database schema up to date (was %s).", state)
        return "upgraded"

    except BaseException as exc:
        log.warning("Could not apply migrations (%s). Falling back to create_all().", exc)
        try:
            db.create_all()
            return "created"
        except Exception:
            log.exception("Could not prepare the database schema.")
            return "failed"
