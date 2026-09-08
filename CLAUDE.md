# Working in this repo

Flask app that audits Microsoft 365 tenants via the Graph API and scores them
against CIS benchmark controls. See README.md for what it does and how to run it;
this file covers the conventions worth knowing before changing anything.

## Layout

`run.py` creates the app (`app/__init__.py` factory). Everything lives in `app/`:

- `checks/` — one module per category, each exposing `run_all(client)`
- `services/` — Graph client, orchestration, scoring, export, comparison,
  digest, mail, formatting, crypto, remediation
- `routes/` — one blueprint per section
- `models/` — `Report` + `ReportCheck`, `Tenant`, `AdminUser`, `Branding`
- `cli.py` — `flask audit` / `digest` / `scheduled-run`
- `schema.py` — Alembic bootstrap at startup

Local dev serves on **5001**, not 5000: macOS ControlCenter holds 5000. `PORT`
overrides it. Deployment notes are in DEPLOYING.md.

There is no v1 any more. `main.py`, `app.py`, `auditor/`, and root `templates/`
were removed; anything referring to them is out of date.

## The check contract

Every check returns a dict with these keys, and `run_all` returns a list of them:

```python
{"check_name", "display_name", "category", "status", "points_earned",
 "points_possible", "summary", "issues", "details", "cis_reference"}
```

`status` is one of `pass | warn | fail | skip | info`.

**`skip` is not a failure.** A missing permission, an unlicensed feature, or an
unprovisioned workload means the control was never measured. Skips are excluded
from the scoring denominator so a tenant is never penalised for a check that
couldn't run — `points_possible` stays set so the UI can still show the weight.

`GraphClient` raises `GraphError` on failure; the `@check` decorator in
`checks/base.py` turns that into the standard skip result. Declare a check's
identity in the decorator and let the body assume the data arrived. Catch
`GraphError` locally only when the check can genuinely continue without that
call — `check_secure_score` without control profiles, `check_stale_accounts`
without `signInActivity`.

A check deriving several results from one call must list the extras in the
decorator's `also=`, or they vanish from the report when the call fails, making
the audit look smaller instead of showing the control went unmeasured.

## Onboarding material

Four places name the Graph permission list: `scripts/check_permissions.py`
(the source of truth), both setup scripts, and ONBOARDING.md. Adding a
permission to the code and forgetting the scripts means an onboarded tenant
silently skips checks and the client's admin has to be asked back.
`tests/test_onboarding_docs.py` fails in both directions — missing, and
requesting more than is used.

The setup scripts resolve permission IDs from the Graph service principal at
runtime. Don't hardcode GUIDs; a test forbids it.

## Adding a check

1. Write it in the right `checks/` module, decorated with `@check(...)`
2. If scored, add it to `CIS_MAP` in `services/scoring.py` with its weight
3. Add guidance to `services/remediation.py` — **the test suite fails if you
   don't**, in both directions, because guidance keys silently drifting away
   from check names is exactly how the help buttons died once already

Adding a whole category also needs an entry in `CATEGORY_MAP`
(`services/report_runner.py`) and a blueprint in `routes/`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

`tests/test_check_contract.py` is the important one: it runs every check module
against a client where all Graph calls fail and one where they all succeed
empty, asserting results stay well-formed, scores never exceed their weight, and
no check disappears on failure. It covers all 28 checks without a tenant, and it
is what makes refactoring the check modules safe.

The suite must pass under `-W error::DeprecationWarning`.

## Check what the API actually returns

Six bugs on this project came from real Graph responses and none from the test
suite, because fixtures encoded assumptions rather than the API. The worst was
`allowedToUseSSPR`, a boolean compared against the string `"none"` — and
`False != "none"` is True, so a tenant with SSPR switched off passed with full
marks. A false pass is the worst failure an audit tool has.

Before trusting a field, read its type and enum values on Microsoft Learn.
Fetching the resource page takes under a minute and twice contradicted a
confident assumption. `clientAppTypes` is the other example: `"all"` includes
legacy authentication, so matching only `exchangeActiveSync`/`other` told
correctly-configured tenants they were exposed.

Where a check can fail open or closed, test both states explicitly.

## Things that will bite you

- **Never call `datetime.utcnow()`** — use `app.utils.utcnow()`. The model
  columns are naive; the stdlib replacement returns aware datetimes and mixing
  them raises `TypeError` on comparison.
- **Background threads have no request context.** The active tenant is resolved
  in the request and passed into `run_category` / `run_full`. Don't try to read
  the session from a worker.
- **Run progress is a module-level dict**, so gunicorn runs `--workers 1
  --threads 4`. A second worker process gets its own copy and progress polls hit
  the wrong one at random.
- **Graph batch responses are not ordered.** `batch_get` maps them back by
  request id; matching by position would attribute one user's data to another.
- **Never render internal identifiers.** Report types and timestamps go through
  `services/formatting.py` as Jinja filters.
- **Escape tenant-supplied strings in the HTML export.** Display names come from
  the audited directory and must not be able to inject markup into a document
  someone forwards to a client.

## Scheduling

`app/cli.py` provides `flask audit`, `flask digest`, and `flask scheduled-run`,
driven by cron rather than an in-process scheduler — see the README for why.
`audit` exits non-zero when any tenant fails, so don't swallow that: it's the
only signal cron has that the tool stopped working.

Anything that renders text from Microsoft needs `app.utils.strip_html` first.
Secure Score remediation arrives as HTML, and it reaches three surfaces now
(security page, client report, email digest).

## Database schema

Alembic owns the schema. `db.create_all()` is no longer the source of truth —
it creates missing *tables* and silently ignores missing *columns*, so adding a
field worked on a fresh install and failed on a real one, at query time, with
client data already in it.

Changing a model means generating a migration:

```bash
FLASK_APP=run.py flask db migrate -m "what changed"
FLASK_APP=run.py flask db upgrade          # startup does this too
```

**Read the generated migration before committing it.** Autogenerate misses
things — server defaults, type changes, renames it reads as drop-plus-add.

`app/schema.py` runs at startup and handles three cases: an empty database is
built from migrations; a stamped one is upgraded; and one built by the old
`create_all()` path is stamped **at the baseline revision, then upgraded**.
Stamping at *head* instead would look fine and skip every migration after the
first, permanently. `tests/test_schema.py` guards that.

It catches `BaseException`, not `Exception`: flask_migrate's helpers call
`sys.exit()` on failure, and `SystemExit` doesn't inherit from `Exception` —
letting it through killed `flask db init` itself.

Tests use in-memory databases and build their schema with `create_all()`
directly, chosen by inspecting the URI rather than `app.config["TESTING"]`,
because fixtures set that flag after `create_app()` has returned.

## Authentication

`app/auth/session_auth.py` installs a `before_request` guard that requires a
session for **every** endpoint except those named in `PUBLIC_ENDPOINTS`. It is
fail-closed on purpose: protecting routes with a decorator means a route added
later is exposed until someone remembers to annotate it, and that failure is
silent. Forgetting here locks people out instead, which gets noticed.

If you add a genuinely public endpoint, add it to `PUBLIC_ENDPOINTS` — and
think about whether it should be.

An install with no `AdminUser` serves nothing but `/setup`, so adding auth
can't leave a fresh deployment as open as it was before.

There is no CSRF library. `SESSION_COOKIE_SAMESITE = "Lax"` stops the session
cookie riding along on cross-site POST and DELETE, which covers the mutating
endpoints. If cross-site GET ever mutates anything, that reasoning breaks and
you need real CSRF tokens.

Tests that exercise routes need `tests/conftest.py::signed_in_client`.

## Credentials

Tenant secrets are Fernet-encrypted with a key derived from `SECRET_KEY`
(`services/crypto.py`). If `SECRET_KEY` changes, stored secrets can't be
decrypted and must be re-entered — decryption failure says so rather than
returning junk. This protects a leaked database file, not someone who already
holds the application environment.

`config.json` and `.env` are gitignored and must stay that way. A live secret
was committed to this repo once and the history had to be rewritten.
