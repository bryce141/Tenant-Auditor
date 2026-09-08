# Working in this repo

Flask app that audits Microsoft 365 tenants via the Graph API and scores them
against CIS benchmark controls. See README.md for what it does and how to run it;
this file covers the conventions worth knowing before changing anything.

## Layout

`run.py` creates the app (`app/__init__.py` factory). Everything lives in `app/`:

- `checks/` — one module per category, each exposing `run_all(client)`
- `services/` — Graph client, orchestration, scoring, export, comparison
- `routes/` — one blueprint per section
- `models/` — `Report` + `ReportCheck`, and `Tenant`

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

## Credentials

Tenant secrets are Fernet-encrypted with a key derived from `SECRET_KEY`
(`services/crypto.py`). If `SECRET_KEY` changes, stored secrets can't be
decrypted and must be re-entered — decryption failure says so rather than
returning junk. This protects a leaked database file, not someone who already
holds the application environment.

`config.json` and `.env` are gitignored and must stay that way. A live secret
was committed to this repo once and the history had to be rewritten.
