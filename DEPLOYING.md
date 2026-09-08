# Deploying

This is an internal tool that holds client credentials, not a public website.
Deploy it somewhere only you can reach, put a password on it, and give it TLS.

The steps below were verified by running the exact production command against a
simulated fresh disk: schema built from migrations, first-run setup enforced,
protected routes closed, session cookie issued `Secure; HttpOnly; SameSite=Lax`.

---

## Render (the path `render.yaml` describes)

**1. Create the service**

Render → **New** → **Blueprint** → point it at this repository. It reads
`render.yaml` and provisions a Python web service, a 1 GB persistent disk at
`/var/data`, and sets `DATA_DIR`, `DATABASE_URL`, `SECRET_KEY`, and
`SESSION_COOKIE_SECURE`.

**2. Pick a paid instance, not free**

Free instances sleep after inactivity. That means a ~50 second first request,
and nothing scheduled ever runs. The smallest paid tier is enough — this is one
worker serving one person.

**3. Deploy, then immediately open the URL and create the administrator**

Until that account exists, `/setup` is reachable by anyone who finds the URL.
It closes permanently once an account is created. Do it before you walk away.

**4. Add your tenant**

**Tenants → Add tenant**. Its app registration needs the Graph permissions in
the README, with admin consent granted. **Test connection** verifies before
saving.

**5. Optional: a custom domain**

`audit.yourdomain.com` reads better on a link you send a client than
`tenant-auditor-xxxx.onrender.com`. Render issues the certificate.

---

## Things that will catch you out

**Never change `SECRET_KEY` after the first deploy.** It signs sessions *and*
derives the key that encrypts stored tenant secrets. Changing it logs everyone
out and makes every stored credential undecryptable — they must be re-entered.
Take a copy of the generated value somewhere safe.

**The disk is the database.** `DATABASE_URL` points at `/var/data` because
Flask's default instance folder is ephemeral on Render: without it, every
redeploy silently starts your audit history over. Don't "tidy" that setting.

**Scheduled audits can't be a second Render service.** A Render disk attaches to
exactly one service, so a cron job gets its own empty filesystem and its own
empty database — it would audit nothing and email a digest saying so. Options:

- run the audit from a machine that has the data (your Mac, a VPS) via the
  crontab in the README;
- move to Postgres so two services can share it;
- trigger a run over HTTP from an external scheduler.

**Running production config locally will look broken.** With
`SESSION_COOKIE_SECURE=true` a browser refuses to send the session cookie over
`http://`, so you sign in and immediately bounce back to the login page. That's
correct behaviour. Leave the variable unset locally.

---

## Backups

The whole application is one SQLite file. Backing up is copying it:

```bash
sqlite3 /var/data/tenant_auditor.db ".backup /var/data/backup-$(date +%F).db"
```

Worth doing before an upgrade. The schema migrates itself on start, and that
has been tested against a database with real data in it, but a copy costs
nothing and this file holds every client's audit history.

---

## Verifying a deploy

```
GET  /            → 302 to /setup   (before an admin exists)
GET  /dashboard/  → 302 to /login   (never 200 while signed out)
GET  /tenants/    → 302 to /login
```

If `/dashboard/` or `/tenants/` returns 200 without signing in, stop and
investigate before adding any tenant: those pages carry directory and client
identifiers.

After signing in, **Run Full Audit** should complete in under a minute and the
score should match what `Reports → Report` shows for the same run.
