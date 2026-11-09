# TrustVault

Secure document sharing where the server decides every access, and every attempt
(including refused ones) lands in a tamper-evident audit log.

Stack: Python 3.11+, FastAPI, SQLite (WAL), vanilla JS front end. One process, no build step.

## Requirements

- Python 3.11 or newer (developed on 3.12) and pip
- Optional: Docker
- Python packages (`requirements.txt`): fastapi, uvicorn, python-multipart, httpx, pytest

## Run it locally (clean clone)

```bash
git clone <your-repo-url> trustvault && cd trustvault
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export TV_AUDIT_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"   # PowerShell: $env:TV_AUDIT_KEY="<hex>"
export TV_SEED_PASSWORD="choose-a-demo-password"      # optional; default is ChangeMe-Demo-2026!
python -m app.seed                   # creates the schema (schema.sql), demo users and 3 documents
uvicorn app.main:app --port 8000
```

Open http://localhost:8000.

Keep the same `TV_AUDIT_KEY` between runs: it is the key that makes the audit chain verifiable.
If it changes, old audit rows fail verification.

### Demo accounts (password = `TV_SEED_PASSWORD`, default `ChangeMe-Demo-2026!`)

| Role   | Username | What to try |
|--------|----------|-------------|
| admin  | `admin`  | Activity tab, user management. Cannot open any document. |
| owner  | `alice`  | Owns 2 docs; shared "Salary letter" with bob. Share / revoke. |
| owner  | `carol`  | Owns "Customer contract". Alice and Bob cannot see it. |
| viewer | `bob`    | Sees only the salary letter. Cannot upload. |

Change the demo password on any public deployment.

## Tests

```bash
python -m pytest -q                  # 86 tests, about 35 s (most of it is password hashing)
python scripts/mutation_check.py     # removes each authorisation check in turn; every mutant must be KILLED
```

`mutation_check.py` does what a reviewer might do: takes one `require(...)` call out of
`app/main.py`, runs the suite, and reports whether any test noticed. Expected last line:
`10/10 authorisation checks are covered by tests`.

## Deploy (Docker)

```bash
docker build -t trustvault .
docker run -p 8000:8000 -v trustvault-data:/data \
  -e TV_AUDIT_KEY="<64 hex chars>" -e TV_SEED_PASSWORD="<demo password>" trustvault
```

On Render / Fly / Railway: deploy the Dockerfile, mount a persistent disk at `/data`, set
`TV_AUDIT_KEY` and `TV_SEED_PASSWORD`, serve over HTTPS, and set `TV_TRUST_PROXY=1` only if the
platform proxy overwrites `X-Forwarded-For`. With `TV_ENV=prod` (set in the Dockerfile) the app
refuses to start without a real `TV_AUDIT_KEY`. Single instance only (SQLite + local disk).

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `TV_ENV` | `dev` | `prod` refuses to start with the dev audit key |
| `TV_DB` | `data/trustvault.db` | SQLite file |
| `TV_STORAGE` | `data/files` | Uploaded files (never served statically) |
| `TV_AUDIT_KEY` | dev value | HMAC key for the audit chain; keep it out of DB backups |
| `TV_SEED_PASSWORD` | `ChangeMe-Demo-2026!` | Password for seeded demo users |
| `TV_MAX_UPLOAD` | 10485760 | Max upload bytes |
| `TV_SESSION_HOURS` | 8 | Session lifetime |
| `TV_TRUST_PROXY` | 0 | Trust `X-Forwarded-For` for audit IPs |

## Folder layout

```
trustvault/
  README.md  THREATS.md  API.md  PROMPTS.md
  requirements.txt  Dockerfile  schema.sql
  app/
    main.py        routes (each document route calls authz.require first)
    authz.py       THE authorisation decision
    audit.py       HMAC-chained append-only audit log + verifier
    db.py          connections, re-entrant BEGIN IMMEDIATE transactions
    security.py    scrypt passwords, session token hashing
    validation.py  upload validation
    storage.py     random-key file storage
    seed.py        demo data
  static/          index.html, app.js, style.css (no inline script, CSP-safe)
  tests/           authz, audit, upload tests
  scripts/mutation_check.py
```

## Roles

- **admin**: creates/deactivates users, resets passwords, reads the global audit log and alerts,
  verifies the audit chain. No access to document content or metadata, and cannot be granted any.
  Separation of duties: whoever runs the system cannot read the files.
- **owner**: uploads documents, owns them, shares them (read or edit) with named owner/viewer
  users, revokes, deletes/restores, sees the full history of their own documents including refused attempts.
- **viewer**: only opens documents explicitly shared with them, read-only.

## Permission model (in my own words)

Per-document grants. No folders, groups or inheritance, deliberately: every "why can they see
this?" has exactly one answer, a row in `grants` or ownership. Levels: `read` < `edit` < `owner`
(owner is implicit, not a grant). `edit` = rename/recategorise and upload new versions; only
owners share, revoke, delete or restore; edit grants go only to owner-role users.
One function, `authz.require()`, decides. It runs inside the same `BEGIN IMMEDIATE` transaction as
the action it protects, so a concurrent revoke cannot slip between check and write. Refusals are
audited, then returned as 404 (no access: hides existence) or 403 (can see it, lacks the level).

### What "revoke is immediate" means, and what it costs

No pre-signed URLs, cached decisions or long-lived links. The server streams the file after a live
DB check on every request, so revoking works on the next request even with a still-valid session.
Cost: every download hits the app and DB (no CDN offload), and a download already in flight cannot
be recalled (files are capped at 10 MB and read in one go).

### Audit protection

Append-only via SQL triggers, plus an HMAC hash chain whose key is not in the database. Admin
verification endpoint and UI. Limits are in THREATS.md.

## Not built (on purpose)

External sharing (needs its own threat model: expiring links, recipient verification), groups and
folders, MFA, encryption at rest, antivirus scanning, retention/purge jobs, multi-instance deployment,
an AI sharing assistant. If you add AI suggestions: it may only propose, a person must confirm, both
suggestion and decision must be audited, and `authz.require()` must stay the only way access is granted.

## Known gaps

- Unauthenticated requests are rejected but not individually audited (no actor).
- No rate limiting except login lockout.
- Files not encrypted at rest.
- Audit tail truncation needs an off-box copy of the head hash to detect.
