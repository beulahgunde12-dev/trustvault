# API

Base path `/api`. Send `Authorization: Bearer <token>` from `POST /api/auth/login`.
Inaccessible or unknown document ids return `404`; known-but-insufficient level returns `403`.
"Owner of doc" = `documents.owner_id` is the caller; "edit/read grant" = an active row in `grants`.

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /auth/login` | anyone | 5 failures lock the user 5 min. Audited. |
| `POST /auth/logout` | any signed-in user | Revokes this token. |
| `GET /me` | any signed-in user | |
| `GET /users/directory` | role `owner` | Active non-admin users, for choosing grantees. |
| `POST /documents` | role `owner` | multipart `file`, `name?`, `category`. Validated. |
| `GET /documents` | any signed-in user | `q, owner, category, created_from, created_to, trash, limit, offset`. Only docs the caller owns or holds a grant on. `trash=true` = caller's own deleted docs. |
| `GET /documents/{id}` | owner of doc, edit grant, read grant | Metadata + versions; `grants` for owner only. |
| `PATCH /documents/{id}` | owner of doc, edit grant | `name`, `category`; unknown fields rejected. |
| `POST /documents/{id}/versions` | owner of doc, edit grant | multipart `file`. |
| `GET /documents/{id}/download?version=n` | owner of doc, edit grant, read grant | Forced attachment. Audited, refusals too. |
| `DELETE /documents/{id}` | owner of doc | Soft delete. |
| `POST /documents/{id}/restore` | owner of doc | |
| `GET /documents/{id}/grants` | owner of doc | |
| `PUT /documents/{id}/grants/{user_id}` | owner of doc | `{"level":"read"|"edit"}`. Not to admins or self; `edit` only to owner-role users. |
| `DELETE /documents/{id}/grants/{user_id}` | owner of doc | Immediate. |
| `GET /documents/{id}/history` | owner of doc | Audit rows for this doc, including refused attempts. |
| `GET /admin/users` | role `admin` | |
| `POST /admin/users` | role `admin` | Roles cannot be changed afterwards. |
| `PATCH /admin/users/{id}` | role `admin` | `active`, `new_password`; both revoke that user's sessions. |
| `GET /admin/audit` | role `admin` | Filters `action, outcome, actor, document_id, before_seq, limit`. |
| `GET /admin/audit/verify` | role `admin` | Recomputes the HMAC chain; returns `ok` and head hash. |
| `GET /admin/alerts` | role `admin` | Repeated denials, failed logins, bulk downloads, bursts of grants (last hour). |
| `GET /healthz` | anyone | |

Audited actions: login, logout, upload, view, update, new_version, download, delete, restore, grant,
grant_changed, revoke, list_grants, view_history, user_created, user_activated, user_deactivated,
password_reset. Outcomes: success, denied, failure.
