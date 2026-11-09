"""TrustVault API. See API.md for who may call what."""
import hashlib
import re
import uuid
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import storage
from .audit import audit, verify_chain
from .authz import require
from .config import BASE, DEV_AUDIT_KEY, settings
from .db import create_user, get_db, init_db, tx
from .errors import Refused
from .security import DUMMY_HASH, hash_password, hash_token, new_token, verify_password
from .util import utc_plus, utcnow
from .validation import ValidationError, clean_text, safe_filename, validate_upload

if settings.env == "prod" and settings.audit_key == DEV_AUDIT_KEY.encode():
    raise RuntimeError("Refusing to start: set TV_AUDIT_KEY when TV_ENV=prod")

app = FastAPI(title="TrustVault", docs_url=None, redoc_url=None)
init_db()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------- auth
def current_user(request: Request, db=Depends(get_db)) -> dict:
    h = request.headers.get("authorization", "")
    if not h.lower().startswith("bearer "):
        raise HTTPException(401, "Authentication required")
    th = hash_token(h[7:].strip())
    row = db.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>? AND u.active=1",
        (th, utcnow())).fetchone()
    if not row:
        raise HTTPException(401, "Authentication required")
    user = dict(row)
    user["_token_hash"] = th
    return user


def roles(*allowed: str):
    def dep(user=Depends(current_user)):
        if user["role"] not in allowed:
            raise HTTPException(403, "Your role cannot do that")
        return user
    return dep


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, db=Depends(get_db)):
    uname = body.username.strip().lower()
    with tx(db):
        u = db.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        if u and u["locked_until"] and u["locked_until"] > utcnow():
            audit(db, None, "login", "denied", actor_name=uname[:64], request=request,
                  detail={"reason": "locked"})
            raise Refused(429, "Too many attempts. Try again later.")
        ok = verify_password(body.password, u["password_hash"] if u else DUMMY_HASH)
        if not (u and ok and u["active"]):
            if u:
                fails = u["failed_logins"] + 1
                locked = utc_plus(minutes=settings.lockout_minutes) \
                    if fails >= settings.lockout_attempts else None
                db.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                           (0 if locked else fails, locked, u["id"]))
            audit(db, None, "login", "denied", actor_name=uname[:64], request=request,
                  detail={"reason": "bad_credentials"})
            raise Refused(401, "Invalid username or password")
        db.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (u["id"],))
        token = new_token()
        db.execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)",
                   (hash_token(token), u["id"], utcnow(), utc_plus(hours=settings.session_hours)))
        audit(db, dict(u), "login", "success", request=request)
    return {"token": token, "user": _public_user(u)}


@app.post("/api/auth/logout")
def logout(request: Request, user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (user["_token_hash"],))
        audit(db, user, "logout", "success", request=request)
    return {"ok": True}


def _public_user(u) -> dict:
    return {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
            "role": u["role"]}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return _public_user(user)


@app.get("/api/users/directory")
def directory(user=Depends(roles("owner")), db=Depends(get_db)):
    """People an owner may share with (active, non-admin, not themselves)."""
    rows = db.execute("SELECT id,username,display_name,role FROM users "
                      "WHERE active=1 AND role!='admin' AND id!=? ORDER BY username",
                      (user["id"],)).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------- documents
async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(413, "File is too large")
    return data


def _validate_or_refuse(db, user, request, action, doc_id, filename, data) -> str:
    try:
        return validate_upload(filename, data, settings.max_upload_bytes)
    except ValidationError as e:
        audit(db, user, action, "failure", doc_id=doc_id, request=request,
              detail={"reason": "validation", "message": str(e), "filename": (filename or "")[:120]})
        raise Refused(400, str(e))


def _doc_dict(d) -> dict:
    return {k: d[k] for k in ("id", "name", "category", "current_version",
                              "created_at", "updated_at")}


@app.post("/api/documents", status_code=201)
async def upload_document(request: Request, file: UploadFile = File(...),
                          name: str | None = Form(None), category: str = Form("general"),
                          user=Depends(roles("owner")), db=Depends(get_db)):
    data = await _read_upload(file)
    key = None
    try:
        with tx(db):
            fname = _validate_or_refuse(db, user, request, "upload", None, file.filename, data)
            try:
                dname = clean_text(name or fname, 120, "name")
                cat = clean_text(category, 50, "category")
            except ValidationError as e:
                raise Refused(400, str(e))
            key, sha = storage.save(data)
            doc_id, now = uuid.uuid4().hex, utcnow()
            db.execute("INSERT INTO documents(id,name,category,owner_id,current_version,"
                       "created_at,updated_at) VALUES (?,?,?,?,1,?,?)",
                       (doc_id, dname, cat, user["id"], now, now))
            db.execute("INSERT INTO document_versions(document_id,version,storage_key,size,"
                       "sha256,original_filename,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?,?)",
                       (doc_id, 1, key, len(data), sha, fname, user["id"], now))
            audit(db, user, "upload", "success", doc_id=doc_id, request=request,
                  detail={"name": dname, "category": cat, "size": len(data), "sha256": sha})
        return {"id": doc_id, "name": dname, "category": cat, "version": 1}
    except BaseException:
        if key and not db.execute("SELECT 1 FROM document_versions WHERE storage_key=?", (key,)).fetchone():
            storage.remove(key)
        raise


_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@app.get("/api/documents")
def search_documents(q: str | None = Query(None, max_length=100),
                     owner: str | None = Query(None, max_length=64),
                     category: str | None = Query(None, max_length=50),
                     created_from: str | None = None, created_to: str | None = None,
                     trash: bool = False, limit: int = Query(50, ge=1, le=100),
                     offset: int = Query(0, ge=0),
                     user=Depends(current_user), db=Depends(get_db)):
    """Only documents the caller owns or holds an active grant on can ever appear."""
    for d in (created_from, created_to):
        if d and not _DATE.match(d):
            raise HTTPException(422, "Dates must be YYYY-MM-DD")
    sql = ("SELECT d.id, d.name, d.category, d.created_at, d.updated_at, d.current_version, "
           "u.username AS owner, "
           "CASE WHEN d.owner_id=:uid THEN 'owner' ELSE (SELECT g.level FROM grants g "
           "WHERE g.document_id=d.id AND g.user_id=:uid AND g.revoked_at IS NULL) END AS my_level "
           "FROM documents d JOIN users u ON u.id=d.owner_id "
           "WHERE (d.owner_id=:uid OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id=d.id "
           "AND g.user_id=:uid AND g.revoked_at IS NULL))")
    p: dict = {"uid": user["id"], "limit": limit, "offset": offset}
    sql += (" AND d.owner_id=:uid AND d.deleted_at IS NOT NULL" if trash
            else " AND d.deleted_at IS NULL")
    if q:
        p["q"] = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " AND d.name LIKE :q ESCAPE '\\'"
    if owner:
        p["owner"] = owner.lower()
        sql += " AND u.username=:owner"
    if category:
        p["cat"] = category
        sql += " AND d.category=:cat"
    if created_from:
        p["cf"] = created_from
        sql += " AND d.created_at>=:cf"
    if created_to:
        p["ct"] = created_to + "T23:59:59"
        sql += " AND d.created_at<=:ct"
    sql += " ORDER BY d.updated_at DESC LIMIT :limit OFFSET :offset"
    return [dict(r) for r in db.execute(sql, p)]


@app.get("/api/documents/{doc_id}")
def get_document(doc_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, level = require(db, user, doc_id, "read", request, "view")  # MUT
        versions = [dict(r) for r in db.execute(
            "SELECT v.version, v.size, v.sha256, v.original_filename, v.created_at, "
            "u.username AS uploaded_by FROM document_versions v JOIN users u ON u.id=v.uploaded_by "
            "WHERE v.document_id=? ORDER BY v.version DESC", (doc["id"],))]
        out = {**_doc_dict(doc), "my_level": level, "versions": versions,
               "owner": db.execute("SELECT username FROM users WHERE id=?",
                                   (doc["owner_id"],)).fetchone()["username"]}
        if level == "owner":
            out["grants"] = _grants(db, doc["id"])
        audit(db, user, "view", "success", doc_id=doc["id"], request=request)
    return out


class UpdateIn(Strict):
    name: str | None = Field(None, max_length=120)
    category: str | None = Field(None, max_length=50)


@app.patch("/api/documents/{doc_id}")
def update_document(doc_id: str, body: UpdateIn, request: Request,
                    user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, _ = require(db, user, doc_id, "edit", request, "update")  # MUT
        try:
            name = clean_text(body.name, 120, "name") if body.name is not None else doc["name"]
            cat = clean_text(body.category, 50, "category") if body.category is not None else doc["category"]
        except ValidationError as e:
            raise Refused(400, str(e))
        db.execute("UPDATE documents SET name=?, category=?, updated_at=? WHERE id=?",
                   (name, cat, utcnow(), doc["id"]))
        audit(db, user, "update", "success", doc_id=doc["id"], request=request,
              detail={"name": [doc["name"], name], "category": [doc["category"], cat]})
    return {"id": doc["id"], "name": name, "category": cat}


@app.post("/api/documents/{doc_id}/versions", status_code=201)
async def new_version(doc_id: str, request: Request, file: UploadFile = File(...),
                      user=Depends(current_user), db=Depends(get_db)):
    data = await _read_upload(file)
    key = None
    try:
        with tx(db):
            doc, _ = require(db, user, doc_id, "edit", request, "new_version")  # MUT
            fname = _validate_or_refuse(db, user, request, "new_version", doc["id"], file.filename, data)
            key, sha = storage.save(data)
            ver, now = doc["current_version"] + 1, utcnow()
            db.execute("INSERT INTO document_versions(document_id,version,storage_key,size,"
                       "sha256,original_filename,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?,?)",
                       (doc["id"], ver, key, len(data), sha, fname, user["id"], now))
            db.execute("UPDATE documents SET current_version=?, updated_at=? WHERE id=?",
                       (ver, now, doc["id"]))
            audit(db, user, "new_version", "success", doc_id=doc["id"], request=request,
                  detail={"version": ver, "size": len(data), "sha256": sha})
        return {"id": doc["id"], "version": ver}
    except BaseException:
        if key and not db.execute("SELECT 1 FROM document_versions WHERE storage_key=?", (key,)).fetchone():
            storage.remove(key)
        raise


@app.get("/api/documents/{doc_id}/download")
def download(doc_id: str, request: Request, version: int | None = Query(None, ge=1),
             user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, _ = require(db, user, doc_id, "read", request, "download")  # MUT
        v = db.execute("SELECT * FROM document_versions WHERE document_id=? AND version=?",
                       (doc["id"], version or doc["current_version"])).fetchone()
        if not v:
            audit(db, user, "download", "failure", doc_id=doc["id"], request=request,
                  detail={"reason": "no_such_version", "version": version})
            raise Refused(404, "Not found")
        audit(db, user, "download", "success", doc_id=doc["id"], request=request,
              detail={"name": doc["name"], "version": v["version"], "sha256": v["sha256"]})
    try:
        data = storage.read(v["storage_key"])
    except OSError:
        audit(db, user, "download", "failure", doc_id=doc["id"], request=request,
              detail={"reason": "file_missing"})
        raise HTTPException(500, "File is unavailable")
    if hashlib.sha256(data).hexdigest() != v["sha256"]:
        audit(db, user, "download", "failure", doc_id=doc["id"], request=request,
              detail={"reason": "integrity_mismatch"})
        raise HTTPException(500, "File failed its integrity check")
    fname = re.sub(r'[^A-Za-z0-9._ -]', "_", v["original_filename"])
    return Response(data, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{fname}"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


@app.delete("/api/documents/{doc_id}")
def delete_document(doc_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, _ = require(db, user, doc_id, "owner", request, "delete")  # MUT
        db.execute("UPDATE documents SET deleted_at=?, deleted_by=? WHERE id=?",
                   (utcnow(), user["id"], doc["id"]))
        audit(db, user, "delete", "success", doc_id=doc["id"], request=request,
              detail={"name": doc["name"]})
    return {"ok": True}


@app.post("/api/documents/{doc_id}/restore")
def restore_document(doc_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, _ = require(db, user, doc_id, "owner", request, "restore", allow_deleted=True)  # MUT
        db.execute("UPDATE documents SET deleted_at=NULL, deleted_by=NULL WHERE id=?", (doc["id"],))
        audit(db, user, "restore", "success", doc_id=doc["id"], request=request)
    return {"ok": True}


# -------------------------------------------------------------------- sharing
def _grants(db, doc_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT g.user_id, u.username, u.display_name, g.level, g.created_at FROM grants g "
        "JOIN users u ON u.id=g.user_id WHERE g.document_id=? AND g.revoked_at IS NULL "
        "ORDER BY u.username", (doc_id,))]


@app.get("/api/documents/{doc_id}/grants")
def list_grants(doc_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, _ = require(db, user, doc_id, "owner", request, "list_grants")  # MUT
        return _grants(db, doc["id"])


class GrantIn(Strict):
    level: Literal["read", "edit"]


@app.put("/api/documents/{doc_id}/grants/{target_id}")
def put_grant(doc_id: str, target_id: int, body: GrantIn, request: Request,
              user=Depends(current_user), db=Depends(get_db)):
    with tx(db):
        doc, _ = require(db, user, doc_id, "owner", request, "grant")  # MUT
        t = db.execute("SELECT * FROM users WHERE id=? AND active=1", (target_id,)).fetchone()
        if not t or t["id"] == user["id"]:
            raise Refused(400, "Choose another active user")
        if t["role"] == "admin":
            raise Refused(400, "Administrators cannot be granted document access")
        if body.level == "edit" and t["role"] == "viewer":
            raise Refused(400, "Viewers can only be given read access")
        cur = db.execute("SELECT * FROM grants WHERE document_id=? AND user_id=? AND revoked_at IS NULL",
                         (doc["id"], t["id"])).fetchone()
        if cur and cur["level"] == body.level:
            return {"ok": True, "unchanged": True}
        if cur:
            db.execute("UPDATE grants SET revoked_at=?, revoked_by=? WHERE id=?",
                       (utcnow(), user["id"], cur["id"]))
        db.execute("INSERT INTO grants(document_id,user_id,level,granted_by,created_at) VALUES (?,?,?,?,?)",
                   (doc["id"], t["id"], body.level, user["id"], utcnow()))
        audit(db, user, "grant_changed" if cur else "grant", "success", doc_id=doc["id"],
              target_user_id=t["id"], request=request,
              detail={"to": t["username"], "level": body.level, "was": cur["level"] if cur else None})
    return {"ok": True}


@app.delete("/api/documents/{doc_id}/grants/{target_id}")
def revoke_grant(doc_id: str, target_id: int, request: Request,
                 user=Depends(current_user), db=Depends(get_db)):
    """Takes effect on the very next request: nothing is cached or pre-signed."""
    with tx(db):
        doc, _ = require(db, user, doc_id, "owner", request, "revoke")  # MUT
        cur = db.execute("SELECT * FROM grants WHERE document_id=? AND user_id=? AND revoked_at IS NULL",
                         (doc["id"], target_id)).fetchone()
        if not cur:
            raise Refused(404, "No such grant")
        db.execute("UPDATE grants SET revoked_at=?, revoked_by=? WHERE id=?",
                   (utcnow(), user["id"], cur["id"]))
        audit(db, user, "revoke", "success", doc_id=doc["id"], target_user_id=target_id,
              request=request, detail={"level": cur["level"]})
    return {"ok": True}


@app.get("/api/documents/{doc_id}/history")
def document_history(doc_id: str, request: Request, limit: int = Query(100, ge=1, le=500),
                     user=Depends(current_user), db=Depends(get_db)):
    """Owner-only: who touched this document, including refused attempts."""
    with tx(db):
        doc, _ = require(db, user, doc_id, "owner", request, "view_history")  # MUT
        rows = db.execute("SELECT seq,ts,actor_name,action,outcome,ip,detail FROM audit_log "
                          "WHERE document_id=? ORDER BY seq DESC LIMIT ?", (doc["id"], limit))
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------- admin
@app.get("/api/admin/users")
def admin_users(user=Depends(roles("admin")), db=Depends(get_db)):
    return [dict(r) for r in db.execute(
        "SELECT id,username,display_name,role,active,created_at FROM users ORDER BY id")]


class NewUserIn(Strict):
    username: str = Field(pattern=r"^[a-z0-9._-]{3,32}$")
    display_name: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=10, max_length=256)
    role: Literal["admin", "owner", "viewer"]


@app.post("/api/admin/users", status_code=201)
def admin_create_user(body: NewUserIn, request: Request, user=Depends(roles("admin")), db=Depends(get_db)):
    with tx(db):
        if db.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
            raise Refused(409, "Username already exists")
        uid = create_user(db, body.username, body.display_name, body.password, body.role)
        audit(db, user, "user_created", "success", target_user_id=uid, request=request,
              detail={"username": body.username, "role": body.role})
    return {"id": uid}


class UserPatchIn(Strict):
    active: bool | None = None
    new_password: str | None = Field(None, min_length=10, max_length=256)


@app.patch("/api/admin/users/{uid}")
def admin_patch_user(uid: int, body: UserPatchIn, request: Request,
                     user=Depends(roles("admin")), db=Depends(get_db)):
    with tx(db):
        t = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not t:
            raise Refused(404, "Not found")
        if body.active is False and uid == user["id"]:
            raise Refused(400, "You cannot deactivate yourself")
        if body.active is not None:
            db.execute("UPDATE users SET active=? WHERE id=?", (int(body.active), uid))
            if not body.active:
                db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (uid,))
            audit(db, user, "user_activated" if body.active else "user_deactivated", "success",
                  target_user_id=uid, request=request, detail={"username": t["username"]})
        if body.new_password:
            db.execute("UPDATE users SET password_hash=?, failed_logins=0, locked_until=NULL WHERE id=?",
                       (hash_password(body.new_password), uid))
            db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (uid,))
            audit(db, user, "password_reset", "success", target_user_id=uid, request=request,
                  detail={"username": t["username"]})
    return {"ok": True}


@app.get("/api/admin/audit")
def admin_audit(action: str | None = None, outcome: str | None = None, actor: str | None = None,
                document_id: str | None = None, before_seq: int | None = None,
                limit: int = Query(100, ge=1, le=500),
                user=Depends(roles("admin")), db=Depends(get_db)):
    sql, p = "SELECT * FROM audit_log WHERE 1=1", []
    for col, val in (("action", action), ("outcome", outcome), ("actor_name", actor),
                     ("document_id", document_id)):
        if val:
            sql += f" AND {col}=?"  # col is from a fixed tuple, never user input
            p.append(val)
    if before_seq:
        sql += " AND seq<?"
        p.append(before_seq)
    sql += " ORDER BY seq DESC LIMIT ?"
    p.append(limit)
    return [dict(r) for r in db.execute(sql, p)]


@app.get("/api/admin/audit/verify")
def admin_audit_verify(user=Depends(roles("admin")), db=Depends(get_db)):
    return verify_chain(db)


@app.get("/api/admin/alerts")
def admin_alerts(user=Depends(roles("admin")), db=Depends(get_db)):
    """Things worth a human's attention in the last hour."""
    since = utc_plus(hours=-1)
    alerts = []
    q = ("SELECT actor_name AS who, COUNT(*) AS n FROM audit_log WHERE ts>=? AND outcome='denied' "
         "AND action!='login' GROUP BY actor_name HAVING n>=5")
    for r in db.execute(q, (since,)):
        alerts.append({"type": "repeated_denials", "who": r["who"], "count": r["n"],
                       "message": f"{r['who']} was refused access {r['n']} times in the last hour"})
    q = ("SELECT actor_name AS who, COUNT(*) AS n FROM audit_log WHERE ts>=? AND action='login' "
         "AND outcome='denied' GROUP BY actor_name HAVING n>=3")
    for r in db.execute(q, (since,)):
        alerts.append({"type": "failed_logins", "who": r["who"], "count": r["n"],
                       "message": f"{r['n']} failed logins for {r['who']} in the last hour"})
    q = ("SELECT actor_name AS who, COUNT(*) AS n FROM audit_log WHERE ts>=? AND action='download' "
         "AND outcome='success' GROUP BY actor_name HAVING n>=20")
    for r in db.execute(q, (since,)):
        alerts.append({"type": "bulk_download", "who": r["who"], "count": r["n"],
                       "message": f"{r['who']} downloaded {r['n']} files in the last hour"})
    q = ("SELECT actor_name AS who, COUNT(*) AS n FROM audit_log WHERE ts>=? AND action IN ('grant','grant_changed') "
         "AND outcome='success' GROUP BY actor_name HAVING n>=10")
    for r in db.execute(q, (since,)):
        alerts.append({"type": "many_grants", "who": r["who"], "count": r["n"],
                       "message": f"{r['who']} made {r['n']} permission changes in the last hour"})
    return alerts


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # Never leak internals to the client.
    return JSONResponse({"detail": "Internal error"}, status_code=500)


app.mount("/static", StaticFiles(directory=f"{BASE}/static"), name="static")


@app.get("/")
def index():
    return FileResponse(f"{BASE}/static/index.html")
