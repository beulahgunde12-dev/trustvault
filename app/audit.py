"""Append-only, HMAC-chained audit log.

Every row stores prev_hash and hash = HMAC(key, prev_hash | canonical_json(row)).
- SQL triggers (schema.sql) reject UPDATE and DELETE.
- Someone who bypasses the triggers (e.g. edits the file directly) must recompute every
  later hash, which needs the key (TV_AUDIT_KEY) that is NOT in the database.
- verify_chain() detects edits, deletions in the middle, and reordering.
- Truncating the *tail* is only detectable against a head hash recorded elsewhere;
  GET /api/admin/audit/verify returns the head so operators can keep it off-box.
"""
import hashlib
import hmac
import json

from .config import settings
from .db import tx
from .util import client_ip, utcnow

GENESIS = "0" * 64


def _mac(prev: str, rec: dict) -> str:
    msg = prev + "|" + json.dumps(rec, sort_keys=True, separators=(",", ":"))
    return hmac.new(settings.audit_key, msg.encode(), hashlib.sha256).hexdigest()


def _record(ts, actor_id, actor_name, action, outcome, doc_id, target, ip, detail) -> dict:
    return {"ts": ts, "actor_id": actor_id, "actor_name": actor_name, "action": action,
            "outcome": outcome, "document_id": doc_id, "target_user_id": target,
            "ip": ip, "detail": detail}


def audit(db, actor, action: str, outcome: str, *, doc_id=None, target_user_id=None,
          request=None, detail: dict | None = None, actor_name: str | None = None) -> None:
    actor_id = actor["id"] if actor else None
    actor_name = (actor["username"] if actor else actor_name)
    detail_s = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))[:2000]
    doc_id = str(doc_id)[:64] if doc_id is not None else None
    with tx(db):
        row = db.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        rec = _record(utcnow(), actor_id, actor_name, action, outcome, doc_id,
                      target_user_id, client_ip(request), detail_s)
        db.execute(
            "INSERT INTO audit_log(ts,actor_id,actor_name,action,outcome,document_id,"
            "target_user_id,ip,detail,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (rec["ts"], actor_id, actor_name, action, outcome, doc_id, target_user_id,
             rec["ip"], detail_s, prev, _mac(prev, rec)))


def verify_chain(db) -> dict:
    prev, count = GENESIS, 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY seq"):
        rec = _record(r["ts"], r["actor_id"], r["actor_name"], r["action"], r["outcome"],
                      r["document_id"], r["target_user_id"], r["ip"], r["detail"])
        if r["prev_hash"] != prev or not hmac.compare_digest(_mac(prev, rec), r["hash"]):
            return {"ok": False, "broken_at_seq": r["seq"], "entries_checked": count,
                    "head": None}
        prev, count = r["hash"], count + 1
    return {"ok": True, "entries_checked": count, "head": prev}
