"""THE authorisation decision. Every route that touches a document calls require().

Rules (nothing else grants access):
  owner  = documents.owner_id == user            -> read, edit, share, delete, restore
  edit   = an active grant with level 'edit'     -> read, edit (rename, new version)
  read   = an active grant with level 'read'     -> read (view, download)
Admins get no implicit access to document content: they have to be the owner or hold a
grant like anyone else (and the grant API refuses to grant to admins).

Every refusal is written to the audit log before the error is raised.
Responses: 404 when the caller has no access at all (does not reveal that the document
exists), 403 when the caller can see it but lacks the needed level.
"""
import re

from .audit import audit
from .errors import Refused

RANK = {"read": 1, "edit": 2, "owner": 3}
_ID = re.compile(r"^[0-9a-f]{32}$")


def _load(db, doc_id: str):
    if not isinstance(doc_id, str) or not _ID.match(doc_id):
        return None
    return db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()


def level_for(db, user, doc) -> str | None:
    if doc["owner_id"] == user["id"]:
        return "owner"
    g = db.execute(
        "SELECT level FROM grants WHERE document_id=? AND user_id=? AND revoked_at IS NULL",
        (doc["id"], user["id"])).fetchone()
    return g["level"] if g else None


def require(db, user, doc_id: str, need: str, request, action: str,
            allow_deleted: bool = False):
    """Return (document_row, caller_level) or audit + raise Refused. Call inside tx()."""
    doc = _load(db, doc_id)
    level = None
    if doc is not None and (doc["deleted_at"] is None or allow_deleted):
        level = level_for(db, user, doc)
        if doc["deleted_at"] is not None and level != "owner":
            level = None  # a deleted document is invisible to everyone but its owner
    if level is None:
        audit(db, user, action, "denied", doc_id=doc_id, request=request,
              detail={"reason": "no_access"})
        raise Refused(404, "Not found")
    if RANK[level] < RANK[need]:
        audit(db, user, action, "denied", doc_id=doc["id"], request=request,
              detail={"reason": "insufficient_level", "have": level, "need": need})
        raise Refused(403, "You do not have permission to do that")
    return doc, level
