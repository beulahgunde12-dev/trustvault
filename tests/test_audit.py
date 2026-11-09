import json
import sqlite3

import pytest

from app.audit import verify_chain


def actions(env, doc=None):
    db = env.db()
    q = "SELECT action, outcome, actor_name FROM audit_log" + (" WHERE document_id=?" if doc else "")
    return [tuple(r) for r in db.execute(q + " ORDER BY seq", (doc,) if doc else ())]


def test_every_kind_of_event_is_recorded(env):
    doc = env.upload("alice")
    env.grant("alice", doc, "bob", "read")
    env.c.get(f"/api/documents/{doc}/download", headers=env.h("bob"))
    env.c.get(f"/api/documents/{doc}/download", headers=env.h("carol"))          # refused
    env.c.patch(f"/api/documents/{doc}", headers=env.h("alice"), json={"name": "n"})
    env.c.post(f"/api/documents/{doc}/versions", headers=env.h("alice"), files={"file": ("a.txt", b"v2")})
    env.c.delete(f"/api/documents/{doc}/grants/{env.ids['bob']}", headers=env.h("alice"))
    env.c.delete(f"/api/documents/{doc}", headers=env.h("alice"))
    got = set(actions(env, doc))
    for want in [("upload", "success", "alice"), ("grant", "success", "alice"),
                 ("download", "success", "bob"), ("download", "denied", "carol"),
                 ("update", "success", "alice"), ("new_version", "success", "alice"),
                 ("revoke", "success", "alice"), ("delete", "success", "alice")]:
        assert want in got, want


def test_refused_attempts_after_revoke_are_recorded(env):
    doc = env.upload("alice")
    env.grant("alice", doc, "bob")
    env.c.delete(f"/api/documents/{doc}/grants/{env.ids['bob']}", headers=env.h("alice"))
    env.c.get(f"/api/documents/{doc}/download", headers=env.h("bob"))
    assert ("download", "denied", "bob") in actions(env, doc)


def test_audit_detail_records_who_granted_what_to_whom(env):
    doc = env.upload("alice")
    env.grant("alice", doc, "bob", "read")
    row = env.db().execute("SELECT * FROM audit_log WHERE action='grant'").fetchone()
    assert row["target_user_id"] == env.ids["bob"]
    assert json.loads(row["detail"]) == {"level": "read", "to": "bob", "was": None}


def test_chain_verifies_when_untouched(env):
    env.upload("alice")
    assert verify_chain(env.db())["ok"] is True
    r = env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()
    assert r["ok"] and r["head"]


def test_database_refuses_update_and_delete_of_audit_rows(env):
    env.upload("alice")
    db = env.db()
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE audit_log SET actor_name='nobody'")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM audit_log")


def _bypass(db, sql, *args):
    """What an attacker with raw file access could do: drop the triggers first."""
    db.executescript("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;")
    db.execute(sql, args)


def test_tampering_with_a_row_is_detected_even_without_triggers(env):
    env.upload("alice")
    env.upload("alice", "b.txt")
    db = env.db()
    _bypass(db, "UPDATE audit_log SET actor_name='mallory' WHERE seq=2")
    res = verify_chain(db)
    assert res["ok"] is False and res["broken_at_seq"] == 2


def test_deleting_a_middle_row_is_detected(env):
    for i in range(3):
        env.upload("alice", f"{i}.txt")
    db = env.db()
    _bypass(db, "DELETE FROM audit_log WHERE seq=3")
    assert verify_chain(db)["ok"] is False


def test_recomputing_hashes_without_the_key_is_not_possible(env):
    """An attacker who rewrites a row AND re-chains with plain SHA-256 is still caught."""
    import hashlib
    env.upload("alice")
    db = env.db()
    _bypass(db, "UPDATE audit_log SET actor_name='mallory', hash=? WHERE seq=1", hashlib.sha256(b"x").hexdigest())
    assert verify_chain(db)["ok"] is False


def test_only_admin_reads_global_audit_and_owner_reads_own_doc_history(env):
    doc = env.upload("alice")
    env.grant("alice", doc, "bob")
    env.c.get(f"/api/documents/{doc}/download", headers=env.h("bob"))
    env.c.get(f"/api/documents/{doc}/download", headers=env.h("carol"))
    hist = env.c.get(f"/api/documents/{doc}/history", headers=env.h("alice")).json()
    assert {(h["actor_name"], h["action"], h["outcome"]) for h in hist} >= {
        ("bob", "download", "success"), ("carol", "download", "denied")}
    assert env.c.get(f"/api/documents/{doc}/history", headers=env.h("carol")).status_code == 404
    assert env.c.get("/api/admin/audit", headers=env.h("alice")).status_code == 403
    rows = env.c.get("/api/admin/audit?outcome=denied", headers=env.h("admin")).json()
    assert any(r["actor_name"] == "carol" for r in rows)


def test_alert_fires_on_repeated_denials(env):
    doc = env.upload("alice")
    for _ in range(5):
        env.c.get(f"/api/documents/{doc}/download", headers=env.h("carol"))
    alerts = env.c.get("/api/admin/alerts", headers=env.h("admin")).json()
    assert any(a["type"] == "repeated_denials" and a["who"] == "carol" for a in alerts)


def test_rolled_back_actions_leave_no_audit_row_claiming_success(env, monkeypatch):
    from app import storage
    monkeypatch.setattr(storage, "save", lambda d: (_ for _ in ()).throw(OSError("disk full")))
    r = env.c.post("/api/documents", headers=env.h("alice"), files={"file": ("a.txt", b"x")})
    assert r.status_code == 500
    assert not [a for a in actions(env) if a[0] == "upload" and a[1] == "success"]
