"""One user must never reach another user's documents, by any route."""
import pytest

from conftest import PW


@pytest.fixture()
def world(env):
    """alice owns a doc; bob has READ; carol (owner) and dave (viewer) have nothing."""
    doc = env.upload("alice", "payslip.txt", b"alice-secret-content")
    env.grant("alice", doc, "bob", "read")
    return env, doc


ROUTES = [  # (method, path template, kwargs) - every route that names a document
    ("GET", "/api/documents/{d}", {}),
    ("GET", "/api/documents/{d}/download", {}),
    ("GET", "/api/documents/{d}/download?version=1", {}),
    ("PATCH", "/api/documents/{d}", {"json": {"name": "pwned"}}),
    ("POST", "/api/documents/{d}/versions", {"files": {"file": ("x.txt", b"evil")}}),
    ("DELETE", "/api/documents/{d}", {}),
    ("POST", "/api/documents/{d}/restore", {}),
    ("GET", "/api/documents/{d}/grants", {}),
    ("PUT", "/api/documents/{d}/grants/{me}", {"json": {"level": "read"}}),
    ("DELETE", "/api/documents/{d}/grants/{me}", {}),
    ("GET", "/api/documents/{d}/history", {}),
]


@pytest.mark.parametrize("who", ["carol", "dave", "admin"])
@pytest.mark.parametrize("method,path,kw", ROUTES)
def test_stranger_gets_404_on_every_document_route(world, who, method, path, kw):
    env, doc = world
    r = env.c.request(method, path.format(d=doc, me=env.ids[who]), headers=env.h(who), **kw)
    assert r.status_code in (403, 404) and "alice-secret" not in r.text
    # ...and nothing changed
    d = env.c.get(f"/api/documents/{doc}", headers=env.h("alice")).json()
    assert d["name"] == "payslip.txt" and d["current_version"] == 1
    assert [g["username"] for g in d["grants"]] == ["bob"]
    # ...and the refusal was recorded
    db = env.db()
    n = db.execute("SELECT COUNT(*) FROM audit_log WHERE outcome='denied' AND actor_name=? "
                   "AND document_id=?", (who, doc)).fetchone()[0]
    assert n >= 1


@pytest.mark.parametrize("method,path,kw", ROUTES)
def test_unauthenticated_gets_401(world, method, path, kw):
    env, doc = world
    r = env.c.request(method, path.format(d=doc, me=1), **kw)
    assert r.status_code == 401


def test_bad_and_fake_tokens_rejected(world):
    env, doc = world
    for h in ({"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"},
              {"Authorization": "Bearer "}):
        assert env.c.get(f"/api/documents/{doc}/download", headers=h).status_code == 401


def test_document_ids_that_are_not_ids_are_404_not_500(world):
    env, _ = world
    for bad in ("1", "../../etc/passwd", "' OR 1=1 --", "%00", "A" * 500):
        r = env.c.get(f"/api/documents/{bad}", headers=env.h("carol"))
        assert r.status_code in (404, 405)


def test_search_never_leaks_other_peoples_documents(world):
    env, doc = world
    env.upload("carol", "carol-private.txt", b"x")
    for who in ("carol", "dave"):
        for qs in ("", "?q=payslip", "?owner=alice", "?category=HR", "?q=%25", "?q=_"):
            r = env.c.get("/api/documents" + qs, headers=env.h(who))
            assert r.status_code == 200
            assert all(d["id"] != doc for d in r.json()), (who, qs)
    # the admin sees no document content or metadata through search either
    assert env.c.get("/api/documents", headers=env.h("admin")).json() == []
    # bob sees exactly the one shared doc
    assert [d["id"] for d in env.c.get("/api/documents", headers=env.h("bob")).json()] == [doc]


def test_read_grant_allows_read_but_not_edit_or_share_or_delete(world):
    env, doc = world
    h = env.h("bob")
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).content == b"alice-secret-content"
    assert env.c.patch(f"/api/documents/{doc}", headers=h, json={"name": "x"}).status_code == 403
    assert env.c.post(f"/api/documents/{doc}/versions", headers=h,
                      files={"file": ("a.txt", b"x")}).status_code == 403
    assert env.c.delete(f"/api/documents/{doc}", headers=h).status_code == 403
    assert env.c.get(f"/api/documents/{doc}/grants", headers=h).status_code == 403
    assert env.c.put(f"/api/documents/{doc}/grants/{env.ids['dave']}", headers=h,
                     json={"level": "read"}).status_code == 403


def test_edit_grant_can_edit_but_not_share_or_delete(world):
    env, doc = world
    env.grant("alice", doc, "carol", "edit")
    h = env.h("carol")
    assert env.c.patch(f"/api/documents/{doc}", headers=h, json={"name": "renamed"}).status_code == 200
    assert env.c.post(f"/api/documents/{doc}/versions", headers=h,
                      files={"file": ("a.txt", b"v2")}).status_code == 201
    assert env.c.delete(f"/api/documents/{doc}", headers=h).status_code == 403
    assert env.c.put(f"/api/documents/{doc}/grants/{env.ids['dave']}", headers=h,
                     json={"level": "read"}).status_code == 403


def test_revoke_takes_effect_on_the_next_request_with_the_same_token(world):
    env, doc = world
    h = env.h("bob")
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).status_code == 200
    r = env.c.delete(f"/api/documents/{doc}/grants/{env.ids['bob']}", headers=env.h("alice"))
    assert r.status_code == 200
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).status_code == 404
    assert env.c.get(f"/api/documents/{doc}", headers=h).status_code == 404
    assert env.c.get("/api/documents", headers=h).json() == []


def test_downgrade_edit_to_read_is_immediate(world):
    env, doc = world
    env.grant("alice", doc, "carol", "edit")
    h = env.h("carol")
    assert env.c.patch(f"/api/documents/{doc}", headers=h, json={"name": "a"}).status_code == 200
    env.grant("alice", doc, "carol", "read")
    assert env.c.patch(f"/api/documents/{doc}", headers=h, json={"name": "b"}).status_code == 403
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).status_code == 200


def test_regrant_after_revoke_works_and_is_single_active_row(world):
    env, doc = world
    env.c.delete(f"/api/documents/{doc}/grants/{env.ids['bob']}", headers=env.h("alice"))
    env.grant("alice", doc, "bob", "read")
    n = env.db().execute("SELECT COUNT(*) FROM grants WHERE document_id=? AND user_id=? "
                         "AND revoked_at IS NULL", (doc, env.ids["bob"])).fetchone()[0]
    assert n == 1


def test_grant_rules(world):
    env, doc = world
    a = env.h("alice")
    put = lambda u, lvl: env.c.put(f"/api/documents/{doc}/grants/{env.ids[u]}", headers=a, json={"level": lvl})
    assert put("dave", "edit").status_code == 400      # viewers: read only
    assert put("admin", "read").status_code == 400     # admins never get document access
    assert put("alice", "read").status_code == 400     # not to yourself
    assert env.c.put(f"/api/documents/{doc}/grants/9999", headers=a, json={"level": "read"}).status_code == 400
    assert put("dave", "owner").status_code == 422     # unknown level


def test_viewer_cannot_upload_and_admin_cannot_upload(env):
    for who in ("bob", "admin"):
        r = env.c.post("/api/documents", headers=env.h(who), files={"file": ("a.txt", b"x")})
        assert r.status_code == 403


def test_non_admin_cannot_use_admin_api(world):
    env, _ = world
    for who in ("alice", "bob"):
        for path in ("/api/admin/audit", "/api/admin/users", "/api/admin/alerts",
                     "/api/admin/audit/verify"):
            assert env.c.get(path, headers=env.h(who)).status_code == 403
        r = env.c.post("/api/admin/users", headers=env.h(who), json={
            "username": "mallory", "display_name": "M", "password": "x" * 12, "role": "admin"})
        assert r.status_code == 403


def test_admin_cannot_read_document_content(world):
    env, doc = world
    assert env.c.get(f"/api/documents/{doc}/download", headers=env.h("admin")).status_code == 404


def test_soft_deleted_document_is_gone_for_grantees_and_restorable_by_owner(world):
    env, doc = world
    assert env.c.delete(f"/api/documents/{doc}", headers=env.h("alice")).status_code == 200
    assert env.c.get(f"/api/documents/{doc}/download", headers=env.h("bob")).status_code == 404
    assert env.c.post(f"/api/documents/{doc}/restore", headers=env.h("bob")).status_code == 404
    assert env.c.get(f"/api/documents/{doc}/download", headers=env.h("alice")).status_code == 404
    assert [d["id"] for d in env.c.get("/api/documents?trash=true", headers=env.h("alice")).json()] == [doc]
    assert env.c.post(f"/api/documents/{doc}/restore", headers=env.h("alice")).status_code == 200
    assert env.c.get(f"/api/documents/{doc}/download", headers=env.h("bob")).status_code == 200


def test_trash_listing_is_owner_only(world):
    env, doc = world
    env.c.delete(f"/api/documents/{doc}", headers=env.h("alice"))
    assert env.c.get("/api/documents?trash=true", headers=env.h("bob")).json() == []


def test_version_download_is_scoped_to_the_authorised_document(world):
    env, doc = world
    other = env.upload("carol", "other.txt", b"carol-secret")
    # bob has no access to carol's doc even though version numbers overlap
    assert env.c.get(f"/api/documents/{other}/download?version=1", headers=env.h("bob")).status_code == 404
    # and asking for a version that does not exist on his doc yields nothing of carol's
    r = env.c.get(f"/api/documents/{doc}/download?version=99", headers=env.h("bob"))
    assert r.status_code == 404 and b"carol-secret" not in r.content


# ------------------------------------------------------------------ sessions
def test_logout_kills_the_token(env):
    h = env.h("bob")
    assert env.c.get("/api/me", headers=h).status_code == 200
    env.c.post("/api/auth/logout", headers=h)
    assert env.c.get("/api/me", headers=h).status_code == 401


def test_deactivating_a_user_kills_their_sessions_immediately(world):
    env, doc = world
    h = env.h("bob")
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).status_code == 200
    r = env.c.patch(f"/api/admin/users/{env.ids['bob']}", headers=env.h("admin"), json={"active": False})
    assert r.status_code == 200
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).status_code == 401
    assert env.c.post("/api/auth/login", json={"username": "bob", "password": PW}).status_code == 401


def test_password_reset_revokes_sessions(env):
    h = env.h("bob")
    env.c.patch(f"/api/admin/users/{env.ids['bob']}", headers=env.h("admin"),
                json={"new_password": "another-long-password"})
    assert env.c.get("/api/me", headers=h).status_code == 401


def test_raw_tokens_are_not_stored(env):
    db = env.db()
    hashes = {r[0] for r in db.execute("SELECT token_hash FROM sessions")}
    assert all(t not in hashes for t in env.tokens.values())


def test_login_lockout_and_audit(env):
    for _ in range(5):
        assert env.c.post("/api/auth/login", json={"username": "bob", "password": "wrong"}).status_code == 401
    assert env.c.post("/api/auth/login", json={"username": "bob", "password": PW}).status_code == 429
    n = env.db().execute("SELECT COUNT(*) FROM audit_log WHERE action='login' AND outcome='denied'").fetchone()[0]
    assert n == 6


def test_unknown_user_and_wrong_password_look_identical(env):
    a = env.c.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    b = env.c.post("/api/auth/login", json={"username": "alice", "password": "x"})
    assert (a.status_code, a.json()) == (b.status_code, b.json())


def test_mass_assignment_is_rejected(world):
    env, doc = world
    r = env.c.patch(f"/api/documents/{doc}", headers=env.h("alice"), json={"owner_id": env.ids["carol"]})
    assert r.status_code == 422
    r = env.c.post("/api/auth/login", json={"username": "alice", "password": PW, "role": "admin"})
    assert r.status_code == 422
