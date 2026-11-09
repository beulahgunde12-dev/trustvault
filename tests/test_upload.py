import io
import zipfile

from conftest import PDF


def post(env, who, name, data, **kw):
    return env.c.post("/api/documents", headers=env.h(who), files={"file": (name, data)}, **kw)


def test_rejects_disallowed_extensions(env):
    for n in ("virus.exe", "page.html", "x.svg", "x.php", "noext", "a.txt.exe", "x.js"):
        assert post(env, "alice", n, b"hello").status_code == 400, n


def test_rejects_content_that_does_not_match_extension(env):
    assert post(env, "alice", "fake.pdf", b"<html><script>alert(1)</script>").status_code == 400
    assert post(env, "alice", "fake.png", PDF).status_code == 400
    assert post(env, "alice", "bin.txt", b"abc\x00def").status_code == 400
    assert post(env, "alice", "latin.txt", b"\xff\xfe\xfa").status_code == 400
    assert post(env, "alice", "fake.docx", b"PK\x03\x04 not really a zip").status_code == 400


def test_rejects_empty_and_oversize(env):
    assert post(env, "alice", "e.txt", b"").status_code == 400
    assert post(env, "alice", "big.txt", b"a" * (1024 * 1024 + 1)).status_code == 413


def test_rejects_zip_bomb_like_office_files(env):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("big.bin", b"\0" * (101 * 1024 * 1024))
    assert post(env, "alice", "bomb.docx", buf.getvalue()).status_code == 400


def test_accepts_valid_files_and_rejections_are_audited(env):
    assert post(env, "alice", "ok.pdf", PDF).status_code == 201
    post(env, "alice", "bad.exe", b"MZ")
    n = env.db().execute("SELECT COUNT(*) FROM audit_log WHERE action='upload' AND outcome='failure'").fetchone()[0]
    assert n == 1


def test_hostile_filenames_are_neutralised_and_never_touch_the_filesystem_path(env, tmp_path):
    r = post(env, "alice", "../../../etc/passwd.txt", b"data")
    assert r.status_code == 201
    doc = r.json()["id"]
    d = env.c.get(f"/api/documents/{doc}", headers=env.h("alice")).json()
    assert d["versions"][0]["original_filename"] == "passwd.txt"
    # storage key is random hex, files live only under the storage dir
    key = env.db().execute("SELECT storage_key FROM document_versions").fetchone()[0]
    assert len(key) == 32 and all(c in "0123456789abcdef" for c in key)
    dl = env.c.get(f"/api/documents/{doc}/download", headers=env.h("alice"))
    assert 'filename="passwd.txt"' in dl.headers["content-disposition"]


def test_download_is_forced_attachment_and_not_sniffable(env):
    r = post(env, "alice", "note.txt", b"<script>alert(1)</script>")
    dl = env.c.get(f"/api/documents/{r.json()['id']}/download", headers=env.h("alice"))
    assert dl.headers["content-type"] == "application/octet-stream"
    assert dl.headers["content-disposition"].startswith("attachment")
    assert dl.headers["x-content-type-options"] == "nosniff"
    assert dl.headers["cache-control"] == "no-store"


def test_download_detects_on_disk_tampering(env):
    import os
    from app.config import settings
    doc = env.upload("alice")
    key = env.db().execute("SELECT storage_key FROM document_versions").fetchone()[0]
    with open(os.path.join(settings.storage_dir, key[:2], key), "wb") as f:
        f.write(b"tampered")
    assert env.c.get(f"/api/documents/{doc}/download", headers=env.h("alice")).status_code == 500


def test_versions_keep_old_content_and_search_filters_work(env):
    doc = env.upload("alice", "v.txt", b"one", category="Legal")
    env.c.post(f"/api/documents/{doc}/versions", headers=env.h("alice"), files={"file": ("v.txt", b"two")})
    h = env.h("alice")
    assert env.c.get(f"/api/documents/{doc}/download", headers=h).content == b"two"
    assert env.c.get(f"/api/documents/{doc}/download?version=1", headers=h).content == b"one"
    for qs, n in (("?q=v.t", 1), ("?category=Legal", 1), ("?category=HR", 0), ("?owner=alice", 1),
                  ("?owner=carol", 0), ("?created_from=2000-01-01", 1), ("?created_to=2000-01-01", 0)):
        assert len(env.c.get("/api/documents" + qs, headers=h).json()) == n, qs
    assert env.c.get("/api/documents?created_from=garbage", headers=h).status_code == 422
