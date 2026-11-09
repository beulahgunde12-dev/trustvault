import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("TV_AUDIT_KEY", "test-key")

from fastapi.testclient import TestClient  

from app import db as dbm  
from app.config import settings  
from app.main import app  

PW = "correct-horse-battery"
USERS = [("admin", "admin"), ("alice", "owner"), ("carol", "owner"),
         ("bob", "viewer"), ("dave", "viewer")]
PDF = b"%PDF-1.4\n%fake but correctly signed\n"


class Env:
    def __init__(self, client):
        self.c = client
        self.ids = {}
        self.tokens = {}

    def login(self, user, password=PW):
        r = self.c.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.text
        self.tokens[user] = r.json()["token"]
        return self.h(user)

    def h(self, user):
        return {"Authorization": "Bearer " + self.tokens[user]}

    def upload(self, user, name="secret.txt", data=b"top secret", category="HR"):
        r = self.c.post("/api/documents", headers=self.h(user), data={"category": category},
                        files={"file": (name, data)})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def grant(self, owner, doc, target, level="read"):
        r = self.c.put(f"/api/documents/{doc}/grants/{self.ids[target]}",
                       headers=self.h(owner), json={"level": level})
        assert r.status_code == 200, r.text

    def db(self):
        return dbm.connect()


@pytest.fixture()
def env(tmp_path):
    settings.db_path = str(tmp_path / "t.db")
    settings.storage_dir = str(tmp_path / "files")
    settings.max_upload_bytes = 1024 * 1024
    dbm.init_db()
    db = dbm.connect()
    e = Env(TestClient(app, raise_server_exceptions=False))
    for name, role in USERS:
        e.ids[name] = dbm.create_user(db, name, name.title(), PW, role)
    db.close()
    for name, _ in USERS:
        e.login(name)
    return e
