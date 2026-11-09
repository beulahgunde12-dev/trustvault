"""Seed demo data: python -m app.seed   (safe to run twice; does nothing if users exist)."""
from fastapi.testclient import TestClient

from .config import settings
from .db import connect, create_user, init_db


def main() -> None:
    init_db()
    db = connect()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        print("Users already exist; seed skipped.")
        return
    pw = settings.seed_password
    for u, n, r in [("admin", "Ada Admin", "admin"), ("alice", "Alice Owner", "owner"),
                    ("carol", "Carol Owner", "owner"), ("bob", "Bob Viewer", "viewer")]:
        create_user(db, u, n, pw, r)
    db.close()

    from .main import app  # imported late so settings are final
    c = TestClient(app)

    def login(u):
        return {"Authorization": "Bearer " + c.post("/api/auth/login",
                json={"username": u, "password": pw}).json()["token"]}

    a, k = login("alice"), login("carol")
    r = c.post("/api/documents", headers=a, data={"category": "HR", "name": "Salary letter - B. Viewer"},
               files={"file": ("salary-letter.txt", b"Dear Bob, your new salary is ...\n")})
    c.put(f"/api/documents/{r.json()['id']}/grants/4", headers=a, json={"level": "read"})
    c.post("/api/documents", headers=a, data={"category": "Finance", "name": "Alice internal budget"},
           files={"file": ("budget.csv", b"item,amount\nrent,1000\n")})
    c.post("/api/documents", headers=k, data={"category": "Contracts", "name": "Customer contract (Carol only)"},
           files={"file": ("contract.txt", b"Confidential contract text.\n")})
    print("Seeded users admin/alice/carol/bob with the seed password and 3 demo documents.")


if __name__ == "__main__":
    main()
