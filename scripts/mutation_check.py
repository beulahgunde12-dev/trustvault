"""Authorisation mutation check.

For every line in app/main.py tagged `# MUT`, remove that authorisation check (replace
`require(` with a stub that grants owner-level access to anyone) and run the test-suite.
A mutant that SURVIVES means the tests do not really cover that check.

    python scripts/mutation_check.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUB = '''

def _mutant_require(db, user, doc_id, need, request, action, allow_deleted=False):
    from .authz import _load
    d = _load(db, doc_id)
    if d is None:
        raise Refused(404, "Not found")
    return d, "owner"
'''


def main() -> int:
    src = open(os.path.join(ROOT, "app", "main.py"), encoding="utf-8").read().split("\n")
    targets = [i for i, l in enumerate(src) if "# MUT" in l]
    survivors = 0
    for n, i in enumerate(targets, 1):
        tmp = tempfile.mkdtemp()
        dst = os.path.join(tmp, "p")
        shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns("data", ".git", "__pycache__", ".pytest_cache"))
        os.makedirs(os.path.join(dst, "data"))
        lines = list(src)
        lines[i] = lines[i].replace("require(", "_mutant_require(", 1)
        open(os.path.join(dst, "app", "main.py"), "w", encoding="utf-8").write("\n".join(lines) + STUB)
        r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                           cwd=dst, capture_output=True, text=True)
        label = re.sub(r"\s+", " ", src[i].strip())[:90]
        killed = r.returncode != 0
        survivors += not killed
        print(f"[{n}/{len(targets)}] {'KILLED  ' if killed else 'SURVIVED'} {label}", flush=True)
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(targets) - survivors}/{len(targets)} authorisation checks are covered by tests")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
