"""File storage. Files live in TV_STORAGE under random keys, outside any web root.
There is no URL that maps to a file: bytes only leave through the authorised download
route. Keys are generated here, never taken from a request."""
import hashlib
import os
import re
import uuid

from .config import settings

_KEY = re.compile(r"^[0-9a-f]{32}$")


def _path(key: str) -> str:
    if not _KEY.match(key):
        raise ValueError("bad storage key")
    return os.path.join(settings.storage_dir, key[:2], key)


def save(data: bytes) -> tuple[str, str]:
    key = uuid.uuid4().hex
    p = _path(key)
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return key, hashlib.sha256(data).hexdigest()


def read(key: str) -> bytes:
    with open(_path(key), "rb") as f:
        return f.read()


def remove(key: str) -> None:
    try:
        os.remove(_path(key))
    except FileNotFoundError:
        pass
