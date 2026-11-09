from datetime import datetime, timedelta, timezone
from fastapi import Request
from .config import settings


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def utc_plus(**kw) -> str:
    return (datetime.now(timezone.utc) + timedelta(**kw)).isoformat(timespec="seconds")


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    if settings.trust_proxy:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()[:45]
    return request.client.host if request.client else None
