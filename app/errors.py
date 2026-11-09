from fastapi import HTTPException


class Refused(HTTPException):
    """A deliberate refusal. The transaction it is raised in is COMMITTED (not rolled
    back) so the audit row that records the refusal survives. Raise it only before any
    other write has happened in that transaction."""
