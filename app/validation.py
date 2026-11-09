"""Upload validation: size, extension allow-list, content signature, zip sanity."""
import io
import os
import re
import unicodedata
import zipfile

ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".docx", ".xlsx"}
MAGIC = {".pdf": b"%PDF-", ".png": b"\x89PNG\r\n\x1a\n", ".jpg": b"\xff\xd8\xff",
         ".jpeg": b"\xff\xd8\xff", ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04"}
MAX_UNZIPPED = 100 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000


class ValidationError(ValueError):
    pass


def clean_text(s: str, maxlen: int, field: str = "value") -> str:
    s = unicodedata.normalize("NFC", s or "")
    s = "".join(ch for ch in s if ch.isprintable()).strip()
    if not s:
        raise ValidationError(f"{field} must not be empty")
    return s[:maxlen]


def safe_filename(name: str | None) -> str:
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable()).strip().strip(".")
    name = re.sub(r"\s+", " ", name)[:120]
    if not name:
        raise ValidationError("A file name is required")
    return name


def validate_upload(filename: str | None, data: bytes, max_bytes: int) -> str:
    """Returns the cleaned filename or raises ValidationError. The client's declared
    Content-Type is ignored: only extension + actual bytes count."""
    fname = safe_filename(filename)
    ext = os.path.splitext(fname)[1].lower()
    if ext not in ALLOWED_EXT:
        raise ValidationError(f"File type {ext or '(none)'} is not allowed. "
                              f"Allowed: {', '.join(sorted(ALLOWED_EXT))}")
    if len(data) == 0:
        raise ValidationError("File is empty")
    if len(data) > max_bytes:
        raise ValidationError(f"File is larger than {max_bytes // (1024 * 1024)} MB")
    if ext in MAGIC and not data.startswith(MAGIC[ext]):
        raise ValidationError(f"File content does not look like a {ext} file")
    if ext in (".txt", ".csv"):
        if b"\x00" in data:
            raise ValidationError("Text file contains binary data")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError("Text file is not valid UTF-8")
    if ext in (".docx", ".xlsx"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_UNZIPPED:
                    raise ValidationError("Archive is too large when unpacked")
                if "[Content_Types].xml" not in z.namelist():
                    raise ValidationError("Not a valid Office document")
        except zipfile.BadZipFile:
            raise ValidationError("Not a valid Office document")
    return fname
