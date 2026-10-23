import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schema.sql"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
SESSION_HOURS = 8
ROLES = {"admin", "owner", "viewer"}
ZERO_HASH = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


DUMMY_PASSWORD_SALT = b"trustvault-dummy-salt"
DUMMY_PASSWORD_HASH = password_hash("not-a-real-password", DUMMY_PASSWORD_SALT)


def open_db(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def append_audit(
    connection: sqlite3.Connection,
    actor_id: str | None,
    action: str,
    document_id: str | None = None,
    details: dict | None = None,
) -> None:
    connection.execute("UPDATE audit_write_lock SET sequence = sequence + 1 WHERE id = 1")
    occurred_at = utc_now()
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else ZERO_HASH
    payload = {
        "occurred_at": occurred_at,
        "actor_id": actor_id,
        "action": action,
        "document_id": document_id,
        "details": details_json,
        "previous_hash": previous_hash,
    }
    event_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    connection.execute(
        """INSERT INTO audit_events
           (occurred_at, actor_id, action, document_id, details, previous_hash, event_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (occurred_at, actor_id, action, document_id, details_json, previous_hash, event_hash),
    )


def verify_audit(connection: sqlite3.Connection) -> bool:
    previous_hash = ZERO_HASH
    for row in connection.execute("SELECT * FROM audit_events ORDER BY id"):
        if row["previous_hash"] != previous_hash:
            return False
        payload = {
            "occurred_at": row["occurred_at"],
            "actor_id": row["actor_id"],
            "action": row["action"],
            "document_id": row["document_id"],
            "details": row["details"],
            "previous_hash": row["previous_hash"],
        }
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if not hmac.compare_digest(expected, row["event_hash"]):
            return False
        previous_hash = row["event_hash"]
    return True


def validate_file(filename: str, content: bytes) -> tuple[str, str]:
    suffix = Path(filename).suffix.lower()
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File must be between 1 byte and 10 MiB")
    signatures = {
        ".pdf": (content.startswith(b"%PDF-"), "application/pdf"),
        ".png": (content.startswith(b"\x89PNG\r\n\x1a\n"), "image/png"),
        ".jpg": (content.startswith(b"\xff\xd8\xff"), "image/jpeg"),
        ".jpeg": (content.startswith(b"\xff\xd8\xff"), "image/jpeg"),
    }
    if suffix == ".txt":
        try:
            content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise HTTPException(status_code=415, detail="Text files must be UTF-8") from error
        if b"\x00" in content:
            raise HTTPException(status_code=415, detail="Invalid text file")
        return "text/plain", suffix
    match = signatures.get(suffix)
    if not match or not match[0]:
        raise HTTPException(status_code=415, detail="Supported formats: PDF, PNG, JPEG, UTF-8 text")
    return match[1], suffix


def create_app(
    db_path: str | None = None,
    encryption_key: bytes | None = None,
    environment: str | None = None,
) -> FastAPI:
    database_path = db_path or os.getenv("TRUSTVAULT_DATABASE", str(ROOT / "trustvault.db"))
    runtime_environment = environment or os.getenv("TRUSTVAULT_ENV", "development")
    configured_key = encryption_key
    raw_key = os.getenv("TRUSTVAULT_ENCRYPTION_KEY")
    if configured_key is None and raw_key:
        try:
            configured_key = base64.b64decode(raw_key, validate=True)
        except ValueError as error:
            raise RuntimeError("TRUSTVAULT_ENCRYPTION_KEY must be base64") from error
    if configured_key is None and runtime_environment != "production":
        configured_key = hashlib.sha256(b"TrustVault local development key only").digest()
    if configured_key is None or len(configured_key) != 32:
        raise RuntimeError("Set TRUSTVAULT_ENCRYPTION_KEY to a base64-encoded 32-byte key")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        admin_username = os.getenv("TRUSTVAULT_ADMIN_USERNAME")
        admin_password = os.getenv("TRUSTVAULT_ADMIN_PASSWORD")
        if (admin_username is None) != (admin_password is None):
            raise RuntimeError("Set both TRUSTVAULT_ADMIN_USERNAME and TRUSTVAULT_ADMIN_PASSWORD")
        if runtime_environment == "production" and not admin_username:
            raise RuntimeError("Production requires TRUSTVAULT_ADMIN_USERNAME and TRUSTVAULT_ADMIN_PASSWORD")
        if admin_password is not None and len(admin_password) < 12:
            raise RuntimeError("TRUSTVAULT_ADMIN_PASSWORD must be at least 12 characters")
        connection = open_db(database_path)
        try:
            connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            if admin_username and admin_password:
                existing = connection.execute(
                    "SELECT id FROM users WHERE username = ?", (admin_username,)
                ).fetchone()
                if not existing:
                    salt = secrets.token_bytes(16)
                    connection.execute(
                        "INSERT INTO users (id, username, password_salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, 'admin', ?)",
                        (str(uuid.uuid4()), admin_username, salt, password_hash(admin_password, salt), utc_now()),
                    )
            connection.commit()
        finally:
            connection.close()
        yield

    api = FastAPI(title="TrustVault API", version="0.1.0", lifespan=lifespan)

    def db_dependency():
        connection = open_db(database_path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    Db = Annotated[sqlite3.Connection, Depends(db_dependency)]

    def current_user(
        authorization: Annotated[str | None, Header()] = None,
        connection: sqlite3.Connection = Depends(db_dependency),
    ) -> sqlite3.Row:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authentication required")
        token = authorization[7:]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = connection.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not session or session["expires_at"] <= utc_now():
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        user = connection.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")
        return user

    User = Annotated[sqlite3.Row, Depends(current_user)]

    def require_admin(user: sqlite3.Row) -> None:
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Administrator role required")

    def document_access(
        connection: sqlite3.Connection,
        document_id: str,
        user: sqlite3.Row,
        permission: str = "read",
    ) -> sqlite3.Row:
        document = connection.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        grant = connection.execute(
            "SELECT permission FROM permissions WHERE document_id = ? AND user_id = ?",
            (document_id, user["id"]),
        ).fetchone()
        allowed = bool(
            document
            and (
                document["owner_id"] == user["id"]
                or (grant and (grant["permission"] == "edit" or permission == "read"))
            )
        )
        if not allowed:
            append_audit(connection, user["id"], "access_denied", document_id, {"required": permission})
            connection.commit()
            raise HTTPException(status_code=404, detail="Document not found")
        if permission == "read":
            append_audit(connection, user["id"], "metadata_read", document_id)
        return document

    def document_response(document: sqlite3.Row) -> dict:
        return {
            "id": document["id"],
            "owner_id": document["owner_id"],
            "owner_username": document["owner_username"] if "owner_username" in document.keys() else None,
            "name": document["name"],
            "category": document["category"],
            "filename": document["filename"],
            "media_type": document["media_type"],
            "created_at": document["created_at"],
            "updated_at": document["updated_at"],
        }

    class UserCreate(BaseModel):
        username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
        password: str = Field(min_length=12, max_length=256)
        role: str

    class MetadataUpdate(BaseModel):
        name: str | None = Field(default=None, min_length=1, max_length=200)
        category: str | None = Field(default=None, min_length=1, max_length=100)

    class PermissionUpdate(BaseModel):
        permission: str

    @api.post("/api/auth/login")
    def login(connection: Db, username: str = Form(), password: str = Form()):
        user = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        salt = user["password_salt"] if user else DUMMY_PASSWORD_SALT
        expected_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
        password_matches = hmac.compare_digest(password_hash(password, salt), expected_hash)
        valid = user is not None and password_matches
        if not valid:
            append_audit(connection, user["id"] if user else None, "login_denied", details={"username": username[:80]})
            connection.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hashlib.sha256(token.encode()).hexdigest(), user["id"], expires.isoformat()),
        )
        append_audit(connection, user["id"], "login")
        return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat(), "role": user["role"]}

    @api.post("/api/auth/logout", status_code=204)
    def logout(connection: Db, user: User, authorization: Annotated[str, Header()]):
        token_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        append_audit(connection, user["id"], "logout")
        return Response(status_code=204)

    @api.post("/api/users", status_code=201)
    def create_user(body: UserCreate, connection: Db, user: User):
        require_admin(user)
        if body.role not in ROLES:
            raise HTTPException(status_code=422, detail="Role must be admin, owner, or viewer")
        salt = secrets.token_bytes(16)
        user_id = str(uuid.uuid4())
        try:
            connection.execute(
                "INSERT INTO users (id, username, password_salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, body.username, salt, password_hash(body.password, salt), body.role, utc_now()),
            )
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=409, detail="Username already exists") from error
        append_audit(connection, user["id"], "user_created", details={"user_id": user_id, "role": body.role})
        return {"id": user_id, "username": body.username, "role": body.role}

    @api.get("/api/users")
    def list_users(connection: Db, user: User):
        if user["role"] not in {"admin", "owner"}:
            raise HTTPException(status_code=403, detail="Owner or administrator role required")
        rows = connection.execute("SELECT id, username, role FROM users ORDER BY username COLLATE NOCASE")
        return [dict(row) for row in rows]

    @api.post("/api/documents", status_code=201)
    async def upload_document(
        connection: Db,
        user: User,
        name: Annotated[str, Form(min_length=1, max_length=200)],
        category: Annotated[str, Form(min_length=1, max_length=100)],
        file: Annotated[UploadFile, File()],
    ):
        if user["role"] not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Only owners can upload documents")
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        media_type, _ = validate_file(file.filename or "", content)
        document_id = str(uuid.uuid4())
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(configured_key).encrypt(nonce, content, document_id.encode())
        created_at = utc_now()
        basename = Path((file.filename or "document").replace("\\", "/")).name[:255]
        safe_filename = "".join(character for character in basename if character.isprintable()) or "document"
        connection.execute(
            """INSERT INTO documents
               (id, owner_id, name, category, filename, media_type, nonce, encrypted_content, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (document_id, user["id"], name, category, safe_filename, media_type, nonce, ciphertext, created_at, created_at),
        )
        append_audit(connection, user["id"], "upload", document_id, {"filename": safe_filename})
        return {"id": document_id, "name": name, "category": category, "created_at": created_at}

    @api.get("/api/documents")
    def list_documents(
        connection: Db,
        user: User,
        q: str | None = Query(default=None, max_length=200),
        owner: str | None = None,
        category: str | None = Query(default=None, max_length=100),
        created_after: str | None = None,
        created_before: str | None = None,
    ):
        sql = """SELECT DISTINCT d.*, owner_user.username AS owner_username
             FROM documents d
             JOIN users owner_user ON owner_user.id = d.owner_id
                 LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
                 WHERE (d.owner_id = ? OR p.user_id IS NOT NULL)"""
        params: list = [user["id"], user["id"]]
        if q:
            sql += " AND d.name LIKE ? ESCAPE '\\'"
            escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
        if owner:
            sql += " AND d.owner_id = ?"
            params.append(owner)
        if category:
            sql += " AND d.category = ?"
            params.append(category)
        if created_after:
            sql += " AND d.created_at >= ?"
            params.append(created_after)
        if created_before:
            sql += " AND d.created_at <= ?"
            params.append(created_before)
        sql += " ORDER BY d.created_at DESC LIMIT 500"
        documents = list(connection.execute(sql, params))
        for document in documents:
            append_audit(connection, user["id"], "document_listed", document["id"])
        return [document_response(row) for row in documents]

    @api.get("/api/documents/{document_id}")
    def get_document(document_id: str, connection: Db, user: User):
        return document_response(document_access(connection, document_id, user))

    @api.get("/api/documents/{document_id}/content")
    def download_document(document_id: str, connection: Db, user: User):
        document = document_access(connection, document_id, user, "read")
        content = AESGCM(configured_key).decrypt(
            document["nonce"], document["encrypted_content"], document_id.encode()
        )
        append_audit(connection, user["id"], "download", document_id)
        return Response(
            content=content,
            media_type=document["media_type"],
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(document['filename'], safe='')}",
                "Cache-Control": "no-store",
            },
        )

    @api.patch("/api/documents/{document_id}")
    def update_document(document_id: str, body: MetadataUpdate, connection: Db, user: User):
        document = document_access(connection, document_id, user, "edit")
        changes = body.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=400, detail="No changes supplied")
        fields = [f"{field} = ?" for field in changes]
        values = list(changes.values())
        values.extend([utc_now(), document_id])
        connection.execute(
            f"UPDATE documents SET {', '.join(fields)}, updated_at = ? WHERE id = ?", values
        )
        append_audit(connection, user["id"], "change", document_id, changes)
        updated = connection.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        return document_response(updated)

    @api.put("/api/documents/{document_id}/permissions/{target_user_id}")
    def grant_permission(
        document_id: str,
        target_user_id: str,
        body: PermissionUpdate,
        connection: Db,
        user: User,
    ):
        document = connection.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if not document or document["owner_id"] != user["id"]:
            append_audit(connection, user["id"], "permission_change_denied", document_id)
            connection.commit()
            raise HTTPException(status_code=404, detail="Document not found")
        if body.permission not in {"read", "edit"}:
            raise HTTPException(status_code=422, detail="Permission must be read or edit")
        if not connection.execute("SELECT id FROM users WHERE id = ?", (target_user_id,)).fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        connection.execute(
            """INSERT INTO permissions (document_id, user_id, permission, granted_by, granted_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(document_id, user_id) DO UPDATE SET
               permission = excluded.permission, granted_by = excluded.granted_by, granted_at = excluded.granted_at""",
            (document_id, target_user_id, body.permission, user["id"], utc_now()),
        )
        append_audit(connection, user["id"], "permission_granted", document_id,
                     {"user_id": target_user_id, "permission": body.permission})
        return {"document_id": document_id, "user_id": target_user_id, "permission": body.permission}

    @api.delete("/api/documents/{document_id}/permissions/{target_user_id}", status_code=204)
    def revoke_permission(document_id: str, target_user_id: str, connection: Db, user: User):
        document = connection.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if not document or document["owner_id"] != user["id"]:
            append_audit(connection, user["id"], "permission_change_denied", document_id)
            connection.commit()
            raise HTTPException(status_code=404, detail="Document not found")
        connection.execute(
            "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
            (document_id, target_user_id),
        )
        append_audit(connection, user["id"], "permission_revoked", document_id, {"user_id": target_user_id})
        return Response(status_code=204)

    @api.delete("/api/documents/{document_id}", status_code=204)
    def delete_document(document_id: str, connection: Db, user: User):
        document = document_access(connection, document_id, user, "edit")
        if document["owner_id"] != user["id"]:
            append_audit(connection, user["id"], "deletion_denied", document_id, {"required": "owner"})
            connection.commit()
            raise HTTPException(status_code=403, detail="Only the owner can delete a document")
        append_audit(connection, user["id"], "deletion", document_id, {"name": document["name"]})
        connection.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        return Response(status_code=204)

    @api.get("/api/admin/audit")
    def list_audit(
        connection: Db,
        user: User,
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ):
        require_admin(user)
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        )
        return [{**dict(row), "details": json.loads(row["details"])} for row in rows]

    @api.get("/api/admin/audit/verify")
    def audit_status(connection: Db, user: User):
        require_admin(user)
        return {"valid": verify_audit(connection)}

    @api.get("/health")
    def health():
        return {"status": "ok"}

    @api.get("/", include_in_schema=False)
    def web_app():
        return FileResponse(ROOT / "web" / "index.html")

    return api


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))