import sqlite3
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor

import app.main as trustvault
from fastapi.testclient import TestClient
import pytest

from app.main import create_app, password_hash


@contextmanager
def make_client(tmp_path):
    app = create_app(str(tmp_path / "test.db"), b"t" * 32)
    client = TestClient(app)
    with client:
        connection = sqlite3.connect(tmp_path / "test.db")
        for username, role in (("admin", "admin"), ("owner", "owner"), ("viewer", "viewer"), ("other", "viewer")):
            salt = (username + "-salt").encode()[:16].ljust(16, b"0")
            connection.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                (username, username, salt, password_hash("correct horse battery staple", salt), role, "2026-01-01T00:00:00+00:00"),
            )
        connection.commit()
        connection.close()
        yield client


def login(client, username):
    response = client.post(
        "/api/auth/login",
        data={"username": username, "password": "correct horse battery staple"},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_ungranted_user_cannot_read_download_or_change_document(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        other_headers = {"Authorization": f"Bearer {login(client, 'other')}"}

        uploaded = client.post(
            "/api/documents",
            headers=owner_headers,
            data={"name": "Offer letter", "category": "HR"},
            files={"file": ("letter.txt", b"salary data", "text/plain")},
        )
        assert uploaded.status_code == 201
        document_id = uploaded.json()["id"]

        assert client.get(f"/api/documents/{document_id}", headers=other_headers).status_code == 404
        assert client.get(f"/api/documents/{document_id}/content", headers=other_headers).status_code == 404
        assert client.patch(
            f"/api/documents/{document_id}", headers=other_headers, json={"name": "stolen"}
        ).status_code == 404
        assert client.delete(f"/api/documents/{document_id}", headers=other_headers).status_code == 404
        assert client.put(
            f"/api/documents/{document_id}/permissions/viewer",
            headers=other_headers, json={"permission": "read"},
        ).status_code == 404
        assert all(item["id"] != document_id for item in client.get("/api/documents", headers=other_headers).json())
        admin_headers = {"Authorization": f"Bearer {login(client, 'admin')}"}
        assert client.get(f"/api/documents/{document_id}", headers=admin_headers).status_code == 404

        owner_list = client.get("/api/documents", headers=owner_headers, params={"q": "% letter"})
        assert owner_list.status_code == 200
        assert owner_list.json() == []
        visible = client.get("/api/documents", headers=owner_headers).json()
        assert client.get(
            "/api/documents", headers=other_headers, params={"owner": visible[0]["owner_id"]}
        ).json() == []
        assert visible[0]["owner_username"] == "owner"


def test_revocation_takes_effect_on_next_request_and_is_audited(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        viewer_headers = {"Authorization": f"Bearer {login(client, 'viewer')}"}
        viewer_id = next(
            user["id"] for user in client.get("/api/users", headers=owner_headers).json()
            if user["username"] == "viewer"
        )
        uploaded = client.post(
            "/api/documents", headers=owner_headers,
            data={"name": "Contract", "category": "Legal"},
            files={"file": ("contract.txt", b"terms", "text/plain")},
        )
        document_id = uploaded.json()["id"]
        assert client.put(
            f"/api/documents/{document_id}/permissions/viewer",
            headers=owner_headers, json={"permission": "read"},
        ).status_code == 200
        assert client.get(f"/api/documents/{document_id}/content", headers=viewer_headers).content == b"terms"
        assert client.get("/api/documents", headers=viewer_headers).json()[0]["id"] == document_id
        assert client.delete(
            f"/api/documents/{document_id}/permissions/viewer", headers=owner_headers
        ).status_code == 204
        assert client.get(f"/api/documents/{document_id}/content", headers=viewer_headers).status_code == 404

        connection = sqlite3.connect(tmp_path / "test.db")
        actions = [row[0] for row in connection.execute("SELECT action FROM audit_events")]
        audited_reads = connection.execute(
            "SELECT actor_id, document_id, action FROM audit_events WHERE action IN ('metadata_read', 'document_listed')"
        ).fetchall()
        connection.close()
        assert "access_denied" in actions
        assert "permission_revoked" in actions
        assert {row[2] for row in audited_reads} == {"metadata_read", "document_listed"}
        assert all(row[0] == viewer_id and row[1] == document_id for row in audited_reads)


def test_document_grants_are_scoped_and_enforce_read_vs_edit(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        viewer_headers = {"Authorization": f"Bearer {login(client, 'viewer')}"}
        other_headers = {"Authorization": f"Bearer {login(client, 'other')}"}
        viewer_id = next(
            user["id"] for user in client.get("/api/users", headers=owner_headers).json()
            if user["username"] == "viewer"
        )

        def upload(name):
            response = client.post(
                "/api/documents",
                headers=owner_headers,
                data={"name": name, "category": "Legal"},
                files={"file": (f"{name}.txt", name.encode(), "text/plain")},
            )
            assert response.status_code == 201
            return response.json()["id"]

        read_id = upload("read-only")
        edit_id = upload("editable")
        for document_id, permission in ((read_id, "read"), (edit_id, "edit")):
            assert client.put(
                f"/api/documents/{document_id}/permissions/{viewer_id}",
                headers=owner_headers,
                json={"permission": permission},
            ).status_code == 200

        assert client.get(f"/api/documents/{read_id}", headers=viewer_headers).status_code == 200
        assert client.get(f"/api/documents/{read_id}/content", headers=viewer_headers).content == b"read-only"
        assert client.patch(
            f"/api/documents/{read_id}", headers=viewer_headers, json={"name": "changed"}
        ).status_code == 404
        assert client.delete(f"/api/documents/{read_id}", headers=viewer_headers).status_code == 404

        changed = client.patch(
            f"/api/documents/{edit_id}", headers=viewer_headers, json={"name": "updated"}
        )
        assert changed.status_code == 200
        assert changed.json()["name"] == "updated"
        assert client.get(f"/api/documents/{edit_id}/content", headers=viewer_headers).content == b"editable"
        assert client.delete(f"/api/documents/{edit_id}", headers=viewer_headers).status_code == 403

        visible_ids = {
            item["id"] for item in client.get("/api/documents", headers=viewer_headers).json()
        }
        assert visible_ids == {read_id, edit_id}
        for document_id in (read_id, edit_id):
            assert client.get(f"/api/documents/{document_id}", headers=other_headers).status_code == 404
            assert client.get(f"/api/documents/{document_id}/content", headers=other_headers).status_code == 404
            assert client.patch(
                f"/api/documents/{document_id}", headers=other_headers, json={"name": "intrusion"}
            ).status_code == 404
            assert client.delete(f"/api/documents/{document_id}", headers=other_headers).status_code == 404


def test_search_filters_only_return_documents_the_caller_can_access(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        viewer_headers = {"Authorization": f"Bearer {login(client, 'viewer')}"}
        users = client.get("/api/users", headers=owner_headers).json()
        viewer_id = next(user["id"] for user in users if user["username"] == "viewer")

        def upload(name, category):
            response = client.post(
                "/api/documents",
                headers=owner_headers,
                data={"name": name, "category": category},
                files={"file": (f"{name}.txt", b"contents", "text/plain")},
            )
            assert response.status_code == 201
            return response.json()["id"]

        visible_id = upload("Alpha contract", "Legal")
        hidden_id = upload("Secret payroll", "HR")
        assert client.put(
            f"/api/documents/{visible_id}/permissions/{viewer_id}",
            headers=owner_headers,
            json={"permission": "read"},
        ).status_code == 200
        visible_doc = next(
            item for item in client.get("/api/documents", headers=owner_headers).json()
            if item["id"] == visible_id
        )

        owner_results = client.get(
            "/api/documents",
            headers=owner_headers,
            params={
                "q": "Alpha",
                "owner": visible_doc["owner_id"],
                "category": "Legal",
                "created_after": visible_doc["created_at"],
                "created_before": visible_doc["created_at"],
            },
        )
        assert [item["id"] for item in owner_results.json()] == [visible_id]
        viewer_results = client.get(
            "/api/documents",
            headers=viewer_headers,
            params={"q": "Secret", "category": "HR"},
        )
        assert viewer_results.json() == []
        assert hidden_id not in {item["id"] for item in viewer_results.json()}


def test_admin_can_verify_audit_and_detect_tampering(tmp_path):
    with make_client(tmp_path) as client:
        admin_headers = {"Authorization": f"Bearer {login(client, 'admin')}"}
        assert client.get("/api/admin/audit/verify", headers=admin_headers).json() == {"valid": True}
        assert client.get("/api/admin/audit", headers=admin_headers).status_code == 200
        viewer_headers = {"Authorization": f"Bearer {login(client, 'viewer')}"}
        assert client.get("/api/admin/audit", headers=viewer_headers).status_code == 403

        connection = sqlite3.connect(tmp_path / "test.db")
        connection.execute("UPDATE audit_events SET details = '{\"forged\":true}' WHERE id = 1")
        connection.commit()
        connection.close()

        assert client.get("/api/admin/audit/verify", headers=admin_headers).json() == {"valid": False}


def test_editor_cannot_delete_and_refusal_is_audited(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        editor_headers = {"Authorization": f"Bearer {login(client, 'viewer')}"}
        uploaded = client.post(
            "/api/documents", headers=owner_headers,
            data={"name": "Review copy", "category": "Legal"},
            files={"file": ("review.txt", b"review terms", "text/plain")},
        )
        document_id = uploaded.json()["id"]
        users = client.get("/api/users", headers=owner_headers).json()
        viewer_id = next(item["id"] for item in users if item["username"] == "viewer")
        assert client.put(
            f"/api/documents/{document_id}/permissions/{viewer_id}",
            headers=owner_headers, json={"permission": "edit"},
        ).status_code == 200

        assert client.delete(f"/api/documents/{document_id}", headers=editor_headers).status_code == 403
        assert client.get(f"/api/documents/{document_id}", headers=owner_headers).status_code == 200

        admin_headers = {"Authorization": f"Bearer {login(client, 'admin')}"}
        events = client.get("/api/admin/audit", headers=admin_headers).json()
        refusal = next(event for event in events if event["action"] == "deletion_denied")
        assert refusal["actor_id"] == viewer_id
        assert refusal["document_id"] == document_id
        assert client.get("/api/admin/audit/verify", headers=admin_headers).json() == {"valid": True}


def test_unknown_login_performs_password_hash_work(tmp_path, monkeypatch):
    with make_client(tmp_path) as client:
        original_password_hash = trustvault.password_hash
        hashes = []

        def track_hash(password, salt):
            hashes.append((password, salt))
            return original_password_hash(password, salt)

        monkeypatch.setattr(trustvault, "password_hash", track_hash)
        response = client.post(
            "/api/auth/login", data={"username": "missing-user", "password": "incorrect"}
        )

        assert response.status_code == 401
        assert len(hashes) == 1
        assert hashes[0][1] == trustvault.DUMMY_PASSWORD_SALT


def test_production_startup_requires_bootstrap_admin(tmp_path, monkeypatch):
    monkeypatch.delenv("TRUSTVAULT_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("TRUSTVAULT_ADMIN_PASSWORD", raising=False)
    app = create_app(str(tmp_path / "production.db"), b"p" * 32, environment="production")

    with pytest.raises(RuntimeError, match="Production requires"):
        with TestClient(app):
            pass


def test_browser_response_has_nonce_csp_and_security_headers(tmp_path):
    with make_client(tmp_path) as client:
        response = client.get("/")

        assert response.status_code == 200
        csp = response.headers["content-security-policy"]
        nonce_directive = next(part for part in csp.split(";") if "script-src" in part)
        nonce = nonce_directive.split("'nonce-", 1)[1].split("'", 1)[0]
        assert f'<script nonce="{nonce}">' in response.text
        assert f'<style nonce="{nonce}">' in response.text
        assert "'unsafe-inline'" not in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"

        api_response = client.get("/health")
        assert api_response.headers["content-security-policy"]
        assert api_response.headers["permissions-policy"] == (
            "camera=(), microphone=(), geolocation=()"
        )


def test_upload_rejects_invalid_signature_and_oversized_content(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        invalid_signature = client.post(
            "/api/documents", headers=owner_headers,
            data={"name": "Fake PDF", "category": "Legal"},
            files={"file": ("fake.pdf", b"not a pdf", "application/pdf")},
        )
        assert invalid_signature.status_code == 415

        oversized = client.post(
            "/api/documents", headers=owner_headers,
            data={"name": "Too large", "category": "Other"},
            files={"file": ("large.txt", b"x" * (trustvault.MAX_UPLOAD_BYTES + 1), "text/plain")},
        )
        assert oversized.status_code == 413
        assert client.get("/api/documents", headers=owner_headers).json() == []


def test_download_encodes_untrusted_filename(tmp_path):
    with make_client(tmp_path) as client:
        owner_headers = {"Authorization": f"Bearer {login(client, 'owner')}"}
        uploaded = client.post(
            "/api/documents", headers=owner_headers,
            data={"name": "Report", "category": "Legal"},
            files={"file": ("../annual\r\nreport.txt", b"report", "text/plain")},
        )
        document_id = uploaded.json()["id"]

        download = client.get(f"/api/documents/{document_id}/content", headers=owner_headers)

        assert download.status_code == 200
        assert "\r" not in download.headers["content-disposition"]
        assert "\n" not in download.headers["content-disposition"]
        assert "%0D" not in download.headers["content-disposition"]
        assert "%0A" not in download.headers["content-disposition"]


def test_concurrent_audit_writes_keep_a_valid_chain(tmp_path):
    database = tmp_path / "concurrent-audit.db"
    app = create_app(str(database), b"c" * 32)
    with TestClient(app):
        pass

    def append_event(index):
        connection = trustvault.open_db(str(database))
        try:
            trustvault.append_audit(connection, None, "concurrent_test", details={"index": index})
            connection.commit()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append_event, range(40)))

    connection = trustvault.open_db(str(database))
    try:
        assert trustvault.verify_audit(connection)
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 40
    finally:
        connection.close()