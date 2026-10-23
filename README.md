# TrustVault

TrustVault is a secure-by-default document sharing application with a FastAPI API and browser UI. It uses SQLite, per-document grants, opaque server-side sessions, AES-256-GCM encrypted document bytes, and a hash-linked audit log. This is a runnable security-focused foundation, not a production certification; known limitations are listed in [THREATS.md](THREATS.md).

## Run locally

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export TRUSTVAULT_ADMIN_USERNAME=admin
export TRUSTVAULT_ADMIN_PASSWORD='change-this-local-password'
uvicorn app.main:app --reload
```

Set `TRUSTVAULT_ADMIN_USERNAME` and `TRUSTVAULT_ADMIN_PASSWORD` before the first start to create the initial administrator. The browser app is at `/`; OpenAPI is at `/docs`. Create owner and viewer accounts through `POST /api/users` as the administrator. Endpoint-level permissions are documented in [API.md](API.md).

Local development uses a fixed encryption key and is not suitable for deployment. For a container deployment, use a stable, separately backed-up 32-byte key and persistent data volume:

```sh
export TRUSTVAULT_ENCRYPTION_KEY="$(openssl rand -base64 32)"
docker build -t trustvault .
docker volume create trustvault-data
docker run --name trustvault --restart unless-stopped -p 8000:8000 \
	-v trustvault-data:/data \
	-e TRUSTVAULT_ENCRYPTION_KEY="$TRUSTVAULT_ENCRYPTION_KEY" \
	-e TRUSTVAULT_ADMIN_USERNAME=admin \
	-e TRUSTVAULT_ADMIN_PASSWORD='replace-with-a-unique-12-plus-character-secret' \
	trustvault
```

Put the service behind a trusted TLS-terminating reverse proxy; do not expose SQLite or its volume publicly. Preserve the encryption key across restarts and back it up separately from the database. Losing it makes stored documents unrecoverable. Use a secrets manager rather than shell history or committed environment files for real deployments.

## Authorization model

The server checks authorization for every document metadata, content, update, permission, and deletion request. A document owner has full control; a named `read` grant permits metadata and download; an `edit` grant additionally permits metadata changes. Document IDs and application roles are not grants. Administrators manage users and inspect the audit stream, but do not automatically read document content. Revocation deletes the grant, so the next request with an otherwise valid session is denied. Previously downloaded plaintext cannot be recalled.

## Roles and API

| Role | Allowed actions |
| --- | --- |
| `admin` | Create users; inspect and verify the audit chain; no implicit document access |
| `owner` | Upload, search own/shared documents, edit/delete owned documents, grant/revoke named users |
| `viewer` | Search and read documents with an explicit grant |

All `/api` routes require a bearer session except `POST /api/auth/login`. `GET /health` is public. Endpoint-specific role and grant rules are documented in [API.md](API.md) and request/response schemas are published at `/openapi.json`.

## Checks

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests cover cross-user access, immediate grant revocation, denied deletion auditing, login hash work for unknown usernames, and audit-chain tamper detection. Audit hashes detect accidental or partial modification, but a database administrator who can rewrite the entire SQLite file can recompute the chain. Production tamper resistance still needs external append-only/WORM anchoring. See [THREATS.md](THREATS.md) for current limitations.