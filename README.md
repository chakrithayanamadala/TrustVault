# TrustVault

TrustVault is a document-sharing API and browser UI built with FastAPI, SQLite, and AES-GCM. This repository is a security-focused challenge implementation, not a production-certified document service. There is no hosted demo URL or public demo credential configured by this checkout.

## Run locally

Requirements: Python 3.12 or newer.

```sh
git clone https://github.com/chakrithayanamadala/TrustVault.git
cd TrustVault
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
export TRUSTVAULT_ADMIN_USERNAME=admin
read -rsp "Initial admin password: " TRUSTVAULT_ADMIN_PASSWORD
echo
export TRUSTVAULT_ADMIN_PASSWORD
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Local development uses a fixed, non-production encryption key and does not create an initial admin automatically. Create the first admin through the bootstrap environment variables described below.

## Container deployment

The service stores its SQLite database at `/data/trustvault.db` in the image. Mount persistent storage at `/data`; do not use an ephemeral container filesystem for documents or audit history. Use one application instance: SQLite is not configured for multi-host concurrent writers. Put the service behind a TLS-terminating reverse proxy, restrict network access to the container, and configure the proxy/host to forward the original scheme and client address safely.

Generate and retain an independent 32-byte encryption key, and set a strong initial administrator password outside source control:

```sh
export TRUSTVAULT_ENCRYPTION_KEY="$(python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
read -rsp "Initial admin password: " TRUSTVAULT_ADMIN_PASSWORD
echo
export TRUSTVAULT_ADMIN_USERNAME=admin
docker build -t trustvault .
docker volume create trustvault-data
docker run -d --name trustvault \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  -v trustvault-data:/data \
  -e TRUSTVAULT_ENCRYPTION_KEY \
  -e TRUSTVAULT_ADMIN_USERNAME \
  -e TRUSTVAULT_ADMIN_PASSWORD \
  trustvault
```

Do not lose or rotate `TRUSTVAULT_ENCRYPTION_KEY` without first implementing a data re-encryption/migration plan: existing files cannot be decrypted with a different key. Back up the database and key separately, restrict access to both, and test restore procedures. The bootstrap admin is created only when its username does not already exist; changing the environment password does not change an existing account's password.

The container listens on port 8000. The sample binds it to loopback and is not a complete public deployment by itself. A public deployment still needs HTTPS, persistent storage, backups, monitoring, account provisioning, and a secure method to deliver credentials to the judge. A free host is suitable only if it provides a persistent mounted disk and does not sleep or discard that disk in a way that breaks the demo. No provider, live URL, or judge credentials are being claimed here.

## First users and demo data

On a fresh database, the bootstrap administrator can create an owner and viewer at `POST /api/users`. Create a viewer the same way. Use unique passwords of at least 12 characters and deliver them out of band; never commit real passwords, access tokens, or encryption keys.

Example user creation request after obtaining an admin bearer token:

```sh
curl -X POST http://127.0.0.1:8000/api/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"owner-demo","password":"REPLACE_WITH_A_UNIQUE_SECRET","role":"owner"}'
```

Create a viewer account, sign in as the owner, upload a small UTF-8 `.txt` file, and grant the viewer `read` access through the UI or `PUT /api/documents/{document_id}/permissions/{target_user_id}`. Verify the viewer can download it, then revoke access and verify the next request returns `404`. Use synthetic, non-confidential content only.

## Design and security boundaries

- **Authentication and roles:** opaque server-side sessions expire after eight hours. Passwords are salted and scrypt-hashed. Administrators provision accounts and inspect audit events; owners upload and control their documents; viewers can only access documents explicitly granted to them. The admin role does not grant document access.
- **Permissions:** grants are direct per-document `read` or `edit` rows. The server checks the current database grant for each document route. Read grants allow metadata and download; edit grants also allow metadata changes. Only the owner can grant/revoke access or delete. Missing and unauthorized document IDs return the same `404`.
- **Storage:** file bytes are AES-256-GCM encrypted with a random nonce and the document ID as associated data before being written to SQLite. The single configured key protects all documents and must be stored separately from the database.
- **Audit:** actions and denied document access are stored in a SHA-256 hash-linked SQLite chain. The append operation serializes concurrent writers. This detects edits/deletions that break the chain, but it does **not** prove history against an attacker who can rewrite the database and recompute the chain. There is no independent immutable audit sink or signed external checkpoint.
- **Upload validation:** the API bounds uploads to 10 MiB and accepts signature-checked PDF/PNG/JPEG or UTF-8 text. It does not perform antivirus scanning, PDF content inspection, or content disarm.
- **Browser:** bearer tokens stay in JavaScript memory, so refresh signs the user out. Responses carry a nonce-based CSP and standard security headers. The token is not stored in cookies or local storage.
- **AI use:** see [PROMPTS.md](PROMPTS.md) for dated prompt/review evidence, including an incorrect test expectation and how it was corrected.

## Verification and hand-in status

Run the automated suite with `python -m pytest -q`. It covers authorization/refusal paths, immediate revocation, role boundaries, read-vs-edit grants, cross-user search isolation, upload validation, audit-chain tampering and concurrent appends, login work for unknown users, production bootstrap requirements, and security headers.

Endpoint-specific authorization is in [API.md](API.md); current and accepted threat gaps are in [THREATS.md](THREATS.md). The original prompt's ten functional requirements are the target; this repo has no separate supplied requirement file. A hosted judge URL, pre-seeded judge account credentials, a recorded five-minute demo video, external immutable audit anchoring, rate limiting, and production key management are not included by this local checkout. Complete those as real deployment/operator actions before describing a public demo as ready.

### Five-minute demo outline

1. Sign in as an owner and upload a synthetic text file.
2. Sign in as an unrelated viewer and demonstrate that list, metadata, content, edit, and delete routes do not reveal it.
3. Grant the named viewer read access; show that the viewer can read/download but cannot edit or delete.
4. Revoke the grant and immediately retry the old session's download.
5. Sign in as admin, inspect audit events, and verify the audit chain. Explain honestly that same-database rewriting is outside the chain's protection.
