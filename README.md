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

The production container uses the PostgreSQL connection in `TRUSTVAULT_DATABASE_URL`; it does not store document data on its local filesystem. Use a TLS-protected PostgreSQL service and keep the encryption key independent from the database. Put the app behind the provider's HTTPS endpoint, restrict database network access where possible, and use a pooled PostgreSQL URL for serverless deployments.

Generate and retain an independent 32-byte encryption key, and set a strong initial administrator password outside source control:

```sh
export TRUSTVAULT_ENCRYPTION_KEY="$(python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
read -rsp "Initial admin password: " TRUSTVAULT_ADMIN_PASSWORD
echo
export TRUSTVAULT_ADMIN_USERNAME=admin
docker build -t trustvault .
docker run --rm --name trustvault \
  -p 127.0.0.1:8000:8000 \
  -e TRUSTVAULT_DATABASE_URL \
  -e TRUSTVAULT_ENCRYPTION_KEY \
  -e TRUSTVAULT_ADMIN_USERNAME \
  -e TRUSTVAULT_ADMIN_PASSWORD \
  trustvault
```

Supply `TRUSTVAULT_DATABASE_URL` from a persistent PostgreSQL instance before running the container. Do not lose or rotate `TRUSTVAULT_ENCRYPTION_KEY` without first implementing a data re-encryption/migration plan: existing files cannot be decrypted with a different key. Back up the database and key separately, restrict access to both, and test restore procedures. The bootstrap admin is created only when its username does not already exist; changing the environment password does not change an existing account's password.

The container listens on port 8000. The sample binds it to loopback and is not a complete public deployment by itself. A public deployment still needs HTTPS, persistent database storage, backups, monitoring, account provisioning, and a secure method to deliver credentials to the judge. No provider, live URL, or judge credentials are being claimed here.

## Deploy on Vercel, Render, or Netlify

Cloud deployments use a shared PostgreSQL database for accounts, permissions, audit events, and the already AES-GCM-encrypted document bytes. This avoids relying on serverless or free-container local filesystems. SQLite remains supported for local development. PostgreSQL schema setup runs on application startup. Existing SQLite data is not automatically migrated; use a fresh database for a demo or plan a separate migration.

Use a PostgreSQL provider and plan that provide persistent storage for as long as the demo must remain available. A free compute plan does not imply free or persistent database storage, and provider terms, limits, sleep behavior, and payment requirements change. Verify they still meet the challenge's no-credit-card requirement in the provider dashboard before proceeding. Use synthetic demo documents only.

Set these secrets in the host dashboard, not in Git:

| Variable | Value |
| --- | --- |
| `TRUSTVAULT_ENV` | `production` |
| `TRUSTVAULT_DATABASE_URL` | PostgreSQL connection URL, preferably a pooled URL with TLS required |
| `TRUSTVAULT_ENCRYPTION_KEY` | Base64-encoded independent 32-byte key |
| `TRUSTVAULT_ADMIN_USERNAME` | Initial admin username |
| `TRUSTVAULT_ADMIN_PASSWORD` | Initial admin password, at least 12 characters |

Generate the encryption key locally with `python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())'`. Store it in the host's secret manager. Loss of this key makes all stored document contents unreadable.

### [Vercel](https://vercel.com/docs/frameworks/backend/fastapi) (FastAPI backend)

Import the repository as a Python project; the root `index.py` exports the FastAPI application and `vercel.json` includes the schema and UI files. Add all five variables above to the Vercel project for the desired environment, then deploy. The PostgreSQL service must allow connections from the app; prefer a pooled TLS connection URL. Vercel's function filesystem is not used for document persistence.

### [Render](https://render.com/docs/deploy-fastapi) (FastAPI backend)

Create a Render Blueprint from this repository using `render.yaml`, or create a Python web service with build command `pip install -r requirements.txt` and start command `uvicorn index:app --host 0.0.0.0 --port $PORT`. Add the PostgreSQL URL and four remaining secret variables in the service environment. The blueprint requests the free web-service plan and has no local disk dependency; pair it with the same persistent external PostgreSQL database. A sleeping/free compute service may be slow on its first request after idle.

### [Netlify](https://docs.netlify.com/build/functions/overview/) (same-origin frontend proxy)

Netlify does not run this Python ASGI application as a Netlify Function. Deploy the FastAPI backend to Vercel or Render first, then edit `web/_redirects` and replace `your-trustvault-api.example.com` with that backend's HTTPS hostname. Deploy this repository to Netlify with `netlify.toml`; it publishes `web/` and force-proxies every path to the backend so both the dynamic UI and API remain same-origin to the browser. Confirm the deployed URL serves the dynamically nonce-protected HTML from the backend and can log in before sharing it.

These are deployment configurations, not proof that a provider account has been provisioned or that a live URL exists. The app is not production-certified: its audit chain remains in PostgreSQL and can be rewritten by a database administrator; no external immutable audit anchor or rate limiting is implemented.

## First users and demo data

On a fresh database, sign in as the bootstrap administrator and use **Create user** to provision owner or viewer accounts in the browser; `POST /api/users` remains available for API-based provisioning. Use unique passwords of at least 12 characters and deliver them out of band; never commit real passwords, access tokens, or encryption keys.

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
- **Storage:** file bytes are AES-256-GCM encrypted with a random nonce and the document ID as associated data before being written to SQLite locally or PostgreSQL in cloud deployments. The single configured key protects all documents and must be stored separately from the database.
- **Audit:** actions and denied document access are stored in a SHA-256 hash-linked chain in the configured database. The append operation serializes concurrent writers. This detects edits/deletions that break the chain, but it does **not** prove history against an attacker who can rewrite the database and recompute the chain. There is no independent immutable audit sink or signed external checkpoint.
- **Upload validation:** the API bounds uploads to 10 MiB and accepts signature-checked PDF/PNG/JPEG or UTF-8 text. It does not perform antivirus scanning, PDF content inspection, or content disarm.
- **Browser:** bearer tokens stay in JavaScript memory, so refresh signs the user out. Responses carry a nonce-based CSP and standard security headers. The token is not stored in cookies or local storage.
- **AI use:** see [PROMPTS.md](PROMPTS.md) for dated prompt/review evidence, including an incorrect test expectation and how it was corrected.

## Verification and hand-in status

Run the automated suite with `python -m pytest -q`. It covers authorization/refusal paths, immediate revocation, role boundaries, read-vs-edit grants, cross-user search isolation, upload validation, audit-chain tampering and concurrent appends, login work for unknown users, production bootstrap requirements, and security headers. PostgreSQL integration coverage is skipped unless `TRUSTVAULT_TEST_DATABASE_URL` points to a dedicated disposable PostgreSQL test database; run it with `TRUSTVAULT_TEST_DATABASE_URL="$TEST_DATABASE_URL" python -m pytest -q -k postgres_document_access_and_revocation`.

Endpoint-specific authorization is in [API.md](API.md); current and accepted threat gaps are in [THREATS.md](THREATS.md). The original prompt's ten functional requirements are the target; this repo has no separate supplied requirement file. A hosted judge URL, pre-seeded judge account credentials, a recorded five-minute demo video, external immutable audit anchoring, rate limiting, and production key management are not included by this local checkout. Complete those as real deployment/operator actions before describing a public demo as ready.

### Five-minute demo outline

1. Sign in as an owner and upload a synthetic text file.
2. Sign in as an unrelated viewer and demonstrate that list, metadata, content, edit, and delete routes do not reveal it.
3. Grant the named viewer read access; show that the viewer can read/download but cannot edit or delete.
4. Revoke the grant and immediately retry the old session's download.
5. Sign in as admin, inspect audit events, and verify the audit chain. Explain honestly that same-database rewriting is outside the chain's protection.
