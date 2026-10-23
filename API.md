# TrustVault API

Every response includes a restrictive Content Security Policy and standard browser security headers. The browser app's inline script and styles use a per-response nonce; the CSP does not allow `unsafe-inline`.

All API routes use JSON responses unless noted. Authenticated routes require `Authorization: Bearer <access_token>`. The login token is an opaque eight-hour server-side session. Document IDs are identifiers, not permissions; each document route checks ownership or a current grant.

| Method and path | Who may call it | Authorization and behavior |
| --- | --- | --- |
| `GET /health` | Anyone | Liveness response only; does not report database or key readiness. |
| `GET /` | Anyone | Serves the browser application. |
| `POST /api/auth/login` | Anyone | Form fields `username`, `password`; creates a session on success. Failed attempts are audited. |
| `POST /api/auth/logout` | Any authenticated user | Revokes the caller's current session. |
| `POST /api/users` | Administrator | Creates a named `admin`, `owner`, or `viewer`; passwords must be at least 12 characters. |
| `GET /api/users` | Administrator or owner | Lists account IDs, usernames, and roles for user administration and sharing. |
| `POST /api/documents` | Owner or administrator | Multipart fields `name`, `category`, and `file`; validates and encrypts the file. |
| `GET /api/documents` | Any authenticated user | Lists only owned or explicitly shared documents. Supports `q`, `owner` (user ID), `category`, `created_after`, and `created_before`. |
| `GET /api/documents/{document_id}` | Owner or user with `read`/`edit` grant | Returns metadata. Missing and unauthorized documents both return `404`. |
| `GET /api/documents/{document_id}/content` | Owner or user with `read`/`edit` grant | Decrypts and downloads content; each successful download is audited. |
| `PATCH /api/documents/{document_id}` | Owner or user with `edit` grant | Changes `name` and/or `category`; owner/editor permission is checked on every request. |
| `PUT /api/documents/{document_id}/permissions/{target_user_id}` | Document owner | JSON body `{"permission":"read"}` or `{"permission":"edit"}`; creates or replaces a direct grant. |
| `DELETE /api/documents/{document_id}/permissions/{target_user_id}` | Document owner | Revokes a direct grant; the next request checks the new state. |
| `DELETE /api/documents/{document_id}` | Document owner | Permanently deletes the document and records the event. An editor cannot delete. |
| `GET /api/admin/audit` | Administrator | Lists audit events, newest first; `limit` is 1-1000 and `offset` is nonnegative. |
| `GET /api/admin/audit/verify` | Administrator | Verifies the hash links currently present in the database. |

The `admin` role does not grant document access. Owners have full control of their own documents. A `read` grant permits metadata and downloads; `edit` additionally permits metadata changes. Only the owner can manage grants or delete. An unauthorized document access returns the same `404` as an unknown ID; denied attempts are recorded where the request reaches a document authorization check.

Request and response schemas are also available from `/docs` and `/openapi.json`. The hash-linked audit log detects edits and deletions that break the chain, but because it is stored in the same SQLite database, it is not independently immutable. See [THREATS.md](THREATS.md).