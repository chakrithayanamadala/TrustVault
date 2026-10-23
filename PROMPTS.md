# AI Prompt Log

This log starts with the first implementation pass on 2026-10-22. Entries are recorded as work happens. The implementation work from this session was consolidated in one commit, rather than a week-long sequence of commits.

## 2026-10-22

- **Asked:** Build the initial TrustVault project from the supplied requirements, prioritizing server-enforced per-document authorization, immediate revocation, encrypted storage, and auditable denied requests.
- **Produced:** FastAPI/SQLite API foundation, opaque sessions, per-document read/edit grants, AES-GCM encrypted bytes, hash-linked audit rows, starter docs, and authorization tests.
- **What was wrong or incomplete:** The audit chain is only tamper-evident if its SQLite database is protected; a database administrator can rewrite it. External immutable anchoring, key management/rotation, rate limits, UI, deployment, and broad tests are not implemented. The implementation must not be described as production-ready yet.
- **What I did instead:** Documented those limitations in `THREATS.md`, required a non-default encryption key in production mode, and started tests that directly exercise the access-control boundary. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

- **Asked:** Review authorization refusals for missing audit events and add a regression test for an editor attempting owner-only deletion.
- **Produced:** A `deletion_denied` event before returning `403`, plus a test checking the document remains and the audit chain verifies.
- **What was wrong or incomplete:** The first edit committed the denial event before raising; without that explicit commit, the request dependency rolled back the audit row along with the refused operation.
- **What I did instead:** Kept the explicit commit and verified the actor, document, refusal response, and chain integrity through the API. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

- **Asked:** Check whether unknown usernames follow the same password verification path as known usernames.
- **Produced:** A dummy scrypt salt/hash for missing accounts and a focused test that observes the hash operation on failed login.
- **What was wrong or incomplete:** The previous `user and password_hash(...)` expression skipped expensive scrypt work when the username did not exist, creating a timing-based account enumeration signal.
- **What I did instead:** Compute and compare a dummy hash for missing users and assert the behavior. This reduces the signal but is not a substitute for rate limiting. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

- **Asked:** Wire the existing server-side owner filter into the browser and ensure owner labels do not leak through search.
- **Produced:** An owner selector populated from authorized document results and a cross-user owner-filter regression assertion.
- **What was wrong or incomplete:** The first test assumed upload responses returned `owner_id`, but the upload response deliberately omits it; the endpoint itself had not failed.
- **What I did instead:** Read the owner ID from the owner's authorized listing, reran the test, and kept owner names scoped to returned authorized documents. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

- **Asked:** Make the clean deployment instructions executable and document endpoint-specific authorization; check production startup prerequisites.
- **Produced:** An endpoint/role reference, Docker build/run instructions, synchronized threat notes, and a production bootstrap-admin guard.
- **What was wrong or incomplete:** Production mode could start without an admin, resulting in a service that could not create users. The first combined docs patch also failed to apply because of patch context ordering.
- **What I did instead:** Added the admin credential guard and isolated docs into smaller edits; its lifespan test passes. The image built, and the container's health, UI, and admin login smoke checks passed locally. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

- **Asked:** Check audit-chain behavior under concurrent writes and review untrusted filenames in download headers.
- **Produced:** A serialized audit append using a SQLite write-lock row, a concurrent-writer chain test, and filename sanitization plus UTF-8 header encoding.
- **What was wrong or incomplete:** Audit appenders could have read the same previous hash before writing. The first concurrency test also used raw SQLite connections without the application's row factory, so it failed in test setup before chain verification.
- **What I did instead:** Acquire the SQLite write lock before reading the prior event, use `open_db` in the stress test, verify 40 concurrent events, and test CR/LF filename handling. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

- **Asked:** Verify that successful document reads, not only refused access and downloads, are attributable in the audit record.
- **Produced:** Events for metadata reads and for each authorized document included in a list result, with a test asserting actor and document IDs.
- **What was wrong or incomplete:** The initial test draft included an empty-collection assertion that could never fail, so it did not actually validate the actor identity.
- **What I did instead:** Replaced it with explicit viewer ID and document ID assertions and reran the read/revocation test. Commit: [7940f47](https://github.com/YNAGARAJ/TustVault/commit/7940f47).

## Reused context

- The project requirements supplied in the initial conversation were used as the task context. No repository-specific prompt or agent instruction files were present at kickoff.

## 2026-10-23

- **Asked:** Review the full checkout against the TrustVault requirements, then harden the browser response against script injection and document the control.
- **Produced:** Per-response Content Security Policy nonces for the app's inline script and styles, plus MIME-sniffing, framing, referrer, and permissions headers. Added a regression test tying the rendered nonce to the CSP and updated `API.md` and `THREATS.md`. Commit: [ec2c0fc](https://github.com/chakrithayanamadala/TrustVault/commit/ec2c0fc).
- **What was wrong or incomplete:** The first implementation draft tried to read the nonce from application state, but the nonce is unique per request; under concurrency that could pair the wrong nonce with a response. I caught that while checking how the middleware and root route shared state, changed the route to use the request-scoped nonce, and verified the rendered HTML and response header agree in a test.
- **What I did instead:** Kept the nonce on `request.state`, tested both the HTML response and API security headers, then ran the full test suite (10 passed). This test is an HTTP-level header/rendering check, not a substitute for browser CSP testing.

The earlier entries above were present in the starting checkout and reference commit `7940f47`, which is not in this repository's available Git history. I have not treated that reference as a commit made or independently verified in this checkout.

- **Asked:** Add adversarial regression coverage for the permission matrix and ensure name/owner/category/date filters never escape the caller's authorized document set.
- **Produced:** Tests for a named read grant, a separate edit grant, owner-only deletion, denied cross-user metadata/download/edit/delete, and all four list filters. Commit: [f12140b](https://github.com/chakrithayanamadala/TrustVault/commit/f12140b).
- **What was wrong or incomplete:** My initial assertion expected `403` when a read-only grantee tried to delete. The endpoint checks edit access before its owner-only deletion rule, so it correctly returns the same `404` used to hide documents from ungranted users. The failing test exposed my mistaken expectation, not an implementation bug.
- **What I did instead:** Matched the assertion to the documented not-found policy, retained the separate `403` assertion for an editor who has edit access but is not the owner, and reran all tests (12 passed). These checks would fail if the tested read/edit authorization boundary were removed.

- **Asked:** Prepare a clean-clone and deployment guide that fits this SQLite-backed service, and describe the project honestly against the challenge hand-in requirements.
- **Produced:** A README covering local setup, environment bootstrap, Docker deployment with a persistent volume, account provisioning, architecture, accepted gaps, and a five-minute demo outline. Commit: [bb492b6](https://github.com/chakrithayanamadala/TrustVault/commit/bb492b6).
- **What was wrong or incomplete:** My first draft of the local run commands did not set bootstrap admin credentials, so a clean development run would have had no admin account to sign in as. I caught this while checking the README against the app's lifespan behavior. A first container smoke attempt using a root-owned tmpfs also failed because the unprivileged app user could not write there.
- **What I did instead:** Added the admin bootstrap commands and verified the documented named-volume setup, health endpoint, HTML response security headers, and admin login in a built container. The tmpfs failure was a test setup mismatch, not a reason to loosen container permissions. The full test suite still passes (12 passed). No free host or hosted URL was provisioned.

- **Asked:** Diagnose and fix the browser's “Cannot read properties of null” error after document upload.
- **Produced:** Captured the upload form element before the first `await`, then reused that reference to build `FormData` and reset the form. Commit: [d8def37](https://github.com/chakrithayanamadala/TrustVault/commit/d8def37).
- **What was wrong or incomplete:** The handler used `event.currentTarget` again after awaiting the upload request. Browsers clear `currentTarget` once synchronous event dispatch ends, so the request could succeed and then the UI would throw while resetting the form. The error was caught in an actual browser upload; the original file had been uploaded successfully.
- **What I did instead:** Kept the form reference before yielding, ran the upload in the browser and confirmed the success notification and no page error, then removed only the temporary regression document. The full existing test suite passes (12 passed); there is no automated JavaScript/browser test harness in this repository.