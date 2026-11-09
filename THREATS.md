# THREATS

Format: threat, what I did, test, status. "Accepted" = I know it and chose to leave it.

## Access to documents
1. **IDOR (using another document's id).** Every document route calls `authz.require()` inside the transaction; ids are random uuid4 hex. Tests: `test_stranger_gets_404_on_every_document_route` (3 users x 11 routes); `scripts/mutation_check.py` removes each check. Closed.
2. **A route I forgot (versions, history, grants, restore, trash).** One function on all 10 document routes; the mutation script proves each is tested. Search is filtered in SQL by ownership/grant. `test_search_never_leaks...`, `test_trash_listing_is_owner_only`. Closed.
3. **Existence oracle (404 vs 403).** No access returns 404; deleted docs also 404 for non-owners. My own test found a leak here (restore of a deleted doc returned 403 to a grantee); fixed in `authz.require`. Closed.
4. **Version parameter crossing documents.** Version is looked up with the document id of the authorised row. `test_version_download_is_scoped...`. Closed.
5. **Admin as a backdoor.** No implicit access, cannot be granted access, cannot upload. `test_admin_cannot_read_document_content`. Closed.
6. **Privilege escalation through grants.** Only owners grant; edit only to owner-role users; not to self/admins; level validated. `test_grant_rules`. Closed.
7. **Mass assignment (`owner_id`, `role` in bodies).** Pydantic `extra="forbid"`. `test_mass_assignment_is_rejected`. Closed.
8. **Check-then-act race (revoke during an action).** Check and write share one `BEGIN IMMEDIATE` transaction. Closed for writes.
9. **Old versions visible to later grantees.** Accepted: a grant covers all versions (simpler model).

## Revocation
10. **Token/link still works after revoke.** No signed URLs or caches; grants read live. `test_revoke_takes_effect_on_the_next_request...`, downgrade test. Closed.
11. **Download already streaming at revoke time.** Accepted: at most 10 MB, read in one go; cannot be recalled.
12. **Leaver keeps a session.** Deactivation and password reset revoke all sessions; `active=1` checked on every request. Tests included. Closed.

## Authentication and sessions
13. **Brute force.** 5 failures lock for 5 min, audited, alert after 3 failures/hour. Closed. Lockout as DoS against a known user: accepted.
14. **User enumeration.** Same status/message; dummy scrypt for unknown users. Test included. Closed (timing approximate).
15. **Token theft from the DB.** Only SHA-256 of tokens stored. `test_raw_tokens_are_not_stored`. Closed.
16. **Token theft via XSS.** Token lives in `sessionStorage`. Mitigations: strict CSP (no inline script), all rendering via `textContent`, uploads never served inline. Residual risk accepted: an XSS bug would expose the token. Cookies would trade it for CSRF handling.
17. **CSRF.** Bearer header, no cookies, no CORS. Closed by design.
18. **No MFA; password rule is only length >= 10.** Accepted.

## Audit trail
19. **Quiet alteration.** Triggers block UPDATE/DELETE; HMAC chain with a key outside the DB; verify endpoint. Tests drop the triggers and show edits, middle deletions and naive re-hashing are detected. Closed for edits.
20. **Tail truncation / rollback by someone with the DB file and the key.** Accepted: needs an external anchor. The verify endpoint returns the head hash to store off-box; automatic anchoring not built.
21. **Refused attempts missing.** Refusals are audited and committed (`Refused` commits its transaction). Closed. Unauthenticated requests are not audited (no actor): accepted.
22. **Audit says "success" for something that rolled back.** Audit row is in the same transaction as the action. `test_rolled_back_actions...`. Closed.
23. **Log injection/oversize.** Canonical JSON, truncated; UI uses `textContent`. Closed.

## Upload and storage
24. **Path traversal / hostile names.** Name sanitised; storage key is server-generated random hex, regex-checked. Test included. Closed.
25. **Disguised files, HTML/SVG/exe.** Extension allow-list + magic bytes + UTF-8 check; declared Content-Type ignored. Closed.
26. **Stored XSS via download.** Always `application/octet-stream`, `attachment`, `nosniff`, no-store. Closed.
27. **Zip bombs / huge files.** Office files: entry count and unpacked size limits; 10 MB cap. Large request bodies are buffered up to the cap by the app; a front proxy should also limit body size. Partly accepted.
28. **On-disk tampering.** SHA-256 verified on every download (500 + audit on mismatch). Detects, does not prevent. Closed.
29. **Files unencrypted at rest.** Accepted: host access reads files. Next step: per-file keys from a KMS.
30. **No malware scanning.** Accepted.

## Injection and platform
31. **SQL injection.** Parameterised queries; the one dynamic column name comes from a fixed tuple; LIKE input escaped. Closed.
32. **Error leakage.** Global handler returns "Internal error"; Swagger UI disabled. Closed.
33. **Headers.** CSP, nosniff, frame-deny, no-referrer, no-store on the API. Closed.
34. **Spoofed `X-Forwarded-For` in audit IPs.** Trusted only when `TV_TRUST_PROXY=1`. Accepted if a proxy is misconfigured.
35. **Default secrets.** Prod refuses to start with the dev audit key; operators must change the demo password.
36. **Request floods.** Accepted: no global rate limiting; use a proxy/WAF.
37. **Single node, SQLite.** Accepted.
38. **Owners can list users** (directory), needed to share by name. Accepted.
39. **Not built:** external sharing, AI suggestions, retention.
