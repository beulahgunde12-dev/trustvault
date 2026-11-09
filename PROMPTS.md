# PROMPTS.md

> **Fill this in yourself with real entries.** The brief needs at least 5 dated entries (2+ about
> authorisation / access control / audit): the prompt, what the AI produced, what was specifically wrong,
> and the commit link where you fixed it. I did not invent history for you; made-up entries score nothing
> and are easy to spot. Commit every time you correct the AI and write the entry that day.

## Entry template

### YYYY-MM-DD: short title
- **Asked:** ...
- **Produced:** ...
- **What was wrong:** (specific: file, line, behaviour)
- **What I did instead:** ... ([commit abc1234](https://github.com/you/repo/commit/abc1234))

## Real problems found while building this (use the ones that happened to you, with your dates and commits)

1. **Deleted-document existence leak.** `POST /restore` by a grantee of a deleted document returned 403
   (confirming it exists) instead of 404. `authz.require(..., allow_deleted=True)` computed a level for deleted
   docs without requiring ownership. Fix in `app/authz.py`: on deleted docs anything but owner counts as no access.
2. **Refusal audit rows lost.** Writing the "denied" audit row and then raising `HTTPException` inside a
   transaction that rolls back on exceptions erases the row. Fix: `Refused` exception that commits (`app/db.py`).
3. **Check-then-act.** Checking permission in one DB call and writing in the next lets a concurrent revoke slip
   between. Fix: `BEGIN IMMEDIATE`, check + write + audit in one transaction.
4. **Tests that do not test.** `scripts/mutation_check.py` removes each `require()` in turn; all 10 mutants are killed.
5. **"Tamper-evident" claim.** A plain SHA-256 chain can be recomputed by someone who edits the file. Switched to
   HMAC with a key outside the DB; test `test_recomputing_hashes_without_the_key...`.

## Reusable context (paste at the start of each AI session)

```
You are helping build TrustVault, where security matters more than features.
- Every route that touches a document calls authz.require() first, inside tx().
- Never decide access in the UI or by hiding buttons.
- Audit every refusal before raising; use Refused (commits), never a bare HTTPException.
- No signed URLs, no cached permission decisions. Revoke works on the next request.
- With every test, say which single line removal would make it fail.
- List what you are unsure about; never claim "secure" without naming the attack you considered.
```
