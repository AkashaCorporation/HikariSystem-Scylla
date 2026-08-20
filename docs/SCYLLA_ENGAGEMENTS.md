# Scylla Engagements

`scylla-engagements` is the authorization-context layer for HikariSystem Scylla. It models the facts that scanners and agents otherwise have to reconstruct from disconnected JSON artifacts: engagement scope, identities, resources, ownership, HTTP transactions, explicit access expectations, and observed access.

The extension is intentionally headless-first. Its current JSON store lives under `.scylla/engagements/`; the command contract is designed so the persistence backend can later move to the updated SQLite engine without changing jobs or agents.

## Evidence model

Scylla separates three concepts:

1. **Observation** — something happened (for example, an HTTP response was received).
2. **Candidate** — evidence is suspicious enough to deserve authorization/business-logic review.
3. **Validated finding** — the expected policy and security impact have been confirmed.

Scanner output should not silently jump from an HTTP status or response-length heuristic to a validated vulnerability.

## Core commands

### `scylla.engagement.createHeadless`

Creates a new engagement and makes it active by default.

```json
{
  "name": "Target authorization review",
  "targets": ["https://api.target.test"],
  "scope": ["api.target.test"],
  "setActive": true
}
```

If `id` is omitted, Scylla generates a unique ID. This is preferred for repeatable jobs.

### `scylla.engagement.addIdentityHeadless`

Associates an engagement identity with an optional `scylla-auth` profile.

```json
{
  "id": "user-a",
  "displayName": "User A",
  "role": "standard-user",
  "authProfile": "user-a"
}
```

### `scylla.engagement.registerResourceHeadless`

Registers a resource and, when known, its owner.

```json
{
  "id": "order-100",
  "type": "order",
  "ownerIdentityId": "user-a",
  "canonicalUrl": "https://api.target.test/api/orders/100",
  "identifiers": ["100"]
}
```

Ownership implies an `allow` expectation for the owner. Non-ownership does **not** imply `deny`; sharing, delegation, team access, or privileged roles may legitimately grant access. Denial policy must be explicit.

### `scylla.engagement.probeHeadless`

Executes a governed HTTP request as an engagement identity and records the response as a transaction.

```json
{
  "identityId": "user-b",
  "resourceId": "order-100",
  "method": "GET",
  "kind": "probe",
  "expectedAccess": "deny"
}
```

The identity's `authProfile` is resolved through `scylla-auth`; its authentication headers take precedence over custom headers so provenance cannot claim one identity while sending another identity's credentials.

`GET`, `HEAD`, and `OPTIONS` are allowed by default. Other methods require `allowStateChange: true`. Scope and rate-limit enforcement still occurs through `scylla-http`.

If an identity references an auth profile but that profile has no valid session, the probe fails rather than silently downgrading to anonymous access.

### `scylla.engagement.recordTransactionHeadless`

Records an already-known transaction, or imports authorization scanner output.

Direct transaction example:

```json
{
  "identityId": "user-a",
  "resourceId": "order-100",
  "kind": "baseline",
  "method": "GET",
  "url": "https://api.target.test/api/orders/100",
  "statusCode": 200,
  "expectedAccess": "allow"
}
```

Scanner import example:

```json
{
  "scannerResultFile": "${outDir}/idor-candidates.json",
  "scannerType": "idor"
}
```

Supported scanner imports currently include `idor` and `privesc`. Import is evidence-versioned: importing the exact same response twice does not duplicate transactions; changed response evidence creates a new transaction.

Imported scanner candidates deliberately use `expectedAccess: "unknown"` for the attacker/low-privilege identity. A scanner can establish suspicious cross-profile equivalence, but it cannot infer the application's authorization policy by itself.

### `scylla.engagement.authorizationMatrixHeadless`

Builds the current identity × resource matrix. Each cell contains:

- expected access (`allow`, `deny`, `unknown`);
- observed access (`allowed`, `denied`, `unknown`);
- latest supporting transaction;
- status code and confidence when available;
- whether observation matches an explicit expectation.

Only explicit mismatches are returned as `mismatches`. Unknown policy is not treated as a vulnerability.

## Scanner-to-engagement flow

A `.scylla_job.json` can now perform:

```text
Auth profiles
    ↓
IDOR / PrivEsc scanner
    ↓
structured candidate JSON
    ↓
recordTransactionHeadless(scannerResultFile=...)
    ↓
Engagement resources + baseline/probe transactions
    ↓
authorizationMatrixHeadless
```

For policy-driven testing, prefer explicit probes:

```text
Engagement
    ↓
Identity A → Resource A → expected allow
Identity B → Resource A → expected deny
    ↓
Scylla Auth
    ↓
Scope Governor
    ↓
Scylla HTTP
    ↓
redacted evidence artifact
    ↓
Transaction
    ↓
Authorization Matrix
```

## Example jobs

- `docs/jobs/authorization-matrix.example.scylla_job.json` — explicit two-user, two-resource access policy.
- `docs/jobs/idor-engagement-import.example.scylla_job.json` — ownership-aware IDOR candidate scan imported into an engagement.
- `docs/jobs/privesc-engagement-import.example.scylla_job.json` — read-only cross-role candidate scan imported into an engagement.

Replace all example targets and credentials before running them. The examples intentionally use placeholder bearer tokens.

## Current limitations

- Persistence is JSON, not the updated SQLite engine yet.
- The Jobs runner has a soft timeout implemented with `Promise.race`; timing out does not currently cancel the underlying command. Do not configure automatic retries for long-running scanner steps until cooperative cancellation/timeout containment is implemented.
- The Jobs runner does not yet support native step-output dataflow. The active-engagement pointer and file-backed scanner import are the current bridge between steps.
- CI/CD and distributable ZIP generation still need to be ported from the current HexCore build/release pipeline.
