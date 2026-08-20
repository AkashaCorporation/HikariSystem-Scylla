---
name: Scylla Authorization Hunting
description: Headless-first workflow for authorized web/API pentesting, identity-aware authorization testing, engagement transactions, and evidence-driven Scylla jobs
---

# Scylla Authorization Hunting Skill

## Mission

Scylla is an offensive-security IDE for **authorized** web/API testing. Treat Scylla as a precise experiment and evidence system, not as an oracle that turns HTTP heuristics into vulnerabilities.

The preferred workflow is:

```text
hypothesis
  → engagement policy/context
  → identity + resource
  → governed probe or scanner candidate
  → transaction/evidence
  → authorization matrix
  → analyst/agent interpretation
  → validated finding only after proof
```

Do not equate HTTP status, response length, endpoint naming, or scanner confidence with demonstrated impact.

---

## Evidence states

Use these states consistently:

- **observation** — a request/response or other fact was captured.
- **candidate** — evidence suggests a security property may be violated and deserves validation.
- **validated** — the expected security policy and practical unauthorized behavior were established with reproducible evidence.

IDOR and privilege-escalation scanners produce **candidates**. They do not establish application policy by themselves.

---

## Core engagement model

### Engagement

An engagement binds authorized targets/scope to identities, resources, transactions, and access expectations.

Create one at the start of a workflow:

```json
{
  "cmd": "scylla.engagement.createHeadless",
  "args": {
    "name": "Target authorization review",
    "targets": ["${target}"],
    "scope": ["api.target.test"],
    "setActive": true
  }
}
```

Prefer generated engagement IDs in reusable jobs. The active engagement bridges pipeline steps until Scylla Jobs gains native step-output dataflow.

### Identity

Bind an engagement identity to a `scylla-auth` profile:

```json
{
  "cmd": "scylla.engagement.addIdentityHeadless",
  "args": {
    "id": "user-a",
    "role": "standard-user",
    "authProfile": "user-a"
  }
}
```

If an identity declares an auth profile but that profile has no valid session, `probeHeadless` must fail. Never reinterpret that failure as an anonymous test.

### Resource

Represent the object or privileged operation being tested:

```json
{
  "cmd": "scylla.engagement.registerResourceHeadless",
  "args": {
    "id": "order-100",
    "type": "order",
    "ownerIdentityId": "user-a",
    "canonicalUrl": "${target}/api/orders/100",
    "identifiers": ["100"]
  }
}
```

Known ownership supports an implicit `allow` expectation for the owner. **Non-ownership does not imply deny.** Sharing, delegated access, organization membership, or administrative roles may legitimately grant access.

State `expectedAccess: "deny"` only when the engagement/application policy supports that expectation.

---

## Preferred deterministic probe

Use `scylla.engagement.probeHeadless` when you already know the security property to test.

Owner baseline:

```json
{
  "cmd": "scylla.engagement.probeHeadless",
  "args": {
    "identityId": "user-a",
    "resourceId": "order-100",
    "method": "GET",
    "kind": "baseline",
    "expectedAccess": "allow"
  }
}
```

Cross-user policy test:

```json
{
  "cmd": "scylla.engagement.probeHeadless",
  "args": {
    "identityId": "user-b",
    "resourceId": "order-100",
    "method": "GET",
    "kind": "probe",
    "expectedAccess": "deny"
  }
}
```

When a resource has `canonicalUrl`, that URL is authoritative. This prevents the generic Scylla Jobs target injection from replacing a resource-specific endpoint with the target root.

Identity-derived authentication headers override custom probe headers. Do not attempt to represent one identity while manually supplying another identity's Cookie/Authorization header.

### State-changing operations

`GET`, `HEAD`, and `OPTIONS` are the safe default methods.

Other methods require:

```json
{ "allowStateChange": true }
```

Use this only when the authorized engagement permits the specific operation and state change is necessary for the hypothesis. Prefer reversible or disposable test objects and capture the pre/post state needed to demonstrate impact.

---

## Authorization matrix

After collecting transactions:

```json
{
  "cmd": "scylla.engagement.authorizationMatrixHeadless"
}
```

Interpret cells as:

```text
expected=allow + observed=allowed → consistent
expected=deny  + observed=denied  → consistent
expected=deny  + observed=allowed → explicit policy mismatch; validate impact
expected=unknown                  → evidence only, not a vulnerability verdict
observed=unknown                  → insufficient evidence
```

A mismatch is a **validation target**, not automatically a report-ready vulnerability. Confirm that the response represents the protected resource/operation and is not a generic success envelope, cache artifact, public object, role-specific projection, or harmless error returned with 2xx.

---

## IDOR candidate workflow

Use `scylla.scanner.idorHeadless` for discovery when object ownership is not yet fully modeled.

Prefer `knownIds` whenever possible:

```json
{
  "cmd": "scylla.scanner.idorHeadless",
  "args": {
    "url": "${target}/api/orders/100",
    "profiles": ["user-a", "user-b"],
    "strategies": ["known-id-swap"],
    "knownIds": {
      "user-a": ["100"],
      "user-b": ["200"]
    }
  }
}
```

The scanner compares:

```text
attacker original baseline
victim baseline on exact tested resource
attacker on the exact same tested resource
```

A candidate requires strong response equivalence to the victim baseline. Heuristic ID mutations may still discover interesting objects, but heuristic ownership remains unknown.

Import scanner evidence into the active engagement:

```json
{
  "cmd": "scylla.engagement.recordTransactionHeadless",
  "args": {
    "scannerResultFile": "${outDir}/idor-candidates.json",
    "scannerType": "idor"
  }
}
```

Imported attacker transactions intentionally use `expectedAccess: "unknown"`. Declare a deny policy separately before treating access as a security violation.

---

## Privilege-escalation candidate workflow

`scylla.scanner.privescHeadless` is **read-only** in its P0 contract. It uses endpoint-name patterns only to prioritize targets, then requires a high-privilege baseline and compares the same endpoint with the low-privilege identity.

```json
{
  "cmd": "scylla.scanner.privescHeadless",
  "args": {
    "url": "${target}",
    "highPrivProfile": "admin",
    "lowPrivProfile": "user"
  }
}
```

The scanner does not automatically POST, PUT, PATCH, or DELETE to admin-like endpoints.

Import candidates with:

```json
{
  "cmd": "scylla.engagement.recordTransactionHeadless",
  "args": {
    "scannerResultFile": "${outDir}/privesc-candidates.json",
    "scannerType": "privesc"
  }
}
```

Again, the low-privilege expectation remains `unknown` until policy is established.

---

## Findings

Use `scylla.findings.createHeadless` only after deciding what the evidence state actually is.

For scanner output or an unexplained differential, prefer:

```json
{
  "classification": "candidate"
}
```

Use:

```json
{
  "classification": "validated"
}
```

only after reproducible authorization/impact proof.

HTTP status alone never determines vulnerability severity. A standalone HTTP artifact is an observation.

Persisted normal HTTP evidence is redacted for common authentication headers/tokens. Explicit saved replay request definitions may intentionally retain credentials and must be treated as sensitive local artifacts; do not commit live credentials.

---

## Scylla Jobs rules

Headless commands relevant to authorization work:

- `scylla.auth.loginHeadless`
- `scylla.auth.sessionCheckHeadless`
- `scylla.auth.sessionRefreshHeadless`
- `scylla.http.sendHeadless`
- `scylla.engagement.createHeadless`
- `scylla.engagement.getHeadless`
- `scylla.engagement.listHeadless`
- `scylla.engagement.setActiveHeadless`
- `scylla.engagement.addIdentityHeadless`
- `scylla.engagement.registerResourceHeadless`
- `scylla.engagement.recordTransactionHeadless`
- `scylla.engagement.probeHeadless`
- `scylla.engagement.authorizationMatrixHeadless`
- `scylla.scanner.idorHeadless`
- `scylla.scanner.privescHeadless`
- `scylla.findings.createHeadless`
- `scylla.reporting.generateHeadless`

The Scope + Rate-Limit Governor remains authoritative for egress. Do not bypass the governed HTTP/auth paths to make a test easier.

### Timeout limitation

The current Jobs runner uses a soft `Promise.race` timeout. The underlying command is not yet cooperatively cancelled when the timeout wins.

Until timeout containment/cancellation is implemented:

- do **not** configure retries for long-running scanner steps;
- do not assume `timeout` means network activity stopped;
- prefer bounded scanner inputs and conservative request limits;
- do not start a replacement operation that could conflict with the timed-out operation.

---

## Example jobs

Use these as templates, replacing placeholder targets and credentials:

- `docs/jobs/authorization-matrix.example.scylla_job.json`
- `docs/jobs/idor-engagement-import.example.scylla_job.json`
- `docs/jobs/privesc-engagement-import.example.scylla_job.json`

Never commit real session cookies, bearer tokens, passwords, API keys, or client secrets into example/job files.

---

## Agent decision rule

Before claiming an authorization vulnerability, be able to answer all of these:

1. **Actor:** which identity actually sent the request?
2. **Resource/operation:** what protected object or action was reached?
3. **Policy:** why should this actor be denied?
4. **Baseline:** what does the legitimate owner/privileged identity receive or accomplish?
5. **Cross-context proof:** did the unauthorized identity receive equivalent protected data or perform the protected action?
6. **Impact:** what confidentiality, integrity, or privilege boundary changed?
7. **Reproducibility:** can the behavior be repeated without relying on stale state or accidental side effects?

If policy or resource semantics are unknown, keep the result as a **candidate** and gather more evidence.
