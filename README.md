# HikariSystem Scylla

<p align="center">
  <img alt="HikariSystem Scylla" src="Scylla.png" width="200">
</p>

<p align="center">
  <strong>Headless-first offensive security experimentation IDE for web/API authorization, business logic, evidence collection, and repeatable security workflows.</strong>
</p>

<p align="center">
  <strong>Product target:</strong> Scylla 3.0.0 — <em>"Engagement Foundations"</em><br>
  <strong>Status:</strong> pre-release; Windows ZIP packaging is being validated before the 3.0.0 tag.
</p>

<p align="center">
  <code>authorization testing</code> &middot; <code>bug bounty</code> &middot; <code>engagement modeling</code> &middot; <code>multi-profile auth</code> &middot; <code>evidence provenance</code> &middot; <code>headless jobs</code> &middot; <code>IDOR</code> &middot; <code>privilege boundaries</code>
</p>

---

## Why Scylla 3.0

Scylla started as a Code-OSS-derived offensive security IDE built from the HexCore codebase. The 2.x line established reconnaissance, authentication, HTTP tooling, vulnerability scanners, jobs, findings, and reporting.

**Scylla 3.0 changes the core model.** Instead of treating an HTTP status code, response length, or scanner heuristic as a vulnerability, Scylla now models the engagement itself: identities, resources, ownership, transactions, expected access, observed access, evidence, and provenance.

The goal is to make Scylla a precise experimentation harness for both human researchers and strong agentic models:

```text
Engagement
   ↓
Identity + Resource + Explicit Policy
   ↓
Governed Experiment
   ↓
HTTP / Scanner Evidence
   ↓
Transaction + Provenance
   ↓
Observation
   ↓
Candidate
   ↓
Validated Finding
```

A scanner can discover something suspicious. It should not silently decide the application's authorization policy for you.

---

## Core principles

### Evidence before conclusions

Scylla separates three states:

- **Observation** — something happened and evidence was recorded.
- **Candidate** — the evidence is suspicious enough to deserve authorization/business-logic review.
- **Validated finding** — policy and security impact have actually been confirmed.

### Identity is part of the evidence

Authorization results are meaningless if Scylla cannot prove which session produced them. Findings and transactions therefore preserve attacker, baseline, resource-owner, scanner, command, and strategy provenance where available.

### Unknown policy stays unknown

A resource being owned by User A does not automatically mean User B must be denied. Shared resources, teams, delegation, administrative roles, and support workflows can all be legitimate. Scylla only marks an authorization mismatch when an explicit expectation exists.

### Safe experiments by default

Engagement probes allow `GET`, `HEAD`, and `OPTIONS` by default. State-changing methods require explicit `allowStateChange: true`. Egress can also be constrained by the shared Scope + Rate-Limit Governor.

---

## Scylla Engagements

`scylla-engagements` is the authorization-context layer introduced for 3.0. It stores engagement state under `.scylla/engagements/` using a JSON backend behind a command/store abstraction that can later move to the updated SQLite engine.

An engagement can model:

- target and scope;
- identities and their `scylla-auth` profiles;
- resources and known ownership;
- canonical URLs and identifiers;
- baseline, probe, replay, and observation transactions;
- expected access (`allow`, `deny`, `unknown`);
- observed access (`allowed`, `denied`, `unknown`);
- response artifact paths, status, body hash, and length;
- confidence, mutation context, parent/baseline links, notes, and tags.

### Headless engagement commands

```text
scylla.engagement.createHeadless
scylla.engagement.getHeadless
scylla.engagement.listHeadless
scylla.engagement.setActiveHeadless
scylla.engagement.addIdentityHeadless
scylla.engagement.registerResourceHeadless
scylla.engagement.recordTransactionHeadless
scylla.engagement.probeHeadless
scylla.engagement.authorizationMatrixHeadless
```

### Governed probe example

```json
{
  "identityId": "user-b",
  "resourceId": "order-100",
  "method": "GET",
  "kind": "probe",
  "expectedAccess": "deny"
}
```

The probe resolves the identity's auth profile, sends through `scylla-http`, records the response as evidence, and adds a transaction to the active engagement. If an identity references an invalid session, the probe fails rather than quietly becoming anonymous.

See [`docs/SCYLLA_ENGAGEMENTS.md`](docs/SCYLLA_ENGAGEMENTS.md) for the full model and command examples.

---

## Authorization Matrix

Scylla can construct an identity × resource matrix from explicit policy and observed transactions:

```text
                 Resource A        Resource B
User A           allow / allowed   deny / denied
User B           deny  / allowed   allow / allowed
                       ^ mismatch
```

A mismatch is meaningful only when the expected policy is known. Cells with `expectedAccess: "unknown"` remain evidence for review and are not promoted into vulnerabilities simply because a request returned `200`.

Example job: [`docs/jobs/authorization-matrix.example.scylla_job.json`](docs/jobs/authorization-matrix.example.scylla_job.json).

---

## Authentication & HTTP evidence

### `scylla-auth`

Scylla supports multiple authenticated profiles for the same engagement, including form/API/OAuth/bearer/basic/anonymous-style contexts depending on the configured profile.

The current authentication path provides:

- profile and session management;
- cookie jars;
- domain-scoped credential resolution;
- auth-aware headless requests;
- governed login egress;
- reusable identities for scanners and engagement probes.

### `scylla-http`

The HTTP layer is the egress chokepoint for governed experiments. It supports request execution, file-backed artifacts, replay-oriented workflows, response persistence, custom host resolution, and scope-aware redirects.

Persisted evidence redacts common credentials from headers and request-body fields, including authorization headers, cookies, API keys, tokens, passwords, and client secrets. Response bodies are preserved because they may be the evidence being investigated.

---

## Scope + Rate-Limit Governor

Scylla interacts with live targets, so the 3.0 line includes a shared governor used across HTTP, authentication, redirects, and raw TCP scanning.

It can enforce:

- exact and wildcard in-scope host patterns;
- per-host token-bucket rate limits;
- global concurrency limits;
- consent-gated automatic job execution;
- engagement-scoped target publication.

Dropping a `.scylla_job.json` into a workspace is not treated as implicit consent to immediately attack its target.

---

## Authorization-focused scanners

### IDOR

The IDOR path is now ownership-aware and evidence-driven. It can use known resource identifiers associated with profiles, collect a victim/owner baseline, replay the same tested resource as another identity, and compare the resulting evidence.

A suspicious comparison becomes a **candidate**, not a validated finding. Known ownership strengthens provenance; it does not automatically prove denial policy.

Example import job: [`docs/jobs/idor-engagement-import.example.scylla_job.json`](docs/jobs/idor-engagement-import.example.scylla_job.json).

### Privilege escalation

The current PrivEsc path performs read-only cross-role comparisons by default. A high-privilege baseline and low-privilege replay can establish suspicious response equivalence, but endpoint names or a `2xx` response alone are not treated as proof of broken access control.

Example import job: [`docs/jobs/privesc-engagement-import.example.scylla_job.json`](docs/jobs/privesc-engagement-import.example.scylla_job.json).

### Other scanner families

Scylla also retains broader web/API testing capabilities including SQL injection, XSS, LFI, SSTI, CORS, SSRF, JWT, GraphQL, Mass Assignment, and related discovery/validation utilities. These families are progressively being moved toward the same evidence/provenance standard used by the authorization work.

---

## Reconnaissance

`scylla-recon` provides native reconnaissance workflows such as:

- TCP port scanning and banner collection;
- web crawling;
- directory/file discovery;
- technology detection;
- WAF fingerprinting.

Raw TCP scanning participates in the same engagement scope/rate/concurrency controls when the governor is configured.

---

## Findings, reporting, and export

### `scylla-findings`

Findings now support structured lifecycle and provenance fields rather than relying on status-code-derived severity.

Important concepts include:

- classification: `observation`, `candidate`, `validated`;
- confidence;
- source scanner/command/strategy;
- attacker/baseline/resource-owner actors;
- evidence links and tags.

### Reporting/export

Scylla retains reporting and export workflows for Markdown-oriented pentest reports and machine-readable formats such as JSON, CSV, and SARIF where supported by the corresponding extensions.

---

## Headless Jobs

`.scylla_job.json` remains the main orchestration format for repeatable workflows. Engagement commands are registered as first-class job capabilities, allowing a job to create an engagement, add identities/resources, execute governed probes, import scanner evidence, and build an authorization matrix.

Typical authorization workflow:

```text
Create engagement
    ↓
Add identities + auth profiles
    ↓
Register owned resources
    ↓
Run explicit baseline/probe experiments
    ↓
Import scanner evidence when useful
    ↓
Build authorization matrix
    ↓
Review mismatches/candidates
    ↓
Promote only validated findings
```

Shipped examples:

- [`authorization-matrix.example.scylla_job.json`](docs/jobs/authorization-matrix.example.scylla_job.json)
- [`idor-engagement-import.example.scylla_job.json`](docs/jobs/idor-engagement-import.example.scylla_job.json)
- [`privesc-engagement-import.example.scylla_job.json`](docs/jobs/privesc-engagement-import.example.scylla_job.json)

---

## Agent-oriented workflows

Scylla is intentionally headless-first so an agent can operate on typed commands and persisted evidence rather than screen-scraping the IDE.

Repository guidance for agents lives in:

- [`AGENTS.md`](AGENTS.md)
- [`.agent/skills/scylla/SKILL.md`](.agent/skills/scylla/SKILL.md)

The intended division of responsibility is simple:

```text
Scylla
  = controlled experiment execution
  + scope/auth enforcement
  + evidence persistence
  + reproducible state

Agent / Researcher
  = hypothesis formation
  + policy interpretation
  + impact reasoning
  + finding validation
```

---

## Extension layout

Scylla is modular. Product versioning and extension package versioning are intentionally separate.

| Extension | Role |
|---|---|
| `scylla-engagements` | Engagements, identities, resources, transactions, probes, authorization matrix, scanner import |
| `scylla-auth` | Authentication profiles, sessions, cookie jars, credential resolution |
| `scylla-http` | HTTP execution, replay, artifacts, evidence persistence, governed egress |
| `scylla-scanner` | Authorization and web/API scanner families |
| `scylla-recon` | Crawl, port scan, directory discovery, fingerprinting |
| `scylla-findings` | Finding lifecycle, provenance, evidence catalog |
| `scylla-jobs` | Headless `.scylla_job.json` orchestration |
| `scylla-reporting` | Report generation |
| `scylla-export` | Machine-readable finding export |
| `scylla-wordlists` | Wordlist discovery and management |
| `scylla-theme` | Scylla UI/theme assets |

A small set of HexCore utility modules remains for shared capabilities such as hashing, strings, Base64, YARA, IOC extraction, file-type detection, common helpers, and eventual SQLite-backed persistence.

---

## Versioning

**Scylla product version:** `3.0.0` target, tracked in `product.json` as `scyllaVersion`.

Do not infer the Scylla product version from:

- the root Code-OSS-derived `package.json` version;
- an individual extension package version such as `scylla-scanner@2.1.0`;
- the VS Code/Code-OSS base version.

The `3.0.0` release tag should represent the first validated standalone Scylla distribution from the Windows ZIP pipeline, not merely a source-tree milestone.

---

## Building from source

### Prerequisites

| Requirement | Recommended baseline |
|---|---|
| Node.js | 22.21.1 |
| npm | 10.x |
| Python | 3.11 |
| Windows build tooling | Visual Studio Build Tools with Desktop development with C++ when native components are required |

### Development bootstrap

```powershell
git clone https://github.com/AkashaCorporation/HikariSystem-Scylla.git
cd HikariSystem-Scylla
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
npm ci
npm run compile
```

Launch the development shell on Windows with:

```powershell
.\scripts\code.bat
```

### Windows distributable

The GitHub Actions Windows build is the intended standalone distribution path. A successful packaging run verifies the built Scylla tree, creates `Scylla-win32-x64.zip`, and uploads the artifact. Until that path completes green end-to-end, 3.0.0 remains a target/pre-release rather than a tagged stable release.

---

## Current 3.0 limitations

- Engagement persistence is JSON today; the store boundary is designed for a later SQLite backend.
- Job timeout handling still uses a soft `Promise.race` timeout and does not cooperatively cancel an underlying long-running command.
- Jobs do not yet expose native typed step-output dataflow; active-engagement state and file-backed evidence imports bridge steps for now.
- Broad scanner families do not all have the same provenance rigor as the new authorization paths yet.

---

## Responsible use

Scylla is an offensive security research tool. Use it only against systems you own or have explicit authorization to test. Scope controls are designed to reduce accidental boundary violations; they are not a substitute for understanding the rules of an engagement.

---

## Contributing

Scylla is open source under the GNU General Public License v3.0. Contributions are welcome. For large architectural changes, opening an issue or draft pull request first is encouraged so scanner semantics, evidence contracts, and headless compatibility can be reviewed together.

---

## License

This project is licensed under the **GNU General Public License v3.0**. See [`LICENSE`](LICENSE) for details.

---

<p align="center">
  <strong>HikariSystem Scylla 3.0</strong><br>
  Evidence-driven offensive security experimentation.
</p>
