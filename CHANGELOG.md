# Changelog

All notable changes to HikariSystem Scylla are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the Scylla product line.

> **Versioning note:** the root Code-OSS package version and individual extension package versions are implementation details and do not define the Scylla product version. Scylla 3.0.0 is tracked explicitly in `product.json`.

## [Unreleased] - Target 3.0.0 - "Engagement Foundations"

> **Scylla 3.0.0 is the first release line intended to ship as a usable standalone Windows ZIP.** The 3.0 architecture moves Scylla away from treating scanner heuristics as findings and toward a headless-first experimentation model: engagements, identities, resources, transactions, explicit authorization expectations, evidence provenance, and controlled probes.

### Added

- **Scylla Engagements (`scylla-engagements`)**: a new authorization-context layer that stores engagement scope, identities, resources, ownership, transactions, expected access, observed access, and evidence under `.scylla/engagements/`.
- **Governed identity probes** via `scylla.engagement.probeHeadless`: resolves the identity's `scylla-auth` profile, executes through `scylla-http`, records evidence, and refuses unsafe state-changing methods unless `allowStateChange: true` is explicitly supplied.
- **Authorization Matrix** via `scylla.engagement.authorizationMatrixHeadless`: builds identity × resource access matrices and reports only explicit expectation mismatches. Unknown policy remains unknown rather than being promoted to a vulnerability.
- **Scanner evidence import** for IDOR and PrivEsc results through `scylla.engagement.recordTransactionHeadless`, including evidence deduplication and provenance preservation.
- **Structured finding lifecycle**: `observation`, `candidate`, and `validated`, plus confidence, source, and actor provenance in `scylla-findings`.
- **Ownership-aware IDOR testing** with deterministic `knownIds`, attacker/victim profiles, victim baselines, resource-owner provenance, and conservative candidate classification.
- **Cross-role PrivEsc baselines** that are read-only by default and preserve high-privilege/low-privilege actor provenance.
- **Agent-facing Scylla skill and repository guidance** for headless workflows, evidence handling, authorization testing, and safe job construction.
- **Engagement job examples** for explicit authorization matrices, IDOR evidence import, and PrivEsc evidence import under `docs/jobs/`.
- **Shared Scylla preflight** (`scripts/verify-scylla-preflight.cjs`) validating engagement command registration and shipped job examples before packaging.
- **Windows build/distribution workflow** aligned with the mature HexCore Code-OSS packaging path, with extension compilation, package verification, ZIP creation, and artifact upload stages.
- **Scope + Rate-Limit Governor** (`scylla.governor.*` settings): in-scope host allowlists, per-host token-bucket rate limiting, global concurrency limits, and consent-gated automatic job execution.
- **Engagement-scope commands**: `scylla.http.{set,clear,get}ScopeHeadless` and `scylla.auth.{set,clear,get}ScopeHeadless`.
- **`.scylla_job.json` `scope` field** for engagement-specific scope beyond the root target.

### Changed

- **IDOR and PrivEsc results are candidates, not automatic validated findings.** HTTP status, body length, endpoint names, or response similarity can produce evidence, but they no longer silently prove authorization policy.
- **Non-owner access expectation defaults to `unknown`.** Ownership implies the owner should be allowed; non-ownership alone does not prove that another identity should be denied because shared resources, delegated access, teams, and administrative roles can be legitimate.
- **Findings created from raw HTTP traffic default to informational observations** instead of deriving severity from status codes.
- **Persisted HTTP evidence redacts credentials** from sensitive request/response headers and common secret-bearing request-body fields while preserving response bodies as evidence.
- **Auth cookies are domain-scoped** and authentication egress is governed, preventing cross-host session leakage and reducing contaminated IDOR/PrivEsc comparisons.
- **Job command capabilities now include all engagement headless commands**, allowing engagements and probes to participate in `.scylla_job.json` pipelines.
- **Job auto-run is consent-gated by default.** Merely opening or editing a job file no longer silently launches scanners against a live target.
- **`scylla-http` egress, redirects, auth login traffic, and the raw TCP port scanner use the shared governor** for scope/rate/concurrency enforcement.
- **Legacy IOC SQLite storage is optional in the current build path**; automatic mode can use the memory fallback until the newer native engine is synchronized from HexCore.
- **Windows Code-OSS packaging no longer forces the upstream APPX `stable` product path.** Scylla does not yet ship the Explorer context-menu DLL/CLSID metadata required by that upstream APPX branch, so the product metadata now follows the working HexCore packaging model.

### Security

- Out-of-scope HTTP/redirect/login/TCP traffic is blocked by the shared governor when engagement scope is configured.
- Persisted evidence no longer writes common authorization headers, cookies, API keys, and token fields in plaintext by default.
- State-changing engagement probes require explicit opt-in.
- Missing/invalid configured auth sessions fail a governed probe instead of silently downgrading the request to anonymous identity.
- Scanner findings preserve actor and source provenance so a report cannot legitimately claim one identity while evidence was produced by another.

### Known limitations before the 3.0.0 tag

- Engagement persistence is JSON; migration to the updated HexCore SQLite engine is intentionally deferred behind the stable command/store abstraction.
- Job timeouts currently use `Promise.race`; expiration does not cooperatively cancel the underlying command yet.
- Jobs do not yet provide native typed step-output dataflow; active-engagement state and file-backed scanner imports are the current bridge between steps.
- The Windows ZIP workflow is the intended 3.0 distribution path and is still being validated end-to-end before the `3.0.0` release tag is cut.

## [2.1.0] - 2026-05-27 - "Hybrid XSS Engine: Dalfox + XSStrike"

> **Major Release: Hybrid XSS Engine** — A complete overhaul of the XSS scanning capabilities. The `scylla.scanner.xssHeadless` command is powered by a two-phase hybrid engine combining Dalfox-style speed/validation with XSStrike-style dynamic payload fuzzing and WAF evasion natively in TypeScript.

### Added

- **Phase 1: Dalfox Heuristics (`xssHeuristics.ts`)**: context detection across HTML, attributes, scripts, and DOM events with structural verification before flagging.
- **Phase 2: XSStrike WAF Fuzzer (`wafFuzzer.ts`)**: targeted boundary canaries and fuzzy matching to score characters allowed, encoded, or removed by a WAF.
- **XSStrike JS Contexter (`jsContexter.ts`)**: balances discovered JavaScript syntax contexts when constructing candidate payloads.
- **XSStrike Dynamic Generator (`dynamicGenerator.ts`)**: constructs mutated payload candidates from the characters observed as viable by the WAF analysis.
- **Exponential Back-off Rate Limiter (`rateLimiter.ts`)**: adaptive handling for HTTP 403 and 429 responses.
- **Configuration Support**: `rateLimitRetryBaseMs` and `maxRetries` arguments for `scylla.scanner.xssHeadless` jobs.

## [2.0.1] - 2026-05-27 - "Windows Build & Bootstrap Hotfix"

> **Hotfix Release: Build & Bootstrap Stability** — Build/bootstrap changes intended to make clean Windows development installs less fragile.

### Fixed

- **Phantom N-API Dependencies in `dirs.ts` & `gulpfile.extensions.ts`**: removed obsolete HexCore extension references and added Scylla extensions to bootstrap/compile paths.
- **Windows npm Command Spawning (`postinstall.ts`)**: improved quoted argument parsing and sanitized `npm_command` handling.
- **Node-GYP Compilation Timeout (`preinstall.ts`)**: increased the preinstall node-gyp timeout to five minutes for slower MSVC runs.
- **Fallback for Native SQLite Binaries (`hexcore-native-install.js`)**: allowed an existing precompiled `better-sqlite3` binary to satisfy installation without forcing a local rebuild.

## [2.0.0] - 2026-04-10 - "Hydra Phase 1"

> **Major Release: Scylla Core Transition** — The project pivoted from the HexCore reverse-engineering codebase toward an offensive-security, business-logic-focused web/API testing IDE.

### Added

- **Scylla Authentication Engine (`scylla-auth`)**: headless-first multi-profile authentication and cookie/session management.
- **Auth-Aware Pipeline Runner**: `.scylla_job.json` support for declaring and preparing authenticated profiles.
- **IDOR Scanner (`scylla.scanner.idorHeadless`)**: horizontal-access-control candidate discovery across multiple mutation strategies.
- **Privilege Escalation Scanner (`scylla.scanner.privescHeadless`)**: cross-role endpoint comparisons.
- **Mass Assignment Scanner (`scylla.scanner.massAssignHeadless`)**: unexpected-property testing for attribute-binding weaknesses.

### Changed

- Core scanning architecture shifted toward headless execution, multi-role contexts, and HTTP replay.
- README and product direction were rewritten around Scylla's web/API testing mission.

### Removed

**13 HexCore reverse-engineering extensions (~2.1 GB)** that belonged to the binary-analysis IDE rather than Scylla's web/API mission:

- `hexcore-debugger`
- `hexcore-disassembler`
- `hexcore-capstone`
- `hexcore-unicorn`
- `hexcore-llvm-mc`
- `hexcore-remill`
- `hexcore-rellic`
- `hexcore-peanalyzer`
- `hexcore-elfanalyzer`
- `hexcore-minidump`
- `hexcore-hexviewer`
- `hexcore-entropy`
- `hexcore-report-composer`

Reusable HexCore utility extensions were retained for shared pipeline capabilities such as hashing, strings, Base64, YARA, IOC extraction, file-type detection, common helpers, and SQLite integration.
