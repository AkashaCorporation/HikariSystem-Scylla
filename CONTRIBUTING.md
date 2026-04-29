# Changelog

All notable changes to Scylla are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [2.0.0] — 2026-04-10 — "Hydra Phase 1"

> **Major release.** Scylla pivots from reverse engineering (HexCore) to authenticated web and API penetration testing. Static unauthenticated scanning is replaced by dynamic multi-profile session management and three new access control scanners.

### Added

#### Authentication Engine (`scylla-auth`)

A new headless-first extension for managing login sessions across multiple user roles.

- **Cookie Jars** — persistent session storage per profile, isolated across roles
- **Multi-profile login** — declare N profiles in the job `auth` object; the runner authenticates all of them before any scanner step runs (`loginAll`)
- **CSRF token extraction** — automatically parses tokens from `meta[name="csrf-token"]`, `input#csrf-token`, and similar patterns; injects them into subsequent `POST` requests
- **Session refresh** — detects `401`/`403` responses during scanning and re-authenticates transparently (`sessionRefresh`)

#### Auth-Aware Pipeline Runner

`pipelineRunner.ts` now accepts an `auth` directive in `.scylla_job.json`. All scanner commands receive the active session cookie for the configured profile automatically.

#### IDOR Scanner (`scylla.scanner.idorHeadless`)

Horizontal privilege escalation scanner. Given an attacker profile and a victim profile, it:

- Substitutes victim resource IDs into attacker requests (sequential and UUID-based)
- Tests parameter pollution, JSON array injection, and HTTP method overrides
- Downgrades UUID identifiers to integer sequences where applicable
- Flags responses that differ in body content or status from the expected denial

#### Privilege Escalation Scanner (`scylla.scanner.privescHeadless`)

Replays endpoints that were discovered under a privileged profile using a standard-user session cookie. Compares response body size, status code, and field count against the privileged baseline and flags divergences.

#### Mass Assignment Scanner (`scylla.scanner.massAssignHeadless`)

Injects unexpected keys into `POST`/`PUT`/`PATCH` request bodies:

- **Role escalation payloads** — `role=admin`, `isAdmin=true`, `userType=staff`
- **Financial payloads** — `price=0`, `discount=100`, `amount=-1`
- **Verification bypasses** — `verified=true`, `emailConfirmed=true`, `active=true`

Flags endpoints where the injected key appears to affect the response or subsequent state.

---

### Changed

- Core scanning architecture redesigned around headless execution, multi-role session contexts, and HTTP request replay without a browser.
- `README.md` rewritten to reflect the 2.0 direction as an open-source access control and business logic testing IDE.

---

### Removed

#### HexCore reverse-engineering extensions (~2.1 GB total)

These modules belong to the HexCore binary analysis IDE and have no role in Scylla's web/API mission.

| Extension | Description |
|---|---|
| `hexcore-debugger` | Unicorn CPU emulator (PE/ELF binary emulation) |
| `hexcore-disassembler` | Capstone/LLVM MC disassembler with CFG view |
| `hexcore-capstone` | Native N-API Capstone disassembly engine |
| `hexcore-unicorn` | Native N-API Unicorn emulation engine |
| `hexcore-llvm-mc` | Native N-API LLVM MC assembler engine |
| `hexcore-remill` | Machine code → LLVM IR lifter (Trail of Bits) |
| `hexcore-rellic` | Decompiler scaffold (placeholder) |
| `hexcore-peanalyzer` | Windows PE binary analyzer |
| `hexcore-elfanalyzer` | Linux ELF binary analyzer |
| `hexcore-minidump` | Windows crash dump parser |
| `hexcore-hexviewer` | Binary hex viewer |
| `hexcore-entropy` | Binary entropy analyzer |
| `hexcore-report-composer` | HexCore report aggregator (superseded by `scylla-reporting`) |

#### Obsolete documentation

| File | Reason |
|---|---|
| `HEXCORE_AUDIT.md` | Native engine audit — HexCore-specific |
| `docs/HEXCORE_AUTOMATION.md` | HexCore pipeline docs — replaced by `SCYLLA_AUTOMATION.md` |
| `docs/HEXCORE_JOB_TEMPLATES.md` | HexCore templates — replaced by `SCYLLA_JOB_TEMPLATES.md` |
| `powers/hexcore-native-engines/` | Native C++/N-API engine documentation |

---

### Retained

Eight HexCore utility extensions remain for pipeline compatibility:

`hexcore-hashcalc` · `hexcore-strings` · `hexcore-base64` · `hexcore-yara` · `hexcore-ioc` · `hexcore-filetype` · `hexcore-common` · `hexcore-better-sqlite3`