# Changelog

All notable changes to the HikariSystem Scylla Studio project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-10 - "Hydra Phase 1"

> **Major Release: Scylla Core Transition** — The project pivots from reverse-engineering (HexCore) to an offensive-security, business-logic-focused API penetration testing IDE. This release replaces static-cookie scans with dynamic, multi-profile authentication tracking and introduces 3 advanced access control scanners.

### Added

- **Scylla Authentication Engine (`scylla-auth`)**: A headless-first extension managing `CookieJars` and multi-profile login contexts. Automatically parses CSRF tokens (`meta[name="csrf-token"]`, `#csrf-token`, etc.) from HTML and injects them into subsequent POST requests.
- **Auth-Aware Pipeline Runner**: `pipelineRunner.ts` in `.scylla_job.json` now accepts an `"auth"` directive. The runner seamlessly authenticates all defined profiles upfront (`loginAll`) and dynamically performs `sessionRefresh` when scanners hit HTTP 401/403.
- **IDOR Scanner (`scylla.scanner.idorHeadless`)**: Detects horizontal privilege escalation using 5 strategies: sequential swaps, UUID tracking, zero-ID, param removal, and HTTP method override.
- **Privilege Escalation Scanner (`scylla.scanner.privescHeadless`)**: Replays administrative API endpoints with a standard user session cookie, diffing body size and response codes to identify vertical privilege escalation.
- **Mass Assignment Scanner (`scylla.scanner.massAssignHeadless`)**: Injects unexpected payload keys (`role=admin`, `price=0`, `verified=true`) to detect attribute binding vulnerabilities.

### Changed

- Complete redesign of the core scanning architecture to prioritize headless execution, multi-role contexts, and HTTP request replays without browser intervention.
- The `README.md` has been rewritten to reflect the new direction as a closed-source bounty hunter IDE.

### Removed

**13 HexCore reverse-engineering extensions (~2.1 GB)** — These modules belong to the HexCore malware analysis IDE and have no use in Scylla's web/API pentesting mission:

- `hexcore-debugger` — Unicorn CPU emulator (PE/ELF binary emulation)
- `hexcore-disassembler` — Capstone/LLVM MC disassembler with CFG view
- `hexcore-capstone` — Native N-API Capstone disassembly engine
- `hexcore-unicorn` — Native N-API Unicorn emulation engine
- `hexcore-llvm-mc` — Native N-API LLVM MC assembler engine
- `hexcore-remill` — Machine code → LLVM IR lifter (Trail of Bits)
- `hexcore-rellic` — Decompiler scaffold (placeholder)
- `hexcore-peanalyzer` — Windows PE binary analyzer
- `hexcore-elfanalyzer` — Linux ELF binary analyzer
- `hexcore-minidump` — Windows crash dump parser
- `hexcore-hexviewer` — Binary hex viewer
- `hexcore-entropy` — Binary entropy analyzer
- `hexcore-report-composer` — HexCore report aggregator (replaced by `scylla-reporting`)

**Obsolete documentation removed:**

- `HEXCORE_AUDIT.md` — Native engine audit report
- `docs/HEXCORE_AUTOMATION.md` — HexCore pipeline automation docs
- `docs/HEXCORE_JOB_TEMPLATES.md` — HexCore job template examples
- `powers/hexcore-native-engines/` — Native C++/N-API engine documentation

**8 reusable HexCore utility extensions retained** for pipeline compatibility: `hexcore-hashcalc`, `hexcore-strings`, `hexcore-base64`, `hexcore-yara`, `hexcore-ioc`, `hexcore-filetype`, `hexcore-common`, `hexcore-better-sqlite3`.

---
