# Changelog

All notable changes to the HikariSystem Scylla Studio project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - "Scope Governor"

> **Security hardening: a shared Scope + Rate-Limit Governor.** Scylla hits LIVE targets, so it now enforces the authorized engagement boundary at every egress, throttles traffic, and no longer auto-fires scans the moment a job file appears. Off by default (back-compatible); you opt in per engagement via the `scylla.governor.*` settings.

### Added

- **Scope + Rate-Limit Governor** (`scylla.governor.*` settings): an in-scope host allowlist (exact + `*.wildcard`), a per-host token-bucket rate limit (`rateLimitPerSec`), a global concurrency cap (`maxConcurrency`), and an auto-run consent toggle (`consent`). One shared primitive that every extension reads from VS Code settings.
- **Engagement-scope commands**: `scylla.http.{set,clear,get}ScopeHeadless` and `scylla.auth.{set,clear,get}ScopeHeadless`. A pipeline run publishes its declared target(s) to the egress layer (mirroring custom-host registration) without touching `settings.json`.
- **`.scylla_job.json` `scope` field**: extra in-scope host patterns for an engagement, beyond `target`.

### Changed

- **Job auto-run is now consent-gated (default OFF).** Dropping, editing, or opening a workspace with a `.scylla_job.json` no longer silently launches scanners at its target; you get a "Run scan now" / "Always auto-run" prompt instead. The interactive "Run Pipeline" command stays the explicit, consent-free path. A pipeline run constrains the egress layer to its declared scope and clears it when finished.
- **`scylla-http` egress is governed.** The `sendHeadless` chokepoint now enforces scope, rate limit, and concurrency on every request, re-checking scope per redirect hop (an out-of-scope `Location` is no longer followed).
- **Auth cookies are domain-scoped.** `getHeadersHeadless` threads the target URL so cookies are matched to the request host (fixes a cross-host session leak that also polluted IDOR/privesc results); the IDOR scanner re-resolves headers per crawl-endpoint host. Auth-side login egress is scope-gated (closes the auto-login SSRF) and throttled.
- **Port scanner is scoped.** Raw TCP connects now enforce the engagement scope before dialing and honor the rate/concurrency budget.

### Security

- Closes the "no guardrails" gap: out-of-scope hits (a bounty-scope violation), unthrottled bursts (rate-limit bans / accidental DoS), silent job auto-fire, and cross-host credential leakage are all addressed by the governor.

## [2.1.0] - 2026-05-27 - "Hybrid XSS Engine: Dalfox + XSStrike"

> **Major Release: Hybrid XSS Engine** — A complete overhaul of the XSS scanning capabilities. The `scylla.scanner.xssHeadless` command is now powered by a two-phase hybrid engine combining Dalfox's speed and AST validation with XSStrike's dynamic payload fuzzing and WAF evasion. This eliminates false positives and generates bespoke payloads to bypass Web Application Firewalls natively in TypeScript without any C++ (N-API) dependencies.

### Added

- **Phase 1: Dalfox Heuristics (`xssHeuristics.ts`)**: Intelligent context detection (HTML, attributes, scripts, dom-events) mapping with static polyglot templates and deep structural DOM verification to ensure execution before flagging.
- **Phase 2: XSStrike WAF Fuzzer (`wafFuzzer.ts`)**: Employs fuzzy string matching (Levenshtein-style) via targeted boundary canaries to score the exact characters a WAF permits, HTML-encodes, or outright deletes.
- **XSStrike JS Contexter (`jsContexter.ts`)**: Dynamically balances open JavaScript syntax blocks (unmatched quotes, brackets, arrays) discovered during reflection, automatically generating an exact reverse string (e.g., `]})`) to prevent JS execution errors.
- **XSStrike Dynamic Generator (`dynamicGenerator.ts`)**: Constructs XSS payloads on the fly via mutation and permutation (e.g., `<sVg/onLOad=`), completely bypassing signature-based WAFs by using only the characters proven safe by the WafFuzzer.
- **Exponential Back-off Rate Limiter (`rateLimiter.ts`)**: Introduces adaptive rate limiting that automatically intercepts HTTP 403 (Forbidden) and 429 (Too Many Requests) responses from defensive systems, throttling the injection speed to outwait the firewall.
- **Configuration Support**: Added `rateLimitRetryBaseMs` and `maxRetries` arguments to `scylla.scanner.xssHeadless` inside `.scylla_job.json`.

## [2.0.1] - 2026-05-27 - "Windows Build & Bootstrap Hotfix"

> **Hotfix Release: Build & Bootstrap Stability** — A critical set of updates to resolve compilation and bootstrap failures during clean installations on Windows environments. This ensures the Scylla Studio IDE can be built and launched by any developer, offline or online, without N-API or compiler toolchain crashes.

### Fixed

- **Phantom N-API Dependencies in `dirs.ts` & `gulpfile.extensions.ts`**: Eliminated reference errors during clean builds by removing obsolete HexCore extensions (disassembler, debugger, etc.) and adding new Scylla extensions (`scylla-auth`, `scylla-export`, `scylla-wordlists`). Implemented dynamic `fs.existsSync` filtering to automatically ignore any non-existent directories on disk during bootstrap and gulp compilation tasks.
- **Windows npm Command Spawning (`postinstall.ts`)**: Patched the command argument parser using a regular expression `command.match(/(?:[^\s"]+|"[^"]*")+/g)` instead of raw space splitting. This preserves quoted arguments containing spaces and prevents bootstrap failures on Windows. Also sanitized the `npm_command` value to avoid launching interactive stuck shells (such as `npm exec`).
- **Node-GYP Compilation Timeout (`preinstall.ts`)**: Increased the preinstall node-gyp execution timeout from 60 seconds to 5 minutes (`300_000` ms) to allow slower MSVC compiler runs on Windows to complete gracefully without aborting.
- **Fallback for Native SQLite Binaries (`hexcore-native-install.js`)**: Patched the installation script for `better-sqlite3` to exit with status code 0 if a precompiled `.node` binary already exists in `prebuilds/win32-x64/`, avoiding compiler errors on environments without local C++ compiler headers.

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
