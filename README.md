# Scylla 2.0 "Hydra"

**An open-source pentesting IDE for finding business logic vulnerabilities that automated scanners miss.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/version-2.0.0--hydra-red)](./CHANGELOG.md)
[![Built on Code-OSS](https://img.shields.io/badge/built%20on-Code--OSS-007ACC)](https://github.com/microsoft/vscode)

`pentesting` · `bug bounty` · `business logic` · `idor` · `headless automation` · `Code-OSS`

---

## What is Scylla?

Scylla is a pentesting IDE built on Code-OSS (forked from HexCore). It runs vulnerability scanning pipelines defined in a `.scylla_job.json` file and ships with a set of headless scanners for web and API targets.

Version 2.0 "Hydra" shifts focus from reverse engineering to **access control and business logic flaws** — the class of bugs that requires authentication and multi-role session management to find. Things like IDOR, vertical privilege escalation, and mass assignment don't show up in a basic unauthenticated crawl. Scylla is built around that constraint.

---

## What's New in 2.0 — "Hydra Phase 1"

### Authentication Engine (`scylla-auth`)

A dedicated session manager that handles multi-profile login workflows, persistent Cookie Jars, and automatic CSRF token extraction from HTML (`meta[name="csrf-token"]`, `#csrf-token`, and similar patterns). The pipeline runner authenticates all declared profiles upfront and performs session refresh automatically on `401`/`403` responses — no manual cookie juggling required.

### IDOR Scanner (`scylla.scanner.idorHeadless`)

Horizontal privilege escalation scanner. Tests five strategies: direct ID substitution, parameter pollution, JSON array injection, parameter overrides, and UUID-to-integer downgrades.

### Privilege Escalation Scanner (`scylla.scanner.privescHeadless`)

Replays administrative API endpoints using a standard-user session cookie and diffs the response body size and status codes against the privileged baseline. Flags vertical access control gaps.

### Mass Assignment Scanner (`scylla.scanner.massAssignHeadless`)

Injects unexpected payload keys into `POST`/`PUT`/`PATCH` endpoints — things like `role=admin`, `price=0`, `verified=true` — to detect attribute binding vulnerabilities in server-side ORMs and serializers.

### Auth-Aware Pipeline Runner

`.scylla_job.json` now accepts an `auth` object. Declare your login profiles there and the pipeline handles authentication before any scanner step runs.

---

## Getting Started

### Run the development build

```powershell
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat
```

### Create a pipeline job

Drop a `.scylla_job.json` in the workspace root. Scylla detects it and runs the pipeline automatically. Example targeting a local app with two roles:

```json
{
  "target": "http://localhost:3000",
  "outDir": ".scylla/pipeline-output",
  "auth": {
    "profiles": [
      { "name": "admin", "loginUrl": "/api/login", "credentials": { "email": "admin@example.com", "password": "admin123" } },
      { "name": "user",  "loginUrl": "/api/login", "credentials": { "email": "user@example.com",  "password": "user123"  } }
    ]
  },
  "steps": [
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 3, "maxPages": 200, "scope": "host" }
    },
    {
      "cmd": "scylla.scanner.idorHeadless",
      "args": {
        "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json",
        "attackerProfile": "user",
        "victimProfile": "admin",
        "createFindings": true
      },
      "continueOnError": true
    },
    {
      "cmd": "scylla.scanner.privescHeadless",
      "args": {
        "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json",
        "unprivilegedProfile": "user",
        "createFindings": true
      },
      "continueOnError": true
    },
    {
      "cmd": "scylla.reporting.generateHeadless",
      "args": { "title": "Access Control Assessment" }
    }
  ]
}
```

Full pipeline documentation: [`docs/SCYLLA_AUTOMATION.md`](./docs/SCYLLA_AUTOMATION.md)  
Ready-to-use templates: [`docs/SCYLLA_JOB_TEMPLATES.md`](./docs/SCYLLA_JOB_TEMPLATES.md)

---

## Architecture

Scylla retains eight utility extensions from HexCore for pipeline compatibility:

| Extension | Purpose |
|---|---|
| `hexcore-hashcalc` | MD5 / SHA1 / SHA256 / SHA512 hashing |
| `hexcore-strings` | ASCII/Unicode string extraction |
| `hexcore-base64` | Base64 detection and decoding |
| `hexcore-yara` | YARA rule scanning |
| `hexcore-ioc` | IoC extraction and classification |
| `hexcore-filetype` | File type detection |
| `hexcore-common` | Shared utilities |
| `hexcore-better-sqlite3` | SQLite driver for finding persistence |

The thirteen HexCore reverse-engineering extensions (disassembler, emulator, LLVM MC, decompiler, PE/ELF analyzers, etc.) were removed in 2.0. See the [Changelog](./CHANGELOG.md) for the full list.

---

## Roadmap

- [ ] **Phase 2:** GraphQL access control scanner, JWT claim manipulation, multi-step business flow attacks
- [ ] **Phase 3:** Collaborative workspace support, finding export to CVSS/Markdown/JSON
- [ ] Plugin API for community scanners

---

## Contributing

Scylla is open source under GPL v3. Contributions are welcome — open an issue before starting significant work so we can discuss scope and avoid duplication.

---

## License

GNU General Public License v3.0 — see [LICENSE](./LICENSE).