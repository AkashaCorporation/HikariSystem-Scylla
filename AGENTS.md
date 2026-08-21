# Repository Guidelines

## Project Structure & Module Organization

This repository is based on the Code-OSS application shell and derives historically from the HexCore codebase. The product is now **HikariSystem Scylla**, a pentesting-oriented IDE focused on recon, HTTP testing, identity-aware authorization analysis, reporting, and automation workflows.

Key directories:

- `src/` — Core application logic inherited from Code-OSS.
- `extensions/` — Built-in extensions, retained reusable `hexcore-*` utilities, and Scylla-native `scylla-*` modules.
- `resources/` — Icons, branding assets, and product metadata.
- `scripts/` — Development, validation, and build scripts.
- `build/` — Build tooling and packaging configuration.
- `docs/jobs/` — Headless `.scylla_job.json` examples.
- `.agent/skills/scylla/` — Current Scylla operational guidance for agents.

Agents should avoid modifying upstream Code-OSS infrastructure unless necessary. Prefer implementing new functionality through extensions or isolated modules.

---

## Agent Skill Routing

For Scylla web/API pentesting, authorization, business-logic, engagement, HTTP, findings, or Jobs work, read and follow:

```text
.agent/skills/scylla/SKILL.md
```

The existing `.agent/skills/hexcore/SKILL.md` is **legacy compatibility material inherited from the old HexCore-derived repository state**. It describes reverse-engineering engines and commands that are not the current Scylla product capability map. Do not use it as the primary tool guide for Scylla work.

For authorization research, treat Scylla as an experiment/evidence system rather than an oracle:

```text
hypothesis
→ engagement/context
→ identity + resource
→ governed probe or scanner candidate
→ transaction/evidence
→ authorization matrix
→ validation
→ finding
```

A scanner candidate is not automatically a validated vulnerability.

---

## Build, Test, and Development Commands

Run the development environment using the Code-OSS preview loop:

```powershell
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat
```

Common tasks:

| Task | Command |
|-----|--------|
| Launch development build | `.\scripts\code.bat` |
| Install pinned dependencies | `npm ci` |
| Run Scylla static preflight | `node scripts/verify-scylla-preflight.cjs` |
| Run tests | `npm test` |
| Lint source | `npm run lint` |

The repository targets Node.js **22.21.1** (see `.nvmrc`).

Agents should verify the affected extension compiles after TypeScript changes and, for packaging changes, keep the Scylla CI/Windows ZIP workflows green.

---

## Coding Style & Naming Conventions

Primary language: **TypeScript**

General rules:

- 2-space indentation unless an inherited file uses the Code-OSS tab convention.
- Prefer TypeScript over plain JavaScript for extensions.
- Follow existing Code-OSS architectural patterns.
- Use descriptive names for modules and services.
- Keep command handlers small; move persistence/protocol/business logic into dedicated modules.
- Prefer explicit typed provenance over information encoded only in free-form strings.

Naming conventions:

| Type | Convention |
|------|------------|
| Classes | PascalCase |
| Functions | camelCase |
| Files | kebab-case.ts or the existing local convention |
| Extensions | `scylla-*` for new Scylla-native modules; retained `hexcore-*` names may remain for compatibility utilities |

Formatting should follow existing repository linting rules.

---

## Headless and Jobs Contract

New automation-capable features should expose deterministic headless commands. When adding a new headless command that should be usable in `.scylla_job.json`, also register it in the Scylla Jobs capability registry in:

```text
extensions/scylla-jobs/src/pipelineRunner.ts
```

Then extend `scripts/verify-scylla-preflight.cjs` if the new capability introduces a new invariant or packaging dependency.

Do not silently bypass the shared Scope + Rate-Limit Governor. Network features should reuse the governed Scylla HTTP/auth paths where possible.

The current Jobs timeout is a **soft timeout** based on `Promise.race`; it does not yet cooperatively cancel the underlying operation. Avoid automatic retries for long-running scanner steps until timeout containment/cancellation is implemented.

---

## Authorization and Evidence Rules

For identity-aware testing:

- Record which identity/profile actually sent a request.
- Model the resource/operation being tested.
- Distinguish ownership from authorization policy.
- Do not infer `deny` solely because an identity is not the resource owner.
- Prefer same-operation cross-profile baselines.
- HTTP `2xx`, body size similarity, endpoint names, or scanner confidence do not prove impact alone.
- Keep uncertain results as `observation` or `candidate`.
- Use `validated` only after policy and unauthorized behavior are demonstrated reproducibly.
- Keep state-changing probes opt-in and scoped to authorized, necessary tests.
- Do not persist or commit live credentials. Normal Scylla HTTP evidence should remain redacted; explicit replay artifacts may still be sensitive.

---

## Commit & Pull Request Guidelines

Commits should be concise and descriptive.

Example:

```text
scylla: add authorization transaction model
```

Pull requests should include:

- description of the change;
- rationale for modification;
- screenshots if UI changes are involved;
- relevant preflight/compile/build results;
- notes about state-changing network behavior, if any.

Large refactors should be split into smaller commits.

---

## Branding & Migration Rules

This repository is Scylla, even where inherited filenames still contain legacy HexCore naming.

Agents should:

- replace user-visible HexCore branding with Scylla where appropriate;
- preserve compatibility with the Code-OSS shell;
- avoid breaking the development preview environment;
- remove reverse-engineering-specific modules when they have no Scylla use;
- prefer new Scylla-specific capabilities under `scylla-*` without forcing rename-only churn in reusable inherited utilities.

HexCore functionality should only remain if it supports Scylla workflows or can be repurposed. Native engine synchronization is a separate migration task and should not be mixed casually into unrelated Scylla feature work.

---

## Agent Workflow Guidance

When modifying the repository:

1. Analyze the existing module and command contracts before editing files.
2. Prefer incremental changes over large rewrites.
3. Avoid altering upstream Code-OSS internals unless necessary.
4. Run `node scripts/verify-scylla-preflight.cjs` for command/build/job-contract changes.
5. Compile affected `scylla-*` extensions.
6. Keep new automation commands visible to Scylla Jobs.
7. Preserve scope, identity provenance, evidence redaction, and safe-by-default network behavior.

Agents should prioritize reproducibility, evidence quality, stability, and clear commit history.
