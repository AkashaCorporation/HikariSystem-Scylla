# Repository Guidelines

## Project Structure & Module Organization

This repository is based on the Code-OSS application shell and currently derives from the HexCore codebase. The goal of this project is to transition the product into **HikariSystem Scylla**, a pentesting-oriented IDE focused on recon, HTTP testing, reporting, and automation workflows.

Key directories:

- `src/` — Core application logic inherited from Code-OSS.
- `extensions/` — Built-in extensions, inherited `hexcore-*` modules, and initial scaffold plus future `scylla-*` modules.
- `resources/` — Icons, branding assets, and product metadata.
- `scripts/` — Development scripts (e.g. launching the development shell).
- `build/` — Build tooling and packaging configuration.

Agents should avoid modifying upstream Code-OSS infrastructure unless necessary. Prefer implementing new functionality through extensions or isolated modules.

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
| Install dependencies | `npm install` |
| Run tests | `npm test` |
| Lint source | `npm run lint` |

Agents should verify the application still launches after structural changes.

---

## Coding Style & Naming Conventions

Primary language: **TypeScript**

General rules:

- 2-space indentation
- Prefer TypeScript over plain JavaScript
- Follow existing Code-OSS architectural patterns
- Use descriptive names for modules and services

Naming conventions:

| Type | Convention |
|------|------------|
| Classes | PascalCase |
| Functions | camelCase |
| Files | kebab-case.ts |
| Extensions | `scylla-*` for new Scylla-native modules; existing `hexcore-*` may remain when reused |

Formatting should follow existing repository linting rules.

---

## Commit & Pull Request Guidelines

Commits should be concise and descriptive.

Example:

```
scylla: replace legacy hexcore branding in product metadata
```

Pull requests should include:

- description of the change
- rationale for modification
- screenshots if UI changes are involved
- confirmation the development shell launches successfully

Large refactors should be split into smaller commits.

---

## Branding & Migration Rules

This repository is transitioning from **HexCore** to **Scylla**.

Agents should:

- replace HexCore branding with Scylla where appropriate
- preserve compatibility with the Code-OSS shell
- avoid breaking the development preview environment
- remove reverse-engineering specific modules unless explicitly required
- prefer new Scylla-specific capabilities under `scylla-*` without forcing rename-only churn in inherited `hexcore-*` modules

HexCore functionality should only remain if it supports Scylla workflows or can be repurposed.

---

## Agent Workflow Guidance

When modifying the repository:

1. Analyze the existing module structure before editing files.
2. Prefer incremental changes over large rewrites.
3. Avoid altering upstream Code-OSS internals unless necessary.
4. Ensure the application can still start using the preview script.

Agents should prioritize stability, incremental migration, and clear commit history during the Scylla transition.
