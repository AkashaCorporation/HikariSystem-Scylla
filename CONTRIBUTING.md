# Contributing to HikariSystem Scylla Studio

Thank you for your interest in Scylla Studio. This repository is currently in a transition phase from the HexCore donor codebase into a dedicated pentesting IDE built on Code-OSS.

## Current Contribution Focus

The highest-value contributions right now are:

- product rebranding from HexCore to Scylla Studio
- pentest-oriented UX and workflow changes
- recon, HTTP testing, reporting, and headless automation features
- cleanup of reverse-engineering-only engines from the default Scylla experience
- build, packaging, and preview stability for the Scylla desktop shell

## Development Setup

```powershell
git clone https://github.com/AkashaCorporation/HikariSystem-Scylla.git
cd HikariSystem-Scylla

$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"
npm install
.\scripts\code.bat
```

## Notes

- Scylla Studio is a sister product to HexCore, not a rename-only release.
- Some files and folders still reference HexCore because the migration is in progress.
- Until the migration is complete, prefer incremental, reviewable changes over broad blind replacements.

## Pull Requests

- Keep changes focused.
- Call out any legacy HexCore behavior that is intentionally preserved.
- Mention whether a change is transitional rebranding, product-shell work, or Scylla-native functionality.

## Security

Do not disclose vulnerabilities in public issues. Use the guidance in [SECURITY.md](SECURITY.md).
