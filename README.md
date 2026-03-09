# HikariSystem Scylla Studio

<p align="center">
  <strong>The Pentesting IDE. Recon, HTTP testing, structured reporting, and headless automation powered by Code-OSS.</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> |
  <a href="#current-direction">Current Direction</a> |
  <a href="#preview">Preview</a> |
  <a href="#roadmap">Roadmap</a> |
  <a href="#license">License</a>
</p>

<p align="center">
  <code>pentesting</code> &middot; <code>bug bounty</code> &middot; <code>recon</code> &middot; <code>HTTP testing</code> &middot; <code>headless automation</code> &middot; <code>Code-OSS</code>
</p>

---

## Overview

HikariSystem Scylla Studio is a pentest-focused IDE being built on top of the same Code-OSS foundation that powers HexCore. The goal is to turn this repository into a dedicated environment for web and API security workflows, while keeping HexCore and Scylla as separate sister products under the same umbrella.

Scylla is not a reverse engineering fork with a new logo. It is a new offensive-security workspace that will gradually replace HexCore-specific branding, product metadata, workflows, and built-in defaults with a bug-hunting and pentest-oriented experience.

The current shell still inherits the donor snapshot's Code-OSS package version `1.104.0`, while the historical HexCore product changelog in this repository starts from `3.5.4` on February 19, 2026.

## Current Direction

The repository currently starts from the HexCore codebase so we can move fast and test changes directly in the real application shell with `scripts/code.bat`.

The first transition goals are:

- rebrand product identity from HexCore to Scylla Studio
- preserve the Code-OSS shell and preview workflow
- keep only the pieces we want to evolve into Scylla
- phase out reverse-engineering engines and analysis modules that do not belong in the Scylla default build
- add Scylla-native workflows for recon, HTTP testing, findings, reporting, and headless job execution

## Preview

Once dependencies are installed, the preview target remains the standard Code-OSS development loop:

```powershell
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat
```

This is the fastest way to validate branding, menus, product identity, and the future Scylla workflow inside the real desktop shell.

## Roadmap

- First-pass rebrand of product metadata, docs, workflows, and assets
- Clean separation between HexCore-native engines and Scylla defaults
- Scylla-native extension set for recon, HTTP, reporting, and automation
- Optional profiles or add-on packs for features that should not ship by default
- Dedicated visual identity and icons for Scylla Studio

## License

This repository is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
