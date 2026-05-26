# HikariSystem Scylla

<p align="center">
  <img alt="HikariSystem Scylla" src="Scylla.png" width="200">
</p>

<p align="center">
  <strong>A comprehensive offensive security and penetration testing IDE built on Code-OSS</strong>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#extensions">Extensions</a> |
  <a href="#authentication-engine">Authentication</a> |
  <a href="#automation-pipeline">Automation</a> |
  <a href="#installation">Installation</a> |
  <a href="#usage">Usage</a> |
  <a href="#license">License</a>
</p>

<p align="center">
  <code>web pentesting</code> &middot; <code>bug bounty</code> &middot; <code>access control</code> &middot; <code>session management</code> &middot; <code>IDOR scanner</code> &middot; <code>headless automation</code> &middot; <code>vulnerability scanners</code> &middot; <code>offensive pipeline</code> &middot; <code>report composer</code>
</p>

---

## Overview

**HikariSystem Scylla** is a state-of-the-art offensive security and penetration testing IDE derived from the HexCore codebase and built on top of the Code-OSS application shell. While HexCore focused on binary reverse engineering, decompilation, and emulation, Scylla shifts the focus entirely to **web vulnerability hunting, automated reconnaissance, access control evaluation, and penetration testing workflows**.

Version 2.0 **"Hydra"** is designed specifically to target complex access control, authorization, and business logic flaws — the critical class of bugs that unauthenticated automated scanners completely miss. By integrating a multi-profile session manager, auth-aware pipeline runner, high-performance scanners, and tactical reporting tools, Scylla provides security professionals with a unified command deck to run, automate, and document offensive operations.

> [!IMPORTANT]
> **What makes Scylla different:**
> - **Auth-First Vulnerability Hunting:** Automate multi-role session orchestration to find complex IDOR, Privilege Escalation, and Mass Assignment flaws.
> - **Zero-Config Native Scanners:** Integrated port scanners, directory fuzzers, crawler suites, and vulnerability engines out of the box (no external tool setups required).
> - **Offensive Automation Pipelines:** Define complete operations in a single `.scylla_job.json` file, with conditional branching and priority queueing.
> - **Scylla Command Deck Dashboard:** A beautiful, responsive starting hub for running diagnostics, choosing fuzzing presets, browsing tactical wordlists, and orchestrating pentests.

---

## Features

### 📡 Automated Reconnaissance (`scylla-recon`)
- **Port Scanner** — Async multi-threaded TCP port scanner with service banner grabbing.
- **Web Crawler** — High-performance crawler with deep page traversal and intelligent scope constraints (domain, host, wildcard).
- **Directory Fuzzing** — Multi-threaded directory and file fuzzer with advanced status filtering and recursive scanning.
- **Technology Detection** — Passive fingerprinting of server headers, cookies, scripts, and meta tags to identify frameworks and infrastructure.
- **WAF Fingerprinting** — Active and passive identification of Web Application Firewalls (Cloudflare, Akamai, AWS WAF, Imperva, etc.).

### 🛡️ Vulnerability Scanning Suite (`scylla-scanner`)
- **SQL Injection (SQLi)** — In-depth parameter payload testing for error-based, boolean-based, and time-based SQL injection.
- **Cross-Site Scripting (XSS)** — Advanced injection testing with context-aware payloads, DOM-based analysis, and active exploit generation.
- **Local File Inclusion (LFI)** — Directory traversal payload testing with LFI exploitation utilities (reading log files, wrapping, base64 filters).
- **Template Injection (SSTI)** — Detecting server-side template engine execution (Jinja2, Twig, Freemarker, Velocity) with payload testing.
- **CORS Misconfiguration** — Active probing for trust-origin wildcard bypasses and credential leakage patterns.
- **SSRF Detection** — Server-Side Request Forgery auditing with out-of-band (OOB) DNS/HTTP callback triggers.
- **JWT Attack Suite** — JWT header manipulation, key spoofing, signature stripping (the `none` algorithm), and secret brute-forcing.
- **GraphQL Security** — Automatic schema introspection query probes, field suggestions harvesting, query depth auditing, and directive injection.

### 🔑 Authentication & Session Engine (`scylla-auth`)
- **Multi-Profile Login** — Declare multiple authenticated user sessions (e.g., Administrator, Standard User, Anonymous) inside your pipeline.
- **Persistent Cookie Jars** — Session preservation across multiple scans, ensuring continuous authenticated states.
- **CSRF Token Extractor** — Automatic parsing of HTML headers, forms, and cookies (`meta[name="csrf-token"]`, `#csrf`, custom fields) to inject fresh tokens dynamically into active fuzzing payloads.
- **Auto-Refresh Handlers** — Smart recovery and re-authentication on `401 Unauthorized` or `403 Forbidden` responses during automated operations.

### 🔌 Tactical HTTP Suite (`scylla-http`)
- **HTTP Request Execution** — Run HTTP requests directly from `.http` file-backed artifacts.
- **Custom Hosts Resolution** — In-editor DNS overrides for testing staging/virtual hosts without editing system `/etc/hosts` files.
- **Intruder/Repeater Capabilities** — Easily replay, edit, and bulk-send requests with payload tables and real-time response diffs.

### 📂 Wordlist Manager (`scylla-wordlists`)
- **Curated Wordlists** — Out-of-the-box tactical wordlists for subdomains, directory fuzzing, default credentials, API endpoints, and common payloads.
- **Preview & Filter** — In-editor wordlist browsing, line slicing, search filtering, and custom path resolving for headless engines.

### 📊 Report Composer & Exporter (`scylla-reporting`, `scylla-export`)
- **Findings Exporter** — One-click export of findings into standard JSON, CSV, and SARIF 2.1 formats for seamless SIEM/pipeline ingestion.
- **Pentest Report Generator** — Aggregate findings, evidence, HTTP transactions, and severity scores into high-end, client-ready Markdown or PDF reports complete with a Table of Contents.

---

## Extensions

HikariSystem Scylla is organized in a highly modular extension structure inside `extensions/`.

### 🛠️ Scylla Native Modules

| Extension | Version | Description |
|-----------|---------|-------------|
| **Scylla Recon** | 0.2.0 | Native reconnaissance workflows: port scanning, web crawling, directory fuzzing, technology detection, and WAF fingerprinting. |
| **Scylla Scanner** | 0.2.0 | Native vulnerability scanners: SQLi, XSS, LFI, SSTI, CORS, SSRF, JWT, GraphQL, DOM XSS, secrets detection, and more. |
| **Scylla HTTP** | 0.1.0 | HTTP request execution, replay, repeater, and file-backed request artifacts (.http) for the Scylla workbench. |
| **Scylla Wordlists** | 0.1.0 | Built-in wordlist manager for directory fuzzing, parameter discovery, and credential testing. |
| **Scylla Export** | 0.1.0 | Export findings to JSON, CSV, and SARIF 2.1 formats for integration with external tools. |
| **Scylla Reporting**| 0.1.0 | Penetration test report generation and composer. |
| **Scylla Findings** | 0.1.0 | Interactive security findings tree view, lifecycle tracker, and vulnerability cataloger. |
| **Scylla Jobs** | 0.2.0 | Headless automation pipeline runner for Scylla jobs (`.scylla_job.json`). |
| **Scylla Theme** | 2.0.0 | Cyberpunk dark themes (including Scylla Hydra Crimson v2) with sleek custom CSS injection. |

### 🧩 Legacy Retained Modules (HexCore Compatibility)
These eight lightweight utility modules are preserved to maintain full automation and scripting compatibility with HexCore-style jobs:

- `hexcore-hashcalc` — MD5 / SHA-1 / SHA-256 / SHA-512 file hashing with VirusTotal lookup.
- `hexcore-strings` — ASCII/UTF-16 string extractor with multi-byte XOR deobfuscation.
- `hexcore-base64` — Detects and decodes Base64 payloads dynamically.
- `hexcore-yara` — High-speed YARA rule matching with built-in anti-analysis signature packs.
- `hexcore-ioc` — Automated Indicator of Compromise extraction (IPs, URLs, domains, registry paths).
- `hexcore-filetype` — Magic bytes signature detection.
- `hexcore-common` — Shared helper libraries.
- `hexcore-better-sqlite3` — Native SQLite3 bindings for logging and finding persistence.

---

## Authentication Engine

The **Scylla Auth Engine** enables automated session hijacking and authenticated scanning. By configuring login profiles, Scylla authenticates upfront and manages session states in the background:

```
[Target Application] 
   ↑
   ├─ (Profile: Administrator) ──→ [Cookie Jar A] ──→ (Automated CSRF Token Injection)
   ├─ (Profile: Standard User)  ──→ [Cookie Jar B] ──→ (Automatic Auth-Header Refresh)
   └─ (Profile: Anonymous)      ──→ [No Cookies]
```

When scanning for **IDOR** or **Privilege Escalation**, the Scanner uses these authenticated channels to replay requests across different security contexts and diff the results to pinpoint authorization gaps.

---

## Automation Pipeline

Scylla provides headless batch testing via `.scylla_job.json` files. The workspace watcher automatically detects these files and queues them in Scylla's priority scheduler.

### 📝 Example `.scylla_job.json`
Below is a complete multi-profile automation script targeting an API and looking for access control bugs:

```json
{
  "target": "http://localhost:3000",
  "outDir": ".scylla/pipeline-output",
  "auth": {
    "profiles": [
      {
        "name": "admin",
        "loginUrl": "/api/login",
        "credentials": { "email": "admin@example.com", "password": "admin123" }
      },
      {
        "name": "user",
        "loginUrl": "/api/login",
        "credentials": { "email": "user@example.com", "password": "user123" }
      }
    ]
  },
  "steps": [
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": {
        "url": "${target}",
        "maxDepth": 3,
        "maxPages": 200,
        "scope": "host"
      }
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
      "args": {
        "title": "Access Control Vulnerability Report"
      }
    }
  ]
}
```

---

## Installation

### Prerequisites

| Requirement | Minimum Version | Verification Command |
|---|---|---|
| **Node.js** | v22.21.1+ (see `.nvmrc`) | `node --version` |
| **npm** | v10+ | `npm --version` |
| **Python** | 3.x | `python --version` |
| **Visual Studio Build Tools** | 2019 or 2022 | Installed via [Visual Studio Installer](https://visualstudio.microsoft.com/downloads/) |

> [!WARNING]
> **Windows Compiles:** Visual Studio Build Tools must have the **"Desktop development with C++"** workload checked. This is required for compiling native node bindings (`node-pty`, `better-sqlite3`, etc.).

### Build Steps

1. **Clone the Repository:**
   ```powershell
   git clone https://github.com/AkashaCorporation/HikariSystem-Scylla.git
   cd HikariSystem-Scylla
   ```

2. **Install Root Dependencies:**
   ```powershell
   $env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
   npm install
   ```

3. **Compile the IDE & Extensions:**
   ```powershell
   $env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
   npm run compile
   ```

4. **Launch the Development Shell:**
   ```powershell
   $env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
   .\scripts\code.bat
   ```

---

## Usage

### 🚀 Running Scans & Recon
- **Start Port Scanning:** Run `Scylla Recon: Port Scan` from the Command Palette (`Ctrl+Shift+P`).
- **Initiate Web Crawl:** Run `Scylla Recon: Crawl Website` and input your target URL.
- **Directory Fuzzing:** Right-click a target directory or run `Scylla Recon: Directory Fuzzing` and select your wordlist of choice.

### 🧪 Vulnerability Auditing
- **Scan Targets:** Open the Scylla findings tab in the Activity Bar to inspect active targets.
- **Vulnerability Checks:** Right-click an endpoint or domain in the tree and select a targeted scanner like `SQL Injection` or `Cross-Site Scripting`.
- **Orchestrate Attacks:** Use the Scylla Command Deck Preset cards for instant fuzzer/scanner runs.

### 📂 Using Wordlists
- **Browse Lists:** Run `Scylla Wordlists: Browse Wordlists` to inspect, preview, and load built-in payload text files.

### 📊 Generating Pentest Reports
- **Execute Report Composer:** Run `Scylla: Generate Pentest Report` to aggregate current workspace findings, screenshots, and evidence files into a beautifully formatted Markdown/PDF deliverable.

---

## Contributing

Scylla is open source under the **GNU General Public License v3.0**. 

Contributions are welcome! Please open a detailed issue or a draft Pull Request to discuss new scanners, vulnerability engines, or dashboard capabilities before initiating large-scale code refactors.

---

## License

This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for complete details.

---

<p align="center">
  <strong>HikariSystem Scylla</strong> — Offensive Security Suite for Professionals
</p>