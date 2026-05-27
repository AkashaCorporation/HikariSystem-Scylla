# Scylla Automation -- Command Reference

Scylla is a pentesting IDE built as a fork of HexCore. It runs vulnerability scanning and web reconnaissance pipelines from a workspace job file named `.scylla_job.json`. This document is the complete reference for AI agents controlling Scylla via CLI.

**Key differences from HexCore:**
- Scylla targets **web applications and network services**, not binary files.
- The job file uses `target` (URL or hostname) instead of `file`.
- Scylla is TypeScript-only -- no Python dependency.
- Output files go to `outDir` (defaults to `.scylla/pipeline-output`).
- Pipeline status is written to `scylla-pipeline.status.json` and `scylla-pipeline.log` inside `outDir`.

---

## How It Works

1. Create a `.scylla_job.json` file in the workspace root.
2. Scylla watches for this file and runs it automatically on create/change.
3. Auto-run serializes repeated triggers to avoid overlapping runs.
4. Manual run: `Run Scylla Pipeline` (`scylla.jobs.runJob`).
5. Generate from preset: `Create Pipeline from Preset` (`scylla.jobs.createPresetJob`).
   - Built-in presets: **Web Recon**, **Vulnerability Scan**, **HTB Easy Machine**, **Secrets Hunt**.
6. Validate before running: `scylla.jobs.validateJob` / `scylla.jobs.validateJobHeadless`.
7. Diagnose health: `scylla.jobs.doctor`.

---

## Job File Schema

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "variables": {
    "customVar": "value"
  },
  "steps": [
    { "cmd": "scylla.recon.portscanHeadless", "args": { "ports": "top1000" } },
    { "cmd": "scylla.recon.crawlHeadless", "args": { "maxDepth": 3, "maxPages": 200 } },
    {
      "cmd": "scylla.scanner.sqliHeadless",
      "args": { "crawlResultFile": "${outDir}/02-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true
    },
    { "cmd": "scylla.reporting.generateHeadless", "args": { "title": "Assessment Report" } }
  ]
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `target` | `string` | Target URL or hostname. Passed to every step as `url` and `target`. |
| `outDir` | `string` | Output directory. Relative paths resolve from workspace root. |
| `steps` | `PipelineStep[]` | Non-empty array of pipeline steps. |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `quiet` | `boolean` | `true` | Suppress VS Code notification messages. |
| `variables` | `Record<string, string>` | `{}` | Custom template variables for `${varName}` substitution. |

---

## Template Variables

The pipeline runner substitutes these variables in all string values within step `args`:

| Variable | Value | Description |
|----------|-------|-------------|
| `${target}` | `job.target` | The target URL or hostname from the job file. |
| `${outDir}` | Resolved output directory | Absolute path to the output directory. |
| `${workspaceRoot}` | Workspace folder path | Absolute path to the first VS Code workspace folder. |

Custom variables defined in `job.variables` are also available (e.g., `${customVar}`).

**IMPORTANT:** Always use `${outDir}` when referencing files produced by earlier steps. The pipeline runner resolves `outDir` to an absolute path at runtime, so hardcoded paths will break.

---

## Step Controls

Each step supports optional execution controls:

```json
{
  "cmd": "scylla.scanner.sqliHeadless",
  "args": { "crawlResultFile": "${outDir}/03-scylla-recon-crawlheadless.json" },
  "timeoutMs": 300000,
  "retryCount": 2,
  "retryDelayMs": 1500,
  "expectOutput": true,
  "continueOnError": true
}
```

| Control | Default | Description |
|---------|---------|-------------|
| `timeoutMs` | per-command default | Override per-step timeout in milliseconds. |
| `retryCount` | `0` | Number of retries after initial failure. |
| `retryDelayMs` | `1000` | Delay between retries in milliseconds. |
| `expectOutput` | `true` | Validate that an output file was created. |
| `continueOnError` | `false` | Continue remaining steps after this step fails. |

---

## Auto-Generated Output Paths

When a step does not define `output.path`, Scylla auto-generates an output file inside `outDir`:

```
{padded-index}-{command-name-dashed}.json
```

Examples:
- Step 1 (`scylla.recon.portscanHeadless`) -> `01-scylla-recon-portscanheadless.json`
- Step 2 (`scylla.recon.crawlHeadless`) -> `02-scylla-recon-crawlheadless.json`
- Step 3 (`scylla.scanner.sqliHeadless`) -> `03-scylla-scanner-sqliheadless.json`

The index is **1-based** and **zero-padded to 2 digits**. The command name has dots replaced with dashes and is lowercased.

This naming convention is critical for `crawlResultFile` references between steps. If the crawl step is step 3 (1-based), its output file is:

```
${outDir}/03-scylla-recon-crawlheadless.json
```

---

## Headless Commands (Pipeline-Safe)

### Recon Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.recon.portscanHeadless` | 300s | TCP port scanning with service/banner detection. |
| `scylla.recon.crawlHeadless` | 300s | Web crawler with form and parameter discovery. |
| `scylla.recon.dirfuzzHeadless` | 600s | Directory and file fuzzer with wordlists. |
| `scylla.recon.techdetectHeadless` | 30s | Technology fingerprinting (48 patterns). |
| `scylla.recon.wafdetectHeadless` | 30s | WAF fingerprinting (10 WAFs) with bypass suggestions. |

#### `scylla.recon.portscanHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *(required)* | Hostname or IP to scan. |
| `ports` | `string` | `"top1000"` | Port specification: `"top100"`, `"top1000"`, `"1-65535"`, or comma-separated like `"80,443,8080"`. |
| `timeoutMs` | `number` | — | Per-connection timeout in milliseconds. |
| `concurrency` | `number` | — | Number of concurrent connections. |

#### `scylla.recon.crawlHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | Seed URL to start crawling. |
| `maxDepth` | `number` | — | Maximum link-follow depth. |
| `maxPages` | `number` | — | Maximum pages to visit. |
| `scope` | `string` | — | Crawl scope: `"host"` (same host), `"domain"` (same domain), `"path"` (same path prefix). |
| `delayMs` | `number` | — | Delay between requests in milliseconds. |
| `timeoutMs` | `number` | — | Per-request timeout in milliseconds. |
| `headers` | `Record<string, string>` | — | Custom HTTP headers. |
| `cookie` | `string` | — | Cookie header value for authenticated crawling. |

#### `scylla.recon.dirfuzzHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | Base URL to fuzz. |
| `wordlist` | `string` | `"common"` | Wordlist: `"common"`, `"medium"`, or a custom path. |
| `extensions` | `string[]` | — | File extensions to append (e.g., `[".php", ".html", ".txt"]`). |
| `concurrency` | `number` | — | Number of concurrent requests. |
| `delayMs` | `number` | — | Delay between requests in milliseconds. |
| `timeoutMs` | `number` | — | Per-request timeout in milliseconds. |
| `followRedirects` | `boolean` | — | Follow HTTP redirects. |
| `filterStatus` | `number[]` | — | Only include responses with these status codes. |
| `headers` | `Record<string, string>` | — | Custom HTTP headers. |
| `cookie` | `string` | — | Cookie header value. |

#### `scylla.recon.techdetectHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | URL to fingerprint. |

#### `scylla.recon.wafdetectHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | URL to detect WAF on. |
| `headers` | `Record<string, string>` | — | Custom HTTP headers. |
| `cookie` | `string` | — | Cookie header value. |

---

### Scanner Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.scanner.sqliHeadless` | 300s | SQL Injection detection (error-based + time-blind). |
| `scylla.scanner.xssHeadless` | 300s | Cross-Site Scripting detection powered by **Dalfox Heuristics Engine (Pure TS)**. Context-aware generation, DOM-simulated AST checks, polyglots, and WAF bypasses. |
| `scylla.scanner.lfiHeadless` | 300s | Local File Inclusion (path traversal + PHP wrappers). |
| `scylla.scanner.sstiHeadless` | 300s | Server-Side Template Injection (8 template engines). |
| `scylla.scanner.secretsHeadless` | 120s | Secrets and credential detection (36 patterns). |
| `scylla.scanner.corsHeadless` | 30s | CORS misconfiguration testing. |
| `scylla.scanner.headersHeadless` | 30s | Security headers analysis (missing/misconfigured headers). |
| `scylla.scanner.domxssHeadless` | 120s | DOM XSS static JavaScript analysis. |
| `scylla.scanner.paramsHeadless` | 300s | Hidden parameter discovery (70 default parameters). |
| `scylla.scanner.redirectHeadless` | 120s | Open redirect detection. |
| `scylla.scanner.jwtHeadless` | 60s | JWT exploitation (none-alg, weak secret, claim tampering). |
| `scylla.scanner.graphqlHeadless` | 120s | GraphQL security (introspection, injection, batching). |
| `scylla.scanner.ssrfHeadless` | 300s | SSRF detection (24 payloads, cloud metadata endpoints). |
| `scylla.scanner.autoHeadless` | 600s | Run all scanners against a target. |

#### Common Scanner Options

All scanner headless commands share these options:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | Target URL. |
| `crawlResultFile` | `string` | — | Path to a crawl result JSON file. Parameters and URLs are extracted from it. |
| `delayMs` | `number` | — | Delay between requests. |
| `timeoutMs` | `number` | — | Per-request timeout. |
| `headers` | `Record<string, string>` | — | Custom HTTP headers. |
| `cookie` | `string` | — | Cookie header value. |
| `output` | `{ path, format? }` | — | Output file configuration. |
| `quiet` | `boolean` | `true` | Suppress notifications. |
| `createFindings` | `boolean` | `false` | Automatically create finding entries in the Findings store. |

#### `scylla.scanner.sqliHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `parameters` | `ParameterTarget[]` | Direct parameter list (overrides crawl extraction). |
| `techniques` | `Array<"error" \| "time-blind">` | SQLi detection techniques to use. |
| `dbms` | `Array<"mysql" \| "postgresql" \| "mssql" \| "sqlite" \| "oracle">` | Target DBMS filter. |

#### `scylla.scanner.xssHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `parameters` | `ParameterTarget[]` | Direct parameter list. |
| `contexts` | `Array<"html" \| "attribute" \| "javascript" \| "url">` | XSS context types to test. |
| `rateLimitRetryBaseMs` | `number` | Base delay for the XSStrike exponential back-off rate limiter (default: 500). |
| `maxRetries` | `number` | Max retries for the XSStrike WAF evasion engine when receiving HTTP 403 or timeouts (default: 3). |

#### `scylla.scanner.lfiHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `parameters` | `ParameterTarget[]` | Direct parameter list. |
| `osTargets` | `Array<"linux" \| "windows">` | Target OS for path traversal payloads. |
| `encodings` | `Array<"plain" \| "url-encoded" \| "double-encoded" \| "null-byte" \| "php-wrapper">` | Encoding techniques. |

#### `scylla.scanner.sstiHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `parameters` | `ParameterTarget[]` | Direct parameter list. |
| `engines` | `Array<"jinja2" \| "twig" \| "freemarker" \| "velocity" \| "smarty" \| "mako" \| "spel" \| "ognl">` | Template engines to test. |

#### `scylla.scanner.secretsHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | `string` | Raw content to scan (alternative to URL fetching). |
| `verify` | `boolean` | Attempt to verify discovered secrets. |

#### `scylla.scanner.paramsHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `wordlist` | `string[]` | Custom parameter wordlist (overrides default 70-param list). |
| `concurrency` | `number` | Concurrent requests for parameter brute-forcing. |

#### `scylla.scanner.jwtHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `token` | `string` | *(required)* JWT token to analyze. |
| `attacks` | `Array<"decode" \| "none-alg" \| "weak-secret" \| "claim-tamper">` | Attack techniques. |

#### `scylla.scanner.graphqlHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `attacks` | `Array<"introspection" \| "injection" \| "batching" \| "field-enum">` | Attack techniques. |

#### `scylla.scanner.ssrfHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `parameters` | `ParameterTarget[]` | Direct parameter list. |

#### `scylla.scanner.redirectHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `parameters` | `ParameterTarget[]` | Direct parameter list. |

#### `scylla.scanner.autoHeadless` -- Additional Options

| Parameter | Type | Description |
|-----------|------|-------------|
| `scanners` | `Array<"sqli" \| "xss" \| "lfi" \| "ssti" \| "secrets" \| "cors" \| "headers" \| "domxss" \| "params" \| "redirect" \| "jwt" \| "graphql" \| "ssrf">` | Subset of scanners to run (defaults to all). |
| `parameters` | `ParameterTarget[]` | Direct parameter list. |

---

### Exploitation Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.scanner.sqliExtractHeadless` | 600s | SQLi data extraction (UNION/blind/time-based). Fingerprints DBMS, enumerates databases/tables/columns, extracts data. |
| `scylla.scanner.xssExploitHeadless` | 30s | XSS payload generator: cookie stealer, keylogger, session hijacker, phishing redirect, DOM defacement. Multiple encodings. |
| `scylla.scanner.lfiExploitHeadless` | 600s | LFI exploitation chains: PHP filter source reading, log poisoning, sensitive file extraction, wrapper RCE testing. |

#### `scylla.scanner.sqliExtractHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | Target URL with vulnerable parameter. |
| `parameter` | `{ name, location }` | *(required)* | Vulnerable parameter: `{ "name": "id", "location": "query" }`. |
| `dbms` | `string` | auto-fingerprint | Target DBMS: `"mysql"`, `"postgresql"`, `"mssql"`, `"sqlite"`, `"oracle"`. |
| `technique` | `string` | `"union"` | Extraction technique: `"union"`, `"boolean-blind"`, `"time-blind"`. Falls back to blind if UNION fails. |
| `maxRows` | `number` | `50` | Maximum rows to extract per table. |
| `delayMs` | `number` | `150` | Delay between requests. |
| `timeoutMs` | `number` | `15000` | Per-request timeout. |
| `headers` | `Record<string, string>` | — | Custom HTTP headers. |
| `cookie` | `string` | — | Cookie header value. |

**Output:** `SqliExtractResult` with `databases[]`, `tables[]`, `columns[]`, `extractedData[]` (table rows).

#### `scylla.scanner.xssExploitHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | Target URL with XSS-vulnerable parameter. |
| `parameter` | `string` | *(required)* | Name of the vulnerable parameter. |
| `context` | `string` | `"html"` | XSS context: `"html"`, `"attribute"`, `"javascript"`, `"url"`. |
| `callbackUrl` | `string` | *(required)* | Attacker callback URL for data exfiltration. |

**Output:** `XssExploitResult` with `payloads[]` (each has `name`, `description`, `payload`, `encoded`). Generates ~80 payloads across 5 categories × 4 encodings (raw, URL, base64, HTML entity).

#### `scylla.scanner.lfiExploitHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `string` | *(required)* | Target URL with LFI-vulnerable parameter. |
| `parameter` | `{ name, location }` | *(required)* | Vulnerable parameter: `{ "name": "file", "location": "query" }`. |
| `traversalPrefix` | `string` | `"../../../../../../"` | Path traversal prefix. |
| `delayMs` | `number` | `150` | Delay between requests. |
| `timeoutMs` | `number` | `15000` | Per-request timeout. |
| `headers` | `Record<string, string>` | — | Custom HTTP headers. |
| `cookie` | `string` | — | Cookie header value. |

**Output:** `LfiExploitResult` with `readableFiles[]`, `logPoisoningPossible`, `writableWrappers[]`, `rceVectors[]`.

---

### HTTP Utility Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.http.sendHeadless` | 30s | Send a raw HTTP request. Args: `url`, `method`, `headers`, `body`. |
| `scylla.http.saveRequestHeadless` | 10s | Save a request definition as a `.http` file. |
| `scylla.http.replayHeadless` | 30s | Replay a saved request. |

---

### Findings Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.findings.createHeadless` | 10s | Create a finding entry. Args: `title`, `severity`, `target`, `summary`, `evidence`, `tags`. |
| `scylla.findings.appendEvidenceHeadless` | 10s | Append evidence to an existing finding. Args: `file`, `content`. |
| `scylla.findings.createFromHttpHeadless` | 10s | Create a finding from an HTTP response file. Args: `responseFile`. |

---

### Reporting Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.reporting.generateHeadless` | 60s | Generate Markdown + HTML report from all findings and scan results. |

#### `scylla.reporting.generateHeadless`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `title` | `string` | `"Scylla Penetration Test Report"` | Report title. |
| `format` | `string` | `"md"` | Primary format: `"md"` or `"html"`. Both are always generated. |

---

### Pipeline Administration Commands

| Command | Timeout | Description |
|---------|---------|-------------|
| `scylla.jobs.runJobHeadless` | — | Run pipeline from `.scylla_job.json`. Args: `jobFile`, `quiet`. |
| `scylla.jobs.validateJobHeadless` | 30s | Validate a job file without executing it. Args: `jobFile`. |
| `scylla.jobs.listCapabilitiesHeadless` | 30s | List all pipeline-safe commands with timeout and headless status. |
| `scylla.jobs.doctor` | 30s | Diagnose command registration health and list available presets. |

---

## Command Aliases

Short names that resolve to full command names:

| Alias | Resolves To |
|-------|-------------|
| `scylla.scan.sqli` | `scylla.scanner.sqliHeadless` |
| `scylla.scan.xss` | `scylla.scanner.xssHeadless` |
| `scylla.scan.lfi` | `scylla.scanner.lfiHeadless` |
| `scylla.scan.ssti` | `scylla.scanner.sstiHeadless` |
| `scylla.scan.secrets` | `scylla.scanner.secretsHeadless` |
| `scylla.scan.auto` | `scylla.scanner.autoHeadless` |
| `scylla.scan.cors` | `scylla.scanner.corsHeadless` |
| `scylla.scan.headers` | `scylla.scanner.headersHeadless` |
| `scylla.scan.domxss` | `scylla.scanner.domxssHeadless` |
| `scylla.scan.params` | `scylla.scanner.paramsHeadless` |
| `scylla.scan.redirect` | `scylla.scanner.redirectHeadless` |
| `scylla.scan.jwt` | `scylla.scanner.jwtHeadless` |
| `scylla.scan.graphql` | `scylla.scanner.graphqlHeadless` |
| `scylla.scan.ssrf` | `scylla.scanner.ssrfHeadless` |
| `scylla.recon.portscan` | `scylla.recon.portscanHeadless` |
| `scylla.recon.crawl` | `scylla.recon.crawlHeadless` |
| `scylla.recon.dirfuzz` | `scylla.recon.dirfuzzHeadless` |
| `scylla.recon.techdetect` | `scylla.recon.techdetectHeadless` |
| `scylla.recon.wafdetect` | `scylla.recon.wafdetectHeadless` |
| `scylla.exploit.sqli` | `scylla.scanner.sqliExtractHeadless` |
| `scylla.exploit.xss` | `scylla.scanner.xssExploitHeadless` |
| `scylla.exploit.lfi` | `scylla.scanner.lfiExploitHeadless` |

---

## How `crawlResultFile` Works

Many scanner commands accept a `crawlResultFile` argument. This is the path to a JSON file produced by `scylla.recon.crawlHeadless`. The crawl result contains:

- `discovered`: Array of `{ url, method, statusCode }` -- all visited pages.
- `forms`: Array of `{ action, method, inputs[] }` -- discovered HTML forms.
- `parameters`: Array of `{ name, location, url, method }` -- discovered parameters.

When a scanner receives `crawlResultFile`, it extracts parameters and URLs from the crawl output and tests each one. This is how recon feeds into scanning.

### Cross-Step File References

The crawl output filename follows the auto-generated pattern:

```
${outDir}/{padded-index}-scylla-recon-crawlheadless.json
```

For example, if the crawl step is the 3rd step (1-based index = 3):

```json
{
  "cmd": "scylla.scanner.sqliHeadless",
  "args": {
    "crawlResultFile": "${outDir}/03-scylla-recon-crawlheadless.json"
  }
}
```

**Always use `${outDir}` in the path.** The pipeline runner resolves it to the actual absolute output directory at runtime.

---

## Interactive-Only Commands (NOT Pipeline-Safe)

These commands require UI interaction and are blocked in pipeline mode:

| Command | Reason |
|---------|--------|
| `scylla.recon.portscan` | Opens input dialog |
| `scylla.recon.crawl` | Opens input dialog |
| `scylla.recon.dirfuzz` | Opens input dialog |
| `scylla.recon.techdetect` | Opens input dialog |
| `scylla.recon.wafdetect` | Opens input dialog |
| `scylla.scanner.sqli` | Opens input dialog + renders report UI |
| `scylla.scanner.xss` | Opens input dialog + renders report UI |
| `scylla.scanner.lfi` | Opens input dialog + renders report UI |
| `scylla.scanner.ssti` | Opens input dialog + renders report UI |
| `scylla.scanner.secrets` | Opens input dialog + renders report UI |
| `scylla.scanner.cors` | Opens input dialog + renders report UI |
| `scylla.scanner.headers` | Opens input dialog + renders report UI |
| `scylla.scanner.domxss` | Opens input dialog + renders report UI |
| `scylla.scanner.params` | Opens input dialog + renders report UI |
| `scylla.scanner.redirect` | Opens input dialog + renders report UI |
| `scylla.scanner.jwt` | Opens input dialog + renders report UI |
| `scylla.scanner.graphql` | Opens input dialog + renders report UI |
| `scylla.scanner.ssrf` | Opens input dialog + renders report UI |
| `scylla.scanner.auto` | Opens input dialog + renders report UI |
| `scylla.scanner.sqliExtract` | Opens input dialog + renders report UI |
| `scylla.scanner.xssExploit` | Opens input dialog + renders report UI |
| `scylla.scanner.lfiExploit` | Opens input dialog + renders report UI |
| `scylla.reporting.generate` | Opens format picker + input dialog |
| `scylla.jobs.runJob` | Opens file picker / shows progress UI |

---

## Pipeline Execution Details

- Every step runs in headless mode (`quiet: true`) and receives the job `target` as both `url` and `target`.
- If a step does not define `output`, Scylla auto-generates output files inside `outDir` using the naming convention described above.
- Before each step, the runner resolves command aliases, checks the capability registry, and skips non-headless commands with a clear error.
- `scylla-pipeline.status.json` contains step-by-step results including `status`, `durationMs`, `attemptCount`, `outputPath`, and any `error`.
- `scylla-pipeline.log` contains timestamped execution logs.
- The pipeline runner replaces `${outDir}` and other template variables in all string-typed args before passing them to the command.

---

## HexCore Commands in Scylla Pipelines

The following HexCore commands are registered in the Scylla pipeline capability map and can be used in `.scylla_job.json` steps:

| Command | Timeout | Description |
|---------|---------|-------------|
| `hexcore.hashcalc.calculate` | 30s | Compute MD5, SHA1, SHA256, SHA512 hashes. |
| `hexcore.strings.extract` | 60s | Extract ASCII/Unicode strings with categorization. |
| `hexcore.base64.decodeHeadless` | 30s | Detect and decode Base64 strings. |
| `hexcore.yara.scan` | 120s | YARA rule scanning with threat scoring. |

---

## Troubleshooting

### `Command '...' not found`
- Confirm you are running a Scylla build (not vanilla VS Code).
- Run `scylla.jobs.listCapabilitiesHeadless` and confirm the command appears.
- Reload the window after extension updates.

### `Unknown command "..."`
- Use the exact command name from the capability registry or the alias table above.
- Run `scylla.jobs.doctor` to see all registered commands.

### `Step timed out after ...`
- Increase `timeoutMs` for the step.
- For large targets, increase `maxPages` on crawl and reduce scanner scope.
- Port scans against `1-65535` can take several minutes -- use `top1000` for quick runs.

### `A "url" argument is required.`
- The pipeline passes the job-level `target` as both `url` and `target`. If you see this error, the `target` field may be missing or empty in the job file.

### `No parameters found in URL.`
- Scanners that test parameters (SQLi, XSS, LFI, SSTI, SSRF, redirect) need either:
  - URL query parameters (e.g., `http://target.com/page?id=1`), or
  - A `crawlResultFile` pointing to a crawl output with discovered parameters, or
  - A `parameters` array in the step args.

### Missing output file
- Check step status in `scylla-pipeline.status.json`.
- If the step failed or timed out, no output file is produced.
- Verify `continueOnError: true` on non-critical steps.

### `crawlResultFile` not found
- Verify the crawl step ran successfully before the scanner step.
- Verify the file path uses `${outDir}` and the correct step index.
- The crawl step index is 1-based: if crawl is step 3, the file is `03-scylla-recon-crawlheadless.json`.

### Pipeline runs overlap or queue
- Scylla serializes auto-triggered runs. If a run is active, subsequent triggers queue and execute after completion.
- Manual runs via `scylla.jobs.runJob` will warn if a run is already active.
