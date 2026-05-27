# Scylla Job Templates

Ready-to-use `.scylla_job.json` templates for AI agents and automated pipelines. Place the JSON in `.scylla_job.json` at the workspace root -- Scylla will detect and execute it automatically.

## Rules

- Replace `https://target.example.com` with the actual target URL or IP.
- All `crawlResultFile` references use `${outDir}` and the correct 1-based, zero-padded step index.
- Auto-generated output filenames follow the pattern: `{padded-index}-{command-dashed}.json`.
- Use `continueOnError: true` on scanner steps so one failure does not abort the pipeline.
- See `docs/SCYLLA_AUTOMATION.md` for the full command reference and argument details.

---

## Template 1: Quick Recon (~2min)

Fast reconnaissance: port scan, technology detection, and WAF detection. No crawling or scanning. Good for a first look at a target before committing to a full pipeline.

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.portscanHeadless",
      "args": { "target": "${target}", "ports": "top1000" },
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.recon.techdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.recon.wafdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    }
  ]
}
```

**Output files:**
- `01-scylla-recon-portscanheadless.json` -- Open ports with service/banner info.
- `02-scylla-recon-techdetectheadless.json` -- Detected technologies, versions, confidence.
- `03-scylla-recon-wafdetectheadless.json` -- WAF name, evidence, bypass suggestions.

---

## Template 2: Full Recon (~10min)

Comprehensive reconnaissance: port scan, technology detection, WAF detection, web crawling, and directory fuzzing. Produces a full endpoint map.

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.portscanHeadless",
      "args": { "target": "${target}", "ports": "top1000" },
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.recon.techdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.recon.wafdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 3, "maxPages": 300, "scope": "host" },
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.recon.dirfuzzHeadless",
      "args": { "url": "${target}", "wordlist": "common", "extensions": [".php", ".html", ".txt", ".bak"] },
      "timeoutMs": 600000
    }
  ]
}
```

**Output files:**
- `01-scylla-recon-portscanheadless.json`
- `02-scylla-recon-techdetectheadless.json`
- `03-scylla-recon-wafdetectheadless.json`
- `04-scylla-recon-crawlheadless.json` -- Discovered pages, forms, parameters, JS routes.
- `05-scylla-recon-dirfuzzheadless.json` -- Discovered paths with status codes.

---

## Template 3: Full Pentest Pipeline (~20min)

End-to-end pipeline: full recon, all scanners against crawl results, and a final report. The most comprehensive template.

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.portscanHeadless",
      "args": { "target": "${target}", "ports": "top1000" },
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.recon.techdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.recon.wafdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 3, "maxPages": 500, "scope": "host" },
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.recon.dirfuzzHeadless",
      "args": { "url": "${target}", "wordlist": "common", "extensions": [".php", ".html", ".txt", ".bak"] },
      "timeoutMs": 600000
    },
    {
      "cmd": "scylla.scanner.sqliHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.xssHeadless",
      "args": { 
        "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", 
        "createFindings": true,
        "rateLimitRetryBaseMs": 1000,
        "maxRetries": 5
      },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.lfiHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.sstiHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.secretsHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.corsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.headersHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.domxssHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.paramsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.redirectHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.ssrfHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.reporting.generateHeadless",
      "args": { "title": "Full Penetration Test Report" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- The crawl step is step 4 (1-based), so `crawlResultFile` references `04-scylla-recon-crawlheadless.json`.
- All scanner steps use `continueOnError: true` so one scanner failure does not abort the rest.
- Scanners that do not use parameters (CORS, headers, DOM XSS, params) receive `url` from the job-level `target`.
- The XSS scanner (`scylla.scanner.xssHeadless`) is powered by the **Dalfox Heuristics Engine**, ensuring robust AST/DOM evasion and polyglot context detection.
- The final report aggregates all findings from all scanners.

---

## Template 4: Web App Assessment (~15min)

Focused web application vulnerability assessment: crawl, directory fuzzing, injection scanners, configuration checks, secrets scan, and report. No port scanning.

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 4, "maxPages": 500, "scope": "host" },
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.recon.dirfuzzHeadless",
      "args": { "url": "${target}", "wordlist": "common", "extensions": [".php", ".html", ".js", ".bak"] },
      "timeoutMs": 600000
    },
    {
      "cmd": "scylla.scanner.sqliHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.xssHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.lfiHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.sstiHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.corsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.headersHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.secretsHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.reporting.generateHeadless",
      "args": { "title": "Web Application Assessment" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- The crawl step is step 1, so `crawlResultFile` references `01-scylla-recon-crawlheadless.json`.
- Covers the OWASP Top 10 injection categories plus configuration issues.

---

## Template 5: API Security Audit (~10min)

Targeted at REST/GraphQL APIs: crawl for endpoints, GraphQL introspection, CORS, security headers, JWT analysis, SSRF, and secrets detection.

```json
{
  "target": "https://api.target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 2, "maxPages": 200, "scope": "host" },
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.graphqlHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.corsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.headersHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.jwtHeadless",
      "args": { "token": "REPLACE_WITH_JWT_TOKEN", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 60000
    },
    {
      "cmd": "scylla.scanner.ssrfHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.secretsHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.reporting.generateHeadless",
      "args": { "title": "API Security Audit" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- Replace `REPLACE_WITH_JWT_TOKEN` with an actual JWT token if you have one. If no JWT is available, remove the JWT step or set `continueOnError: true` (already set).
- The crawl step is step 1, so `crawlResultFile` references `01-scylla-recon-crawlheadless.json`.
- GraphQL scanner tests introspection, injection, batching, and field enumeration.

---

## Template 6: Bug Bounty Quick Scan (~5min)

Rapid scan for the highest-impact vulnerabilities: crawl, SQLi, XSS, secrets, CORS, and report. Designed for speed over completeness.

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 2, "maxPages": 100, "scope": "host" },
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.sqliHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 180000
    },
    {
      "cmd": "scylla.scanner.xssHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 180000
    },
    {
      "cmd": "scylla.scanner.secretsHeadless",
      "args": { "crawlResultFile": "${outDir}/01-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.corsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.reporting.generateHeadless",
      "args": { "title": "Bug Bounty Quick Scan" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- Uses shallow crawl (`maxDepth: 2`, `maxPages: 100`) for speed.
- Focuses on SQLi, XSS, secrets, and CORS -- the most common bug bounty findings.
- The crawl step is step 1, so `crawlResultFile` references `01-scylla-recon-crawlheadless.json`.

---

## Template 7: Infrastructure Audit (~5min)

Network-level assessment: port scanning, technology fingerprinting, WAF detection, and security headers. No crawling or injection scanning.

```json
{
  "target": "https://target.example.com",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.portscanHeadless",
      "args": { "target": "${target}", "ports": "top1000" },
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.recon.techdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.recon.wafdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.headersHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    }
  ]
}
```

**Notes:**
- Lightweight audit -- identifies open services, technology stack, WAF presence, and security header gaps.
- No report generation step; read individual output files directly.
- Add `scylla.reporting.generateHeadless` as a final step if you want a unified report.

---

## Template 8: HTB Machine (~15min)

Full pipeline targeting a HackTheBox machine IP. Recon, crawl, directory fuzzing, all major scanners, and a final report.

```json
{
  "target": "http://10.10.10.100",
  "outDir": ".scylla/pipeline-output",
  "quiet": true,
  "steps": [
    {
      "cmd": "scylla.recon.portscanHeadless",
      "args": { "target": "${target}", "ports": "top1000" },
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.recon.techdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000,
      "continueOnError": true
    },
    {
      "cmd": "scylla.recon.wafdetectHeadless",
      "args": { "url": "${target}" },
      "timeoutMs": 30000,
      "continueOnError": true
    },
    {
      "cmd": "scylla.recon.crawlHeadless",
      "args": { "url": "${target}", "maxDepth": 3, "maxPages": 500, "scope": "host" },
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.recon.dirfuzzHeadless",
      "args": { "url": "${target}", "wordlist": "common", "extensions": [".php", ".html", ".txt", ".bak", ".old", ".conf"] },
      "timeoutMs": 600000
    },
    {
      "cmd": "scylla.scanner.sqliHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.xssHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.lfiHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.sstiHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.secretsHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.corsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.headersHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 30000
    },
    {
      "cmd": "scylla.scanner.domxssHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.paramsHeadless",
      "args": { "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.scanner.redirectHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 120000
    },
    {
      "cmd": "scylla.scanner.ssrfHeadless",
      "args": { "crawlResultFile": "${outDir}/04-scylla-recon-crawlheadless.json", "createFindings": true },
      "continueOnError": true,
      "timeoutMs": 300000
    },
    {
      "cmd": "scylla.reporting.generateHeadless",
      "args": { "title": "HTB Machine Assessment" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- Uses HTTP (not HTTPS) since most HTB machines serve on plain HTTP.
- Replace `10.10.10.100` with the actual HTB machine IP.
- The crawl step is step 4, so `crawlResultFile` references `04-scylla-recon-crawlheadless.json`.
- Tech detect and WAF detect have `continueOnError: true` since some HTB machines may not respond to fingerprinting probes.
- Directory fuzzing includes extra extensions (`.old`, `.conf`) common in CTF environments.
- All scanners run with `createFindings: true` so the final report includes all discovered vulnerabilities.

---

## Troubleshooting

- **`No .scylla_job.json file was found.`** -- Ensure the file exists in the workspace root opened in Scylla.
- **`timed out after ...`** -- Increase `timeoutMs` for the step. Reduce `maxPages` on crawl for large sites.
- **Missing output file** -- Confirm step status is `ok` in `scylla-pipeline.status.json`. Failed/timed-out steps do not produce output.
- **`Command is not headless-safe`** -- The command requires UI interaction. Use the `Headless` variant from `docs/SCYLLA_AUTOMATION.md`.
- **Wrong `crawlResultFile` path** -- Count the crawl step's 1-based index and use that zero-padded number in the filename. Example: step 4 = `04-scylla-recon-crawlheadless.json`.
- **`Unknown command "..."`** -- Validate the job file with `scylla.jobs.validateJobHeadless`. Check the alias and command tables in `docs/SCYLLA_AUTOMATION.md`.
