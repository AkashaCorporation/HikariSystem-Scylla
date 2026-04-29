# Scylla 2.0 — "Hydra"

> **Codename:** Hydra
> **Focus:** Business Logic Exploitation, Authenticated Scanning, IDOR Discovery, API Attack Surface
> **Context:** Scylla 1.0.0 covers OWASP technical vulnerabilities (SQLi, XSS, LFI, SSTI, SSRF). Version 2.0 adds the vulnerability classes that **actually pay** in bug bounty: IDOR, broken access control, business logic flaws, and authentication bypass. These account for ~60% of bounty payouts on HackerOne/Bugcrowd but are ignored by every open-source scanner.

---

## What 1.0.0 Already Has (Foundation)

| Category | Commands | Status |
|----------|----------|--------|
| Recon | portscan, crawl, dirfuzz, techdetect, wafdetect | Complete |
| Injection | SQLi, XSS, LFI, SSTI | Complete |
| Config | CORS, headers, secrets, DOM XSS, open redirect | Complete |
| API | GraphQL, JWT | Complete |
| Exploitation | SQLi extract, XSS exploit, LFI exploit | Complete |
| Pipeline | Job automation, findings, reporting | Complete |
| Integration | HexCore hash/strings/base64/YARA | Complete |

---

## Milestone 1 — Authenticated Scanning (P0)

> Every serious bounty target requires login. Without auth, you only scan the login page.

### 1.1 Session Manager — `scylla.auth.*`

**Problem:** Current scanners send requests with a static `cookie` header. Real-world targets have CSRF tokens, session rotation, MFA, OAuth flows. When the session expires mid-scan, everything breaks silently.

**New commands:**

| Command | Description |
|---------|-------------|
| `scylla.auth.loginHeadless` | Automated login via form submission or API endpoint |
| `scylla.auth.oauthHeadless` | OAuth2 flow (authorization code, client credentials) |
| `scylla.auth.sessionCheckHeadless` | Verify session is still valid |
| `scylla.auth.sessionRefreshHeadless` | Re-authenticate when session expires |

**Implementation:**

```json
{
  "target": "https://app.example.com",
  "auth": {
    "type": "form",
    "loginUrl": "https://app.example.com/login",
    "fields": {
      "username": "testuser@example.com",
      "password": "testpass123"
    },
    "csrfSelector": "input[name='_token']",
    "successIndicator": "dashboard",
    "sessionCookie": "session_id"
  },
  "steps": [
    { "cmd": "scylla.auth.loginHeadless" },
    { "cmd": "scylla.recon.crawlHeadless", "args": { "maxDepth": 5 } },
    { "cmd": "scylla.scanner.sqliHeadless" }
  ]
}
```

**Session persistence:** After login, the session cookie is automatically injected into all subsequent requests. If a scanner detects a 401/403 response, it triggers `sessionRefreshHeadless` automatically.

**Multi-role scanning:** Support for multiple auth profiles to test horizontal/vertical privilege escalation:

```json
{
  "auth": {
    "profiles": {
      "admin": { "loginUrl": "...", "fields": { "username": "admin", "password": "..." } },
      "user": { "loginUrl": "...", "fields": { "username": "user1", "password": "..." } },
      "guest": { "type": "none" }
    }
  }
}
```

### 1.2 Cookie Jar & CSRF Token Auto-Refresh

- Persistent cookie jar across all pipeline steps
- Auto-extract CSRF tokens from HTML forms before each POST
- Support for custom token headers (`X-CSRF-Token`, `X-XSRF-TOKEN`)
- Session rotation detection: if `Set-Cookie` changes, update the jar

**Priority:** P0 — without this, nothing else in 2.0 works against real targets

---

## Milestone 2 — IDOR & Broken Access Control Scanner (P0)

> IDOR is the #1 paying vulnerability class in bug bounty. No scanner does it well because it requires understanding authorization context.

### 2.1 IDOR Scanner — `scylla.scanner.idorHeadless`

**What it does:**
1. Crawls the target while authenticated as User A
2. Extracts all endpoints with numeric/UUID identifiers in URL params, path, or body
3. Replaces each identifier with User B's identifier (or incremented/decremented values)
4. Compares responses: if User A gets User B's data, it's an IDOR

**Detection strategies:**

| Strategy | Description |
|----------|-------------|
| `sequential` | Replace `id=123` with `id=124`, `id=122` |
| `uuid-swap` | Replace UUID with another known UUID (from User B's session) |
| `zero-id` | Try `id=0`, `id=1`, `id=-1` |
| `remove-param` | Remove the ID parameter entirely |
| `method-swap` | Change GET to POST or vice versa |

**Args:**

```json
{
  "cmd": "scylla.scanner.idorHeadless",
  "args": {
    "crawlResultFile": "${outDir}/03-scylla-recon-crawlheadless.json",
    "profiles": ["admin", "user"],
    "strategies": ["sequential", "zero-id", "remove-param"],
    "compareFields": ["body_hash", "status_code", "content_length"],
    "sensitivePatterns": ["email", "phone", "address", "ssn", "credit_card"]
  }
}
```

**Output:** List of IDOR findings with request/response pairs, affected endpoint, and data exposure classification.

### 2.2 Privilege Escalation Scanner — `scylla.scanner.privescHeadless`

**What it does:**
1. Crawls as `admin` profile → collects all admin-only endpoints
2. Replays each admin-only request with `user` profile's session
3. If the `user` session can access admin endpoints → vertical privilege escalation

**Implementation:**

```json
{
  "cmd": "scylla.scanner.privescHeadless",
  "args": {
    "highPrivProfile": "admin",
    "lowPrivProfile": "user",
    "crawlResultFile": "${outDir}/admin-crawl.json"
  }
}
```

### 2.3 Mass Assignment Scanner — `scylla.scanner.massAssignHeadless`

**What it does:**
1. Finds endpoints that accept JSON/form data (registration, profile update, etc.)
2. Adds extra fields: `role=admin`, `is_admin=true`, `price=0`, `verified=true`
3. Checks if the server accepted the extra fields

**Common payloads:**
- `{"role": "admin"}`, `{"isAdmin": true}`, `{"is_staff": 1}`
- `{"price": 0}`, `{"discount": 100}`, `{"amount": -1}`
- `{"verified": true}`, `{"email_verified": true}`
- `{"password": "newpass"}` (on profile endpoints without current password check)

**Priority:** P0 — IDOR + privesc + mass assignment = the trifecta that pays $500-$15,000 per finding

---

## Milestone 3 — API Attack Surface (P1)

> Modern apps are API-first. The API often exposes more than the UI.

### 3.1 API Schema Discovery — `scylla.recon.apiDiscoverHeadless`

**What it does:**
1. Probe common paths: `/api/v1/`, `/swagger.json`, `/openapi.yaml`, `/graphql`, `/.well-known/`
2. If OpenAPI/Swagger found: parse all endpoints, methods, parameters
3. Compare documented endpoints vs discovered endpoints (from crawl)
4. Flag undocumented endpoints as potential shadow API

**Output:**
```json
{
  "documentedEndpoints": 45,
  "discoveredEndpoints": 52,
  "undocumentedEndpoints": [
    { "path": "/api/v1/admin/users", "method": "GET", "source": "js-analysis" },
    { "path": "/api/internal/debug", "method": "GET", "source": "dirfuzz" }
  ]
}
```

### 3.2 API Fuzzer — `scylla.scanner.apiFuzzHeadless`

**What it does:**
- Takes an OpenAPI spec or endpoint list
- Fuzzes each parameter with type-specific payloads:
  - Integers: `0`, `-1`, `MAX_INT`, `null`
  - Strings: empty, very long, special chars, format strings
  - Booleans: `true`, `false`, `null`, `"true"`, `1`
  - Arrays: empty, single element, 10000 elements
  - Objects: nested, recursive, missing required fields

### 3.3 Rate Limit Tester — `scylla.scanner.rateLimitHeadless`

**What it does:**
- Tests if sensitive endpoints (login, password reset, OTP verify, API key generation) have rate limiting
- Sends N requests in M seconds and checks for 429 or blocking
- Reports: no rate limit = vulnerability (account takeover via brute force)

**Args:**
```json
{
  "cmd": "scylla.scanner.rateLimitHeadless",
  "args": {
    "endpoints": [
      { "url": "/api/login", "method": "POST", "body": {"email": "test@test.com", "password": "wrong"} },
      { "url": "/api/forgot-password", "method": "POST", "body": {"email": "test@test.com"} }
    ],
    "requestCount": 50,
    "windowSeconds": 10
  }
}
```

### 3.4 REST/GraphQL Introspection Deep Scan

Expand the existing GraphQL scanner:
- Full schema extraction via introspection
- Identify mutations that modify sensitive data
- Test mutations without authentication
- Detect batch query attacks (resource exhaustion)
- Field-level authorization testing (can user query admin-only fields?)

**Priority:** P1 — APIs are where the bugs are in modern apps

---

## Milestone 4 — Business Logic Scanner (P1)

> The bugs that pay $5,000-$50,000. No tool does this because it requires understanding application context.

### 4.1 Workflow Bypass Scanner — `scylla.scanner.workflowHeadless`

**What it does:**
- Records a multi-step flow (e.g., checkout: add to cart → enter address → payment → confirm)
- Replays skipping steps (e.g., go directly from add to cart to confirm)
- Tests if the server enforces step order

**Configuration:**
```json
{
  "cmd": "scylla.scanner.workflowHeadless",
  "args": {
    "steps": [
      { "name": "add_to_cart", "url": "/api/cart/add", "method": "POST", "body": {"item_id": 1} },
      { "name": "checkout", "url": "/api/checkout", "method": "POST", "body": {} },
      { "name": "payment", "url": "/api/payment", "method": "POST", "body": {"card": "4111..."} },
      { "name": "confirm", "url": "/api/order/confirm", "method": "POST", "body": {} }
    ],
    "skipTests": [[0, 2], [0, 3], [1, 3]]
  }
}
```

### 4.2 Price/Quantity Manipulation — `scylla.scanner.priceManipHeadless`

**What it does:**
- Intercepts requests that contain price/quantity/amount fields
- Modifies values: `price=0`, `quantity=-1`, `discount=100`, `amount=0.01`
- Checks if the server accepts the modified values

### 4.3 Race Condition Tester — `scylla.scanner.raceHeadless`

**What it does:**
- Sends the same request N times concurrently (e.g., "redeem coupon")
- Checks if the action executed more than once
- Common targets: coupon redemption, money transfer, vote submission, like/follow

**Args:**
```json
{
  "cmd": "scylla.scanner.raceHeadless",
  "args": {
    "url": "/api/coupon/redeem",
    "method": "POST",
    "body": { "code": "SAVE50" },
    "concurrency": 20,
    "successIndicator": "Coupon applied"
  }
}
```

**Priority:** P1 — these are the bugs that get $10K+ bounties

---

## Milestone 5 — Intelligence & Automation (P2)

### 5.1 Subdomain Takeover Scanner — `scylla.scanner.subdomainTakeoverHeadless`

- Check CNAME records for dangling references
- Test common providers: AWS S3, GitHub Pages, Heroku, Shopify, Azure, etc.
- Verify takeover by attempting to claim the resource

### 5.2 JavaScript Analysis Engine — `scylla.scanner.jsAnalysisHeadless`

Expand DOM XSS scanner into full JS analysis:
- Extract API endpoints from JavaScript bundles
- Find hardcoded secrets (AWS keys, API tokens, Firebase configs)
- Identify client-side routing (React/Angular/Vue routes)
- Extract WebSocket endpoints
- Find postMessage handlers (potential XSS via message injection)

### 5.3 Nuclei Integration Enhancement

Current: 6000+ templates via external nuclei binary.
Enhancement:
- Native TypeScript nuclei template runner (no external dependency)
- Custom template creation from Scylla findings
- Auto-generate nuclei templates from confirmed vulnerabilities

### 5.4 Smart Scope Manager

**Problem:** Testers accidentally go out of scope.

**Solution:**
```json
{
  "scope": {
    "include": ["*.target.com", "api.target.com"],
    "exclude": ["admin.target.com", "*.third-party.com"],
    "rateLimit": { "requestsPerSecond": 5 },
    "allowedMethods": ["GET", "POST"],
    "maxDepth": 5
  }
}
```

All commands check scope before sending requests. Violations are blocked and logged.

**Priority:** P2 — quality of life and safety

---

## Milestone 6 — Reporting & Integration (P2)

### 6.1 Bounty Platform Report Generator

Auto-format findings for specific platforms:
- **HackerOne** format (severity, impact, reproduction steps, PoC)
- **Bugcrowd** format (VRT taxonomy, priority)
- **Intigriti** format (CVSS, endpoint, type)

```json
{
  "cmd": "scylla.reporting.generateHeadless",
  "args": {
    "format": "hackerone",
    "finding": "IDOR-001"
  }
}
```

### 6.2 Diff Scanner — What Changed Since Last Scan

- Compare current scan results with previous scan
- Highlight: new endpoints, removed endpoints, changed responses
- Useful for continuous monitoring of bounty targets

### 6.3 Evidence Collector

- Auto-capture request/response pairs for each finding
- Screenshot pages with vulnerabilities (via Playwright)
- Generate video-like step-by-step evidence (HTML slideshow)

---

## Milestone 7 — Mobile App Analysis (P2) — HexCore Bridge

> This is where Scylla meets HexCore. Use HexCore to reverse the mobile app, feed endpoints to Scylla.

### 7.1 APK Endpoint Extractor — `scylla.mobile.apkAnalyzeHeadless`

**What it does:**
1. Decompile APK (via `apktool` or `jadx`)
2. Extract all URLs/endpoints from smali/Java code
3. Extract hardcoded API keys, secrets, Firebase configs
4. Feed discovered endpoints into Scylla crawler/scanner pipeline

### 7.2 Certificate Pinning Bypass Detector

- Analyze APK for certificate pinning implementation
- Report: OkHttp pinning, custom TrustManager, Network Security Config
- Suggest bypass method (Frida script, Magisk module)

### 7.3 Deep Link Analyzer

- Extract all deep links / intent filters from AndroidManifest.xml
- Test for deep link hijacking (can another app intercept?)
- Test for authentication bypass via deep link

**Priority:** P2 — bridges HexCore (binary analysis) with Scylla (web testing)

---

## Pipeline Presets — New in 2.0

### Preset: `bug-bounty-full`

```json
{
  "target": "https://target.example.com",
  "preset": "bug-bounty-full",
  "auth": { "type": "form", "loginUrl": "...", "fields": { ... } },
  "steps": [
    { "cmd": "scylla.auth.loginHeadless" },
    { "cmd": "scylla.recon.techdetectHeadless" },
    { "cmd": "scylla.recon.wafdetectHeadless" },
    { "cmd": "scylla.recon.crawlHeadless", "args": { "maxDepth": 5, "maxPages": 500 } },
    { "cmd": "scylla.recon.dirfuzzHeadless" },
    { "cmd": "scylla.recon.apiDiscoverHeadless" },
    { "cmd": "scylla.scanner.idorHeadless" },
    { "cmd": "scylla.scanner.privescHeadless" },
    { "cmd": "scylla.scanner.sqliHeadless", "continueOnError": true },
    { "cmd": "scylla.scanner.xssHeadless", "continueOnError": true },
    { "cmd": "scylla.scanner.ssrfHeadless", "continueOnError": true },
    { "cmd": "scylla.scanner.massAssignHeadless", "continueOnError": true },
    { "cmd": "scylla.scanner.rateLimitHeadless" },
    { "cmd": "scylla.scanner.secretsHeadless", "args": { "verify": true } },
    { "cmd": "scylla.scanner.jwtHeadless" },
    { "cmd": "scylla.reporting.generateHeadless", "args": { "format": "hackerone" } }
  ]
}
```

### Preset: `api-pentest`

```json
{
  "preset": "api-pentest",
  "steps": [
    { "cmd": "scylla.auth.loginHeadless" },
    { "cmd": "scylla.recon.apiDiscoverHeadless" },
    { "cmd": "scylla.scanner.idorHeadless" },
    { "cmd": "scylla.scanner.apiFuzzHeadless" },
    { "cmd": "scylla.scanner.rateLimitHeadless" },
    { "cmd": "scylla.scanner.massAssignHeadless" },
    { "cmd": "scylla.scanner.graphqlHeadless" },
    { "cmd": "scylla.scanner.jwtHeadless" },
    { "cmd": "scylla.reporting.generateHeadless" }
  ]
}
```

---

## Priority Matrix

| # | Feature | Priority | Effort | Bounty Impact |
|---|---------|----------|--------|--------------|
| 1.1 | Session Manager / Auth | **P0** | Medium | Enables everything else |
| 2.1 | IDOR Scanner | **P0** | High | $500-$15,000 per finding |
| 2.2 | Privilege Escalation | **P0** | Medium | $1,000-$10,000 per finding |
| 2.3 | Mass Assignment | **P0** | Low | $500-$5,000 per finding |
| 3.3 | Rate Limit Tester | **P1** | Low | $200-$2,000 per finding |
| 4.1 | Workflow Bypass | **P1** | Medium | $5,000-$50,000 per finding |
| 4.3 | Race Condition Tester | **P1** | Low | $1,000-$10,000 per finding |
| 3.1 | API Schema Discovery | **P1** | Medium | Enables better scanning |
| 3.2 | API Fuzzer | **P1** | Medium | $500-$5,000 per finding |
| 5.4 | Scope Manager | **P2** | Low | Safety / compliance |
| 5.2 | JS Analysis Engine | **P2** | Medium | Endpoint discovery |
| 6.1 | Bounty Report Generator | **P2** | Low | Time savings |
| 7.1 | APK Endpoint Extractor | **P2** | Medium | HexCore bridge |
| 4.2 | Price Manipulation | **P2** | Low | $1,000-$5,000 per finding |
| 5.1 | Subdomain Takeover | **P2** | Low | $200-$1,000 per finding |
| 6.2 | Diff Scanner | **P2** | Medium | Continuous monitoring |

---

## Open vs Closed Source Decision

**Recommendation: Closed Source for Scylla**

| Factor | HexCore (Open) | Scylla (Closed) |
|--------|---------------|-----------------|
| **Competition** | Decompiler MLIR = zero competitors | Web scanners = hundreds of clones |
| **Value** | Academic (papers, community) | Commercial (tool advantage) |
| **Copying risk** | Low (niche, complex C++) | High (TypeScript, easy to fork) |
| **Revenue model** | GitHub sponsors / reputation | SaaS or license |
| **Community benefit** | RE researchers use it | Bounty hunters would just copy it |

If you open source Scylla, within 6 months there will be 10 forks with your IDOR scanner. Keep it closed, sell access or use it as your competitive advantage.

Alternative: **Open source Scylla 1.0** (what exists now — basic scanners) and keep **2.0 features closed** (IDOR, auth, business logic). The 1.0 builds community, the 2.0 is your edge.

---

## Technical Notes

- All 2.0 commands must support headless mode (pipeline-safe)
- Auth state persists across pipeline steps via shared cookie jar
- Multi-profile auth uses named profiles referenced in scanner args
- IDOR/privesc scanners require at least 2 auth profiles configured
- Rate limit: respect target's rate limits AND platform rules
- All scanners check scope before sending requests (Milestone 5.4)
- Findings from 2.0 scanners use same findings store as 1.0
- Report generator supports 1.0 + 2.0 findings together
