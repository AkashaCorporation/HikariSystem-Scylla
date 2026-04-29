# Scylla HTTP

Scylla HTTP is the first function-first HTTP workflow for HikariSystem Scylla.

Current capabilities:

- create request definition files under `.scylla/http/requests/`
- send requests from saved Scylla request files or inline arguments
- persist response artifacts under `.scylla/http/responses/`
- return structured headless results for automation and future job runners

Commands:

- `scylla.http.createRequest`
- `scylla.http.send`
- `scylla.http.sendHeadless`
- `scylla.http.saveRequestHeadless`
- `scylla.http.replayHeadless`

Request format:

```json
{
  "name": "login-check",
  "method": "POST",
  "url": "https://target.tld/api/login",
  "headers": {
    "content-type": "application/json"
  },
  "body": "{\"username\":\"admin\",\"password\":\"admin\"}",
  "timeoutMs": 15000,
  "followRedirects": true
}
```

This extension is intentionally function-first. If the HTTP layer needs a dedicated core or engine later, the command contract can stay stable while the implementation moves behind it.
