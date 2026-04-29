# Scylla Findings

Scylla Findings is the first file-backed findings workflow for HikariSystem Scylla.

Current capabilities:

- create finding markdown files under `.scylla/findings/`
- append evidence blocks headlessly
- generate a finding directly from a Scylla HTTP response artifact
- keep the workflow simple enough for UI, automation, and future job execution

Commands:

- `scylla.findings.create`
- `scylla.findings.createHeadless`
- `scylla.findings.appendEvidenceHeadless`
- `scylla.findings.createFromHttpHeadless`

This extension is intentionally function-first. If Scylla later needs a richer findings core or database-backed engine, the command contract can stay stable while the implementation moves behind it.
