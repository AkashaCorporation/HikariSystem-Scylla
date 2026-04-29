/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { ReportData } from './types';

/**
 * Convert a ReportData object into a standalone HTML document.
 * Uses inline CSS for a self-contained file (no external dependencies).
 */
export function renderHtmlReport(data: ReportData): string {
	const sections: string[] = [];

	// Executive Summary
	sections.push(renderExecutiveSummary(data));

	// Findings Table
	if (data.findings.length > 0) {
		sections.push(renderFindingsTable(data));
		sections.push(renderDetailedFindings(data));
	}

	// Recon Summary
	if (data.reconSummary) {
		sections.push(renderReconSummary(data));
	}

	// Timeline
	if (data.timeline.length > 0) {
		sections.push(renderTimeline(data));
	}

	return wrapHtml(data.title, data.generatedAt, data.target, sections.join('\n'));
}

// ---------------------------------------------------------------------------
// Section Renderers
// ---------------------------------------------------------------------------

function renderExecutiveSummary(data: ReportData): string {
	const { executiveSummary } = data;
	const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

	const badges = severityOrder
		.filter(s => (executiveSummary.bySeverity[s] ?? 0) > 0)
		.map(s => `<span class="badge badge-${s}">${capitalize(s)}: ${executiveSummary.bySeverity[s]}</span>`)
		.join(' ');

	return `
	<section class="section">
		<h2>Executive Summary</h2>
		<div class="summary-grid">
			<div class="summary-card">
				<div class="summary-value risk-${executiveSummary.riskLevel.toLowerCase()}">${esc(executiveSummary.riskLevel)}</div>
				<div class="summary-label">Overall Risk</div>
			</div>
			<div class="summary-card">
				<div class="summary-value">${executiveSummary.totalFindings}</div>
				<div class="summary-label">Total Findings</div>
			</div>
		</div>
		<div class="badges">${badges}</div>
	</section>`;
}

function renderFindingsTable(data: ReportData): string {
	const rows = data.findings.map((f, i) => `
		<tr>
			<td>${i + 1}</td>
			<td><span class="severity severity-${f.severity.toLowerCase()}">${capitalize(f.severity)}</span></td>
			<td>${esc(f.title)}</td>
			<td>${esc(f.status)}</td>
			<td><code>${esc(truncate(f.target, 50))}</code></td>
		</tr>`).join('');

	return `
	<section class="section">
		<h2>Findings Overview</h2>
		<table>
			<thead>
				<tr>
					<th>#</th>
					<th>Severity</th>
					<th>Title</th>
					<th>Status</th>
					<th>Target</th>
				</tr>
			</thead>
			<tbody>${rows}</tbody>
		</table>
	</section>`;
}

function renderDetailedFindings(data: ReportData): string {
	const findings = data.findings.map((f, i) => {
		const tags = f.tags.length > 0
			? `<div class="tags">${f.tags.map(t => `<span class="tag">${esc(t)}</span>`).join(' ')}</div>`
			: '';

		return `
		<div class="finding">
			<h3>${i + 1}. ${esc(f.title)}</h3>
			<div class="finding-meta">
				<span class="severity severity-${f.severity.toLowerCase()}">${capitalize(f.severity)}</span>
				<span class="meta-item"><strong>ID:</strong> ${esc(f.id)}</span>
				<span class="meta-item"><strong>Status:</strong> ${esc(f.status)}</span>
				<span class="meta-item"><strong>Target:</strong> <code>${esc(f.target)}</code></span>
			</div>
			${tags}
			${f.summary ? `<div class="finding-summary">${esc(f.summary)}</div>` : ''}
		</div>`;
	}).join('');

	return `
	<section class="section">
		<h2>Detailed Findings</h2>
		${findings}
	</section>`;
}

function renderReconSummary(data: ReportData): string {
	const r = data.reconSummary!;
	const techList = r.technologies.length > 0
		? r.technologies.map(t => `<span class="tag">${esc(t)}</span>`).join(' ')
		: '<em>None detected</em>';

	return `
	<section class="section">
		<h2>Reconnaissance Summary</h2>
		<div class="summary-grid">
			<div class="summary-card">
				<div class="summary-value">${r.openPorts}</div>
				<div class="summary-label">Open Ports</div>
			</div>
			<div class="summary-card">
				<div class="summary-value">${r.discoveredEndpoints}</div>
				<div class="summary-label">Endpoints</div>
			</div>
			<div class="summary-card">
				<div class="summary-value">${r.hiddenPaths}</div>
				<div class="summary-label">Hidden Paths</div>
			</div>
		</div>
		<div class="tech-list">
			<strong>Technologies:</strong> ${techList}
		</div>
	</section>`;
}

function renderTimeline(data: ReportData): string {
	const rows = data.timeline.map(e => `
		<tr>
			<td>${e.timestamp ? formatTimestamp(e.timestamp) : '-'}</td>
			<td>${esc(e.event)}</td>
			<td><span class="status status-${e.status}">${esc(e.status)}</span></td>
		</tr>`).join('');

	return `
	<section class="section">
		<h2>Pipeline Timeline</h2>
		<table>
			<thead>
				<tr><th>Timestamp</th><th>Event</th><th>Status</th></tr>
			</thead>
			<tbody>${rows}</tbody>
		</table>
	</section>`;
}

// ---------------------------------------------------------------------------
// HTML Wrapper
// ---------------------------------------------------------------------------

function wrapHtml(title: string, generatedAt: string, target: string, body: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<style>
:root {
	--bg: #0d1117;
	--surface: #161b22;
	--border: #30363d;
	--text: #c9d1d9;
	--text-muted: #8b949e;
	--accent: #58a6ff;
	--critical: #f85149;
	--high: #d29922;
	--medium: #e3b341;
	--low: #58a6ff;
	--info: #8b949e;
	--ok: #3fb950;
	--error: #f85149;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
	font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
	background: var(--bg);
	color: var(--text);
	line-height: 1.6;
	max-width: 1100px;
	margin: 0 auto;
	padding: 2rem;
}

h1 {
	font-size: 2rem;
	margin-bottom: 0.5rem;
	color: #fff;
}

h2 {
	font-size: 1.4rem;
	margin-bottom: 1rem;
	color: #fff;
	border-bottom: 1px solid var(--border);
	padding-bottom: 0.5rem;
}

h3 {
	font-size: 1.1rem;
	color: #fff;
	margin-bottom: 0.5rem;
}

.header {
	margin-bottom: 2rem;
	padding-bottom: 1rem;
	border-bottom: 2px solid var(--accent);
}

.header-meta {
	color: var(--text-muted);
	font-size: 0.9rem;
}

.header-meta code {
	color: var(--accent);
}

.section {
	background: var(--surface);
	border: 1px solid var(--border);
	border-radius: 6px;
	padding: 1.5rem;
	margin-bottom: 1.5rem;
}

.summary-grid {
	display: flex;
	gap: 1rem;
	margin-bottom: 1rem;
}

.summary-card {
	background: var(--bg);
	border: 1px solid var(--border);
	border-radius: 6px;
	padding: 1rem 1.5rem;
	text-align: center;
	flex: 1;
}

.summary-value {
	font-size: 1.8rem;
	font-weight: bold;
	color: #fff;
}

.summary-label {
	font-size: 0.85rem;
	color: var(--text-muted);
	margin-top: 0.25rem;
}

.risk-critical, .risk-Critical { color: var(--critical); }
.risk-high, .risk-High { color: var(--high); }
.risk-medium, .risk-Medium { color: var(--medium); }
.risk-low, .risk-Low { color: var(--low); }
.risk-informational, .risk-Informational { color: var(--info); }

table {
	width: 100%;
	border-collapse: collapse;
	font-size: 0.9rem;
}

th, td {
	text-align: left;
	padding: 0.6rem 0.8rem;
	border-bottom: 1px solid var(--border);
}

th {
	color: var(--text-muted);
	font-weight: 600;
	font-size: 0.8rem;
	text-transform: uppercase;
	letter-spacing: 0.05em;
}

tr:hover { background: rgba(88, 166, 255, 0.04); }

code {
	background: var(--bg);
	padding: 0.15em 0.4em;
	border-radius: 3px;
	font-size: 0.85em;
	font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
	color: var(--accent);
}

.severity {
	display: inline-block;
	padding: 0.15em 0.6em;
	border-radius: 3px;
	font-size: 0.8rem;
	font-weight: 600;
}

.severity-critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); }
.severity-high { background: rgba(210, 153, 34, 0.2); color: var(--high); }
.severity-medium { background: rgba(227, 179, 65, 0.2); color: var(--medium); }
.severity-low { background: rgba(88, 166, 255, 0.2); color: var(--low); }
.severity-info { background: rgba(139, 148, 158, 0.2); color: var(--info); }

.badge {
	display: inline-block;
	padding: 0.3em 0.8em;
	border-radius: 12px;
	font-size: 0.8rem;
	font-weight: 600;
	margin-right: 0.5rem;
}

.badge-critical { background: rgba(248, 81, 73, 0.15); color: var(--critical); border: 1px solid rgba(248, 81, 73, 0.3); }
.badge-high { background: rgba(210, 153, 34, 0.15); color: var(--high); border: 1px solid rgba(210, 153, 34, 0.3); }
.badge-medium { background: rgba(227, 179, 65, 0.15); color: var(--medium); border: 1px solid rgba(227, 179, 65, 0.3); }
.badge-low { background: rgba(88, 166, 255, 0.15); color: var(--low); border: 1px solid rgba(88, 166, 255, 0.3); }
.badge-info { background: rgba(139, 148, 158, 0.15); color: var(--info); border: 1px solid rgba(139, 148, 158, 0.3); }

.status-ok { color: var(--ok); }
.status-error { color: var(--error); }
.status-timeout { color: var(--medium); }
.status-skipped { color: var(--text-muted); }

.finding {
	background: var(--bg);
	border: 1px solid var(--border);
	border-radius: 6px;
	padding: 1rem 1.5rem;
	margin-bottom: 1rem;
}

.finding-meta {
	display: flex;
	flex-wrap: wrap;
	gap: 1rem;
	margin: 0.5rem 0;
	font-size: 0.85rem;
}

.meta-item { color: var(--text-muted); }

.finding-summary {
	margin-top: 0.75rem;
	padding-top: 0.75rem;
	border-top: 1px solid var(--border);
	white-space: pre-wrap;
}

.tags { margin-top: 0.5rem; }

.tag {
	display: inline-block;
	background: rgba(88, 166, 255, 0.1);
	color: var(--accent);
	padding: 0.15em 0.5em;
	border-radius: 3px;
	font-size: 0.8rem;
	margin-right: 0.3rem;
	margin-bottom: 0.3rem;
}

.tech-list { margin-top: 0.75rem; }

.footer {
	text-align: center;
	color: var(--text-muted);
	font-size: 0.8rem;
	margin-top: 2rem;
	padding-top: 1rem;
	border-top: 1px solid var(--border);
}

@media print {
	body { background: #fff; color: #1a1a1a; max-width: none; }
	.section { border-color: #ddd; background: #fff; }
	.summary-card { background: #f8f8f8; border-color: #ddd; }
	.summary-value { color: #1a1a1a; }
	.finding { background: #f8f8f8; }
	h1, h2, h3 { color: #1a1a1a; }
	code { background: #f0f0f0; color: #0366d6; }
}
</style>
</head>
<body>
	<div class="header">
		<h1>${esc(title)}</h1>
		<div class="header-meta">
			Generated: ${esc(generatedAt)} &bull; Target: <code>${esc(target)}</code>
		</div>
	</div>
${body}
	<div class="footer">
		Generated by Scylla Reporting Engine &bull; HikariSystem
	</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function esc(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

function capitalize(s: string): string {
	return s.charAt(0).toUpperCase() + s.slice(1);
}

function truncate(s: string, max: number): string {
	return s.length > max ? s.slice(0, max - 3) + '...' : s;
}

function formatTimestamp(iso: string): string {
	try {
		const d = new Date(iso);
		return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
	} catch {
		return iso;
	}
}
