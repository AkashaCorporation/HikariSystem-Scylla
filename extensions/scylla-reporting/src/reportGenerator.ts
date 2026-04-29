/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import type {
	ExecutiveSummary,
	FindingEntry,
	ReconSummary,
	ReportData,
	ReportGenerateCommandOptions,
	TimelineEntry,
} from './types';
import { loadFindings } from './findingsParser';
import {
	listJsonFiles,
	loadJsonFile,
	resolveFindingsDir,
	resolveOutputPath,
	resolveScanResultsDir,
	writeReport,
	writeReportData,
} from './artifacts';

// ---------------------------------------------------------------------------
// Report Generation
// ---------------------------------------------------------------------------

export interface GenerateResult {
	reportPath: string;
	dataPath: string;
	data: ReportData;
	markdown: string;
}

export function generateReport(options?: ReportGenerateCommandOptions): GenerateResult {
	const findingsDir = resolveFindingsDir(options);
	const scanResultsDir = resolveScanResultsDir(options);
	const outputPath = resolveOutputPath(options);

	// 1. Load findings
	const findings = loadFindings(findingsDir);

	// 2. Build executive summary
	const executiveSummary = buildExecutiveSummary(findings);

	// 3. Load recon summary from scan results
	const reconSummary = buildReconSummary(scanResultsDir);

	// 4. Build timeline from pipeline status
	const timeline = buildTimeline(scanResultsDir, options?.pipelineStatus);

	// 5. Determine target
	const target = findings[0]?.target || extractTargetFromPipeline(scanResultsDir) || 'Unknown';

	// 6. Assemble report data
	const data: ReportData = {
		generatedAt: new Date().toISOString(),
		title: options?.title ?? 'Scylla Penetration Test Report',
		target,
		executiveSummary,
		findings,
		reconSummary: reconSummary ?? undefined,
		timeline,
	};

	// 7. Render markdown
	const markdown = renderMarkdownReport(data);

	// 8. Write output
	writeReport(markdown, outputPath);
	const dataPath = outputPath.replace(/\.(md|html)$/, '.data.json');
	writeReportData(data, dataPath);

	return { reportPath: outputPath, dataPath, data, markdown };
}

// ---------------------------------------------------------------------------
// Executive Summary
// ---------------------------------------------------------------------------

function buildExecutiveSummary(findings: FindingEntry[]): ExecutiveSummary {
	const bySeverity: Record<string, number> = {};
	for (const f of findings) {
		bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
	}

	const riskLevel = determineRiskLevel(bySeverity);

	return {
		totalFindings: findings.length,
		bySeverity,
		riskLevel,
	};
}

function determineRiskLevel(bySeverity: Record<string, number>): string {
	if ((bySeverity['critical'] ?? 0) > 0) { return 'Critical'; }
	if ((bySeverity['high'] ?? 0) > 0) { return 'High'; }
	if ((bySeverity['medium'] ?? 0) > 0) { return 'Medium'; }
	if ((bySeverity['low'] ?? 0) > 0) { return 'Low'; }
	return 'Informational';
}

// ---------------------------------------------------------------------------
// Recon Summary
// ---------------------------------------------------------------------------

function buildReconSummary(scanResultsDir: string): ReconSummary | null {
	const files = listJsonFiles(scanResultsDir);
	if (files.length === 0) { return null; }

	let openPorts = 0;
	let discoveredEndpoints = 0;
	const technologies: string[] = [];
	let hiddenPaths = 0;

	for (const file of files) {
		const data = loadJsonFile<Record<string, unknown>>(file);
		if (!data) { continue; }
		const basename = path.basename(file).toLowerCase();

		// Port scan results
		if (basename.includes('portscan')) {
			const ports = data.openPorts ?? data.ports;
			if (Array.isArray(ports)) {
				openPorts += ports.length;
			}
		}

		// Crawl results
		if (basename.includes('crawl')) {
			const endpoints = data.endpoints ?? data.discoveredUrls ?? data.urls;
			if (Array.isArray(endpoints)) {
				discoveredEndpoints += endpoints.length;
			}
		}

		// Tech detect results
		if (basename.includes('techdetect') || basename.includes('tech')) {
			const techs = data.technologies ?? data.detected;
			if (Array.isArray(techs)) {
				for (const t of techs) {
					const name = typeof t === 'string' ? t : (t as Record<string, unknown>)?.name;
					if (typeof name === 'string' && !technologies.includes(name)) {
						technologies.push(name);
					}
				}
			}
		}

		// Dir fuzz results
		if (basename.includes('dirfuzz') || basename.includes('fuzz')) {
			const hits = data.hits ?? data.discovered ?? data.paths;
			if (Array.isArray(hits)) {
				hiddenPaths += hits.length;
			}
		}
	}

	if (openPorts === 0 && discoveredEndpoints === 0 && technologies.length === 0 && hiddenPaths === 0) {
		return null;
	}

	return { openPorts, discoveredEndpoints, technologies, hiddenPaths };
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

function buildTimeline(scanResultsDir: string, pipelineStatusPath?: string): TimelineEntry[] {
	const timeline: TimelineEntry[] = [];

	// Try to load pipeline status
	const statusPath = pipelineStatusPath
		?? path.join(scanResultsDir, 'scylla-pipeline.status.json');

	const status = loadJsonFile<Record<string, unknown>>(statusPath);
	if (status && Array.isArray(status.steps)) {
		for (const step of status.steps as Array<Record<string, unknown>>) {
			timeline.push({
				timestamp: (step.startedAt as string) ?? '',
				event: `${step.cmd ?? step.resolvedCmd ?? 'unknown'}`,
				status: (step.status as string) ?? 'unknown',
			});
		}

		if (status.startedAt) {
			timeline.unshift({
				timestamp: status.startedAt as string,
				event: 'Pipeline started',
				status: 'ok',
			});
		}
		if (status.finishedAt) {
			timeline.push({
				timestamp: status.finishedAt as string,
				event: `Pipeline finished (${status.status})`,
				status: (status.status as string) ?? 'unknown',
			});
		}
	}

	return timeline;
}

function extractTargetFromPipeline(scanResultsDir: string): string | null {
	const statusPath = path.join(scanResultsDir, 'scylla-pipeline.status.json');
	const status = loadJsonFile<Record<string, unknown>>(statusPath);
	if (status && typeof status.target === 'string') {
		return status.target;
	}
	return null;
}

// ---------------------------------------------------------------------------
// Markdown Renderer
// ---------------------------------------------------------------------------

function renderMarkdownReport(data: ReportData): string {
	const lines: string[] = [];

	// Title
	lines.push(`# ${data.title}`);
	lines.push('');
	lines.push(`**Generated:** ${data.generatedAt}`);
	lines.push(`**Target:** \`${data.target}\``);
	lines.push('');

	// Executive Summary
	lines.push('---');
	lines.push('');
	lines.push('## Executive Summary');
	lines.push('');
	lines.push(`**Overall Risk Level:** ${data.executiveSummary.riskLevel}`);
	lines.push(`**Total Findings:** ${data.executiveSummary.totalFindings}`);
	lines.push('');

	if (Object.keys(data.executiveSummary.bySeverity).length > 0) {
		lines.push('| Severity | Count |');
		lines.push('|----------|-------|');
		const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
		for (const sev of severityOrder) {
			const count = data.executiveSummary.bySeverity[sev];
			if (count && count > 0) {
				lines.push(`| ${severityIcon(sev)} ${capitalize(sev)} | ${count} |`);
			}
		}
		// Any others not in the standard order
		for (const [sev, count] of Object.entries(data.executiveSummary.bySeverity)) {
			if (!severityOrder.includes(sev) && count > 0) {
				lines.push(`| ${capitalize(sev)} | ${count} |`);
			}
		}
		lines.push('');
	}

	// Findings Table
	if (data.findings.length > 0) {
		lines.push('---');
		lines.push('');
		lines.push('## Findings Overview');
		lines.push('');
		lines.push('| # | Severity | Title | Status | Target |');
		lines.push('|---|----------|-------|--------|--------|');
		for (let i = 0; i < data.findings.length; i++) {
			const f = data.findings[i];
			lines.push(`| ${i + 1} | ${severityIcon(f.severity)} ${capitalize(f.severity)} | ${f.title} | ${f.status} | \`${truncate(f.target, 40)}\` |`);
		}
		lines.push('');

		// Detailed Findings
		lines.push('---');
		lines.push('');
		lines.push('## Detailed Findings');
		lines.push('');

		for (let i = 0; i < data.findings.length; i++) {
			const f = data.findings[i];
			lines.push(`### ${i + 1}. ${f.title}`);
			lines.push('');
			lines.push(`- **ID:** ${f.id}`);
			lines.push(`- **Severity:** ${severityIcon(f.severity)} ${capitalize(f.severity)}`);
			lines.push(`- **Status:** ${f.status}`);
			lines.push(`- **Target:** \`${f.target}\``);
			if (f.tags.length > 0) {
				lines.push(`- **Tags:** ${f.tags.map(t => `\`${t}\``).join(', ')}`);
			}
			lines.push('');
			if (f.summary) {
				lines.push(f.summary);
				lines.push('');
			}
		}
	}

	// Recon Summary
	if (data.reconSummary) {
		lines.push('---');
		lines.push('');
		lines.push('## Reconnaissance Summary');
		lines.push('');
		lines.push(`- **Open Ports:** ${data.reconSummary.openPorts}`);
		lines.push(`- **Discovered Endpoints:** ${data.reconSummary.discoveredEndpoints}`);
		lines.push(`- **Hidden Paths (Dir Fuzz):** ${data.reconSummary.hiddenPaths}`);
		if (data.reconSummary.technologies.length > 0) {
			lines.push(`- **Technologies:** ${data.reconSummary.technologies.join(', ')}`);
		}
		lines.push('');
	}

	// Timeline
	if (data.timeline.length > 0) {
		lines.push('---');
		lines.push('');
		lines.push('## Pipeline Timeline');
		lines.push('');
		lines.push('| Timestamp | Event | Status |');
		lines.push('|-----------|-------|--------|');
		for (const entry of data.timeline) {
			const ts = entry.timestamp ? formatTimestamp(entry.timestamp) : '-';
			lines.push(`| ${ts} | ${entry.event} | ${statusIcon(entry.status)} ${entry.status} |`);
		}
		lines.push('');
	}

	// Footer
	lines.push('---');
	lines.push('');
	lines.push('*Generated by Scylla Reporting Engine | HikariSystem*');
	lines.push('');

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityIcon(severity: string): string {
	switch (severity.toLowerCase()) {
		case 'critical': return '🔴';
		case 'high': return '🟠';
		case 'medium': return '🟡';
		case 'low': return '🔵';
		case 'info': return '⚪';
		default: return '⚪';
	}
}

function statusIcon(status: string): string {
	switch (status.toLowerCase()) {
		case 'ok': return '✅';
		case 'error': return '❌';
		case 'timeout': return '⏰';
		case 'skipped': return '⏭️';
		default: return '▶️';
	}
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
