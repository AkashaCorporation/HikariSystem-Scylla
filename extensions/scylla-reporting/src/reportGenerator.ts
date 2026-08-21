/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import type {
	AuthorizationSummary,
	EngagementSummary,
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
	resolveAuthorizationMatrixFile,
	resolveEngagementFile,
	resolveFindingsDir,
	resolvePipelineStatusPath,
	resolveReportPaths,
	resolveScanResultsDir,
	writeReport,
	writeReportData,
} from './artifacts';
import { renderHtmlReport } from './htmlRenderer';

export interface GenerateResult {
	reportPath: string;
	markdownPath: string;
	htmlPath: string;
	dataPath: string;
	data: ReportData;
	markdown: string;
}

export function generateReport(options?: ReportGenerateCommandOptions): GenerateResult {
	const findingsDir = resolveFindingsDir(options);
	const scanResultsDir = resolveScanResultsDir(options);
	const paths = resolveReportPaths(options);
	const records = loadFindings(findingsDir);
	const findings = records.filter(record => record.classification === 'validated');
	const candidates = records.filter(record => record.classification === 'candidate');
	const observations = records.filter(record => record.classification === 'observation');
	const executiveSummary = buildExecutiveSummary(records, findings, candidates, observations);
	const reconSummary = buildReconSummary(scanResultsDir);
	const engagementSummary = buildEngagementSummary(resolveEngagementFile(options));
	const authorizationSummary = buildAuthorizationSummary(
		resolveAuthorizationMatrixFile(options, scanResultsDir),
	);
	const pipelineStatusPath = resolvePipelineStatusPath(scanResultsDir, options?.pipelineStatus);
	const timeline = buildTimeline(pipelineStatusPath);
	const target = determineTarget(records, scanResultsDir, engagementSummary);

	const data: ReportData = {
		generatedAt: new Date().toISOString(),
		title: options?.title ?? 'Scylla Security Assessment Report',
		target,
		executiveSummary,
		records,
		findings,
		candidates,
		observations,
		reconSummary: reconSummary ?? undefined,
		engagementSummary,
		authorizationSummary,
		timeline,
	};

	const markdown = renderMarkdownReport(data, options);
	const html = renderHtmlReport(data, options);
	writeReport(markdown, paths.markdownPath);
	writeReport(html, paths.htmlPath);
	writeReportData(data, paths.dataPath);

	return {
		reportPath: paths.primaryPath,
		markdownPath: paths.markdownPath,
		htmlPath: paths.htmlPath,
		dataPath: paths.dataPath,
		data,
		markdown,
	};
}

function buildExecutiveSummary(
	records: FindingEntry[],
	findings: FindingEntry[],
	candidates: FindingEntry[],
	observations: FindingEntry[],
): ExecutiveSummary {
	const bySeverity = countBySeverity(findings);
	const candidateBySeverity = countBySeverity(candidates);
	return {
		totalFindings: findings.length,
		totalRecords: records.length,
		validatedFindings: findings.length,
		candidates: candidates.length,
		observations: observations.length,
		bySeverity,
		candidateBySeverity,
		riskLevel: determineRiskLevel(bySeverity, findings.length),
		riskBasis: 'validated-findings-only',
	};
}

function countBySeverity(findings: FindingEntry[]): Record<string, number> {
	const result: Record<string, number> = {};
	for (const finding of findings) {
		result[finding.severity] = (result[finding.severity] ?? 0) + 1;
	}
	return result;
}

function determineRiskLevel(bySeverity: Record<string, number>, totalValidated: number): string {
	if (totalValidated === 0) { return 'Not Established'; }
	if ((bySeverity.critical ?? 0) > 0) { return 'Critical'; }
	if ((bySeverity.high ?? 0) > 0) { return 'High'; }
	if ((bySeverity.medium ?? 0) > 0) { return 'Medium'; }
	if ((bySeverity.low ?? 0) > 0) { return 'Low'; }
	return 'Informational';
}

function buildReconSummary(scanResultsDir: string): ReconSummary | null {
	const files = listJsonFiles(scanResultsDir);
	if (files.length === 0) { return null; }

	const summary: ReconSummary = {
		openPorts: 0,
		pagesVisited: 0,
		discoveredEndpoints: 0,
		forms: 0,
		parameters: 0,
		javascriptRoutes: 0,
		hiddenPaths: 0,
		technologies: [],
	};

	for (const file of files) {
		const data = loadJsonFile<Record<string, unknown>>(file);
		if (!data) { continue; }
		const basename = path.basename(file).toLowerCase();

		if (basename.includes('portscan')) {
			const ports = data.openPorts ?? data.ports;
			if (Array.isArray(ports)) { summary.openPorts += ports.length; }
		}

		if (basename.includes('crawl')) {
			const endpoints = firstArray(data.discovered, data.endpoints, data.discoveredUrls, data.urls);
			if (endpoints) { summary.discoveredEndpoints += endpoints.length; }
			summary.pagesVisited = Math.max(summary.pagesVisited, asFiniteNumber(data.pagesVisited));
			const forms = firstArray(data.forms);
			const parameters = firstArray(data.parameters);
			const routes = firstArray(data.routeCandidates, data.jsRoutes);
			if (forms) { summary.forms += forms.length; }
			if (parameters) { summary.parameters += parameters.length; }
			if (routes) { summary.javascriptRoutes += routes.length; }
		}

		if (basename.includes('techdetect') || basename.includes('tech')) {
			const technologies = firstArray(data.technologies, data.detected);
			for (const entry of technologies ?? []) {
				const name = typeof entry === 'string' ? entry : asString((entry as Record<string, unknown>)?.name);
				if (name && !summary.technologies.includes(name)) { summary.technologies.push(name); }
			}
		}

		if (basename.includes('wafdetect')) {
			const detected = data.wafDetected === true;
			summary.waf = {
				detected,
				name: asString(data.wafName) || undefined,
				confidence: normalizeConfidence(data.confidence),
				mode: asString(data.mode) || asString(data.probeMode) || undefined,
			};
		}

		if (basename.includes('dirfuzz') || basename.includes('fuzz')) {
			const hits = firstArray(data.hits, data.discovered, data.paths);
			if (hits) { summary.hiddenPaths += hits.length; }
		}
	}

	if (summary.openPorts === 0 && summary.pagesVisited === 0 && summary.discoveredEndpoints === 0 &&
		summary.forms === 0 && summary.parameters === 0 && summary.javascriptRoutes === 0 &&
		summary.hiddenPaths === 0 && summary.technologies.length === 0 && !summary.waf) {
		return null;
	}
	return summary;
}

function buildEngagementSummary(filePath?: string): EngagementSummary | undefined {
	if (!filePath) { return undefined; }
	const data = loadJsonFile<Record<string, unknown>>(filePath);
	if (!data) { return undefined; }
	return {
		id: asString(data.id) || path.basename(filePath, '.json'),
		name: asString(data.name) || 'Unnamed Engagement',
		targets: asStringArray(data.targets),
		scope: asStringArray(data.scope),
		identities: firstArray(data.identities)?.length ?? 0,
		resources: firstArray(data.resources)?.length ?? 0,
		transactions: firstArray(data.transactions)?.length ?? 0,
		filePath,
	};
}

function buildAuthorizationSummary(filePath?: string): AuthorizationSummary | undefined {
	if (!filePath) { return undefined; }
	const data = loadJsonFile<Record<string, unknown>>(filePath);
	if (!data) { return undefined; }
	return {
		engagementId: asString(data.engagementId) || undefined,
		identities: firstArray(data.identities)?.length ?? 0,
		resources: firstArray(data.resources)?.length ?? 0,
		cells: firstArray(data.cells)?.length ?? 0,
		mismatches: firstArray(data.mismatches)?.length ?? 0,
		filePath,
	};
}

function buildTimeline(pipelineStatusPath: string): TimelineEntry[] {
	const timeline: TimelineEntry[] = [];
	const status = loadJsonFile<Record<string, unknown>>(pipelineStatusPath);
	if (!status) { return timeline; }

	if (status.startedAt) {
		timeline.push({ timestamp: asString(status.startedAt), event: 'Pipeline started', status: 'ok' });
	}
	for (const step of firstArray(status.steps) ?? []) {
		const typed = step as Record<string, unknown>;
		timeline.push({
			timestamp: asString(typed.startedAt),
			event: asString(typed.cmd) || asString(typed.resolvedCmd) || 'unknown',
			status: asString(typed.status) || 'unknown',
			durationMs: asFiniteNumber(typed.durationMs) || undefined,
		});
	}
	if (status.finishedAt) {
		timeline.push({
			timestamp: asString(status.finishedAt),
			event: `Pipeline finished (${asString(status.status) || 'unknown'})`,
			status: asString(status.status) || 'unknown',
		});
	}
	return timeline;
}

function determineTarget(records: FindingEntry[], scanResultsDir: string, engagement?: EngagementSummary): string {
	return records.find(record => record.target)?.target
		?? engagement?.targets[0]
		?? extractTargetFromPipeline(scanResultsDir)
		?? 'Unknown';
}

function extractTargetFromPipeline(scanResultsDir: string): string | null {
	const status = loadJsonFile<Record<string, unknown>>(path.join(scanResultsDir, 'scylla-pipeline.status.json'));
	return status && typeof status.target === 'string' ? status.target : null;
}

function renderMarkdownReport(data: ReportData, options?: ReportGenerateCommandOptions): string {
	const lines: string[] = [];
	lines.push(`# ${data.title}`, '');
	lines.push(`**Generated:** ${data.generatedAt}`);
	lines.push(`**Target:** \`${data.target}\``, '');
	lines.push('---', '', '## Executive Summary', '');
	lines.push(`**Overall Risk Level:** ${data.executiveSummary.riskLevel}`);
	lines.push('> Overall risk is derived from **validated findings only**. Candidates and observations are tracked separately and do not establish impact.', '');
	lines.push(`- **Validated findings:** ${data.executiveSummary.validatedFindings}`);
	lines.push(`- **Candidates requiring validation:** ${data.executiveSummary.candidates}`);
	lines.push(`- **Observations:** ${data.executiveSummary.observations}`);
	lines.push(`- **Total security records:** ${data.executiveSummary.totalRecords}`, '');

	appendSeverityTable(lines, 'Validated Findings by Severity', data.executiveSummary.bySeverity);
	appendSeverityTable(lines, 'Candidate Severity (Provisional)', data.executiveSummary.candidateBySeverity);

	appendRecordSection(lines, 'Validated Findings', data.findings, 'No validated findings were recorded.');
	if (options?.includeCandidates !== false) {
		appendRecordSection(lines, 'Candidates Requiring Validation', data.candidates,
			'No candidates are awaiting validation.', true);
	}
	if (options?.includeObservations !== false) {
		appendRecordSection(lines, 'Observations', data.observations, 'No standalone observations were recorded.', true);
	}

	if (data.engagementSummary || data.authorizationSummary) {
		lines.push('---', '', '## Engagement & Authorization Context', '');
		if (data.engagementSummary) {
			const engagement = data.engagementSummary;
			lines.push(`- **Engagement:** ${engagement.name} (\`${engagement.id}\`)`);
			lines.push(`- **Targets:** ${engagement.targets.length > 0 ? engagement.targets.map(item => `\`${item}\``).join(', ') : 'None recorded'}`);
			lines.push(`- **Scope:** ${engagement.scope.length > 0 ? engagement.scope.map(item => `\`${item}\``).join(', ') : 'None recorded'}`);
			lines.push(`- **Identities / Resources / Transactions:** ${engagement.identities} / ${engagement.resources} / ${engagement.transactions}`);
		}
		if (data.authorizationSummary) {
			const matrix = data.authorizationSummary;
			lines.push(`- **Authorization matrix:** ${matrix.cells} cells across ${matrix.identities} identities and ${matrix.resources} resources`);
			lines.push(`- **Explicit expectation mismatches:** ${matrix.mismatches}`);
			if (matrix.mismatches === 0) {
				lines.push('- **Interpretation:** No explicit authorization-policy mismatch was observed in the recorded matrix. Unknown policy remains unknown.');
			}
		}
		lines.push('');
	}

	if (data.reconSummary) {
		const recon = data.reconSummary;
		lines.push('---', '', '## Reconnaissance Summary', '');
		lines.push(`- **Open Ports:** ${recon.openPorts}`);
		lines.push(`- **Pages Visited:** ${recon.pagesVisited}`);
		lines.push(`- **Discovered Endpoints:** ${recon.discoveredEndpoints}`);
		lines.push(`- **Forms / Parameters / JS Routes:** ${recon.forms} / ${recon.parameters} / ${recon.javascriptRoutes}`);
		lines.push(`- **Hidden Paths (Dir Fuzz):** ${recon.hiddenPaths}`);
		if (recon.technologies.length > 0) { lines.push(`- **Technologies:** ${recon.technologies.join(', ')}`); }
		if (recon.waf) {
			lines.push(`- **WAF/Edge Observation:** ${recon.waf.detected ? recon.waf.name ?? 'Detected' : 'Not detected'}${recon.waf.confidence !== undefined ? ` (${Math.round(recon.waf.confidence * 100)}% confidence)` : ''}${recon.waf.mode ? `, mode=${recon.waf.mode}` : ''}`);
		}
		lines.push('');
	}

	if (data.timeline.length > 0) {
		lines.push('---', '', '## Pipeline Timeline', '');
		lines.push('| Timestamp | Event | Status | Duration |');
		lines.push('|-----------|-------|--------|----------|');
		for (const entry of data.timeline) {
			lines.push(`| ${entry.timestamp ? formatTimestamp(entry.timestamp) : '-'} | ${escapeTable(entry.event)} | ${statusIcon(entry.status)} ${entry.status} | ${entry.durationMs !== undefined ? `${entry.durationMs} ms` : '-'} |`);
		}
		lines.push('');
	}

	lines.push('---', '', '*Generated by Scylla Reporting Engine | HikariSystem*', '');
	return lines.join('\n');
}

function appendSeverityTable(lines: string[], title: string, counts: Record<string, number>): void {
	if (Object.values(counts).every(count => count === 0)) { return; }
	lines.push(`### ${title}`, '');
	lines.push('| Severity | Count |', '|----------|-------|');
	for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
		const count = counts[severity] ?? 0;
		if (count > 0) { lines.push(`| ${severityIcon(severity)} ${capitalize(severity)} | ${count} |`); }
	}
	lines.push('');
}

function appendRecordSection(
	lines: string[],
	title: string,
	records: FindingEntry[],
	emptyMessage: string,
	showClassification = false,
): void {
	lines.push('---', '', `## ${title}`, '');
	if (records.length === 0) {
		lines.push(emptyMessage, '');
		return;
	}
	lines.push('| # | Severity | Title | Classification | Confidence | Status | Target |');
	lines.push('|---|----------|-------|----------------|------------|--------|--------|');
	for (let i = 0; i < records.length; i++) {
		const record = records[i];
		lines.push(`| ${i + 1} | ${severityIcon(record.severity)} ${capitalize(record.severity)} | ${escapeTable(record.title)} | ${record.classification} | ${record.confidence !== undefined ? `${Math.round(record.confidence * 100)}%` : '-'} | ${record.status} | \`${truncate(record.target, 40)}\` |`);
	}
	lines.push('');

	for (let i = 0; i < records.length; i++) {
		const record = records[i];
		lines.push(`### ${i + 1}. ${record.title}`, '');
		lines.push(`- **ID:** ${record.id}`);
		lines.push(`- **Severity:** ${severityIcon(record.severity)} ${capitalize(record.severity)}${record.classification !== 'validated' ? ' *(provisional until validation)*' : ''}`);
		lines.push(`- **Classification:** ${record.classification}`);
		lines.push(`- **Status:** ${record.status}`);
		lines.push(`- **Target:** \`${record.target}\``);
		if (record.confidence !== undefined) { lines.push(`- **Confidence:** ${Math.round(record.confidence * 100)}%`); }
		if (record.source?.scanner) { lines.push(`- **Source scanner:** ${record.source.scanner}`); }
		if (record.source?.command) { lines.push(`- **Source command:** \`${record.source.command}\``); }
		if (record.source?.strategy) { lines.push(`- **Strategy:** ${record.source.strategy}`); }
		if (record.actors?.attackerProfile) { lines.push(`- **Attacker profile:** ${record.actors.attackerProfile}`); }
		if (record.actors?.baselineProfile) { lines.push(`- **Baseline profile:** ${record.actors.baselineProfile}`); }
		if (record.actors?.resourceOwnerProfile) { lines.push(`- **Resource owner profile:** ${record.actors.resourceOwnerProfile}`); }
		if (record.tags.length > 0) { lines.push(`- **Tags:** ${record.tags.map(tag => `\`${tag}\``).join(', ')}`); }
		lines.push('');
		if (showClassification && record.classification !== 'validated') {
			lines.push('> This record is not a validated vulnerability and does not contribute to the report risk level.', '');
		}
		if (record.summary) { lines.push(record.summary, ''); }
		if (record.evidence.length > 0) {
			lines.push('**Evidence:**');
			for (const evidence of record.evidence) { lines.push(`- ${evidence}`); }
			lines.push('');
		}
	}
}

function firstArray(...values: unknown[]): unknown[] | undefined {
	return values.find(Array.isArray) as unknown[] | undefined;
}

function asFiniteNumber(value: unknown): number {
	const number = Number(value);
	return Number.isFinite(number) ? number : 0;
}

function asString(value: unknown): string {
	return typeof value === 'string' ? value.trim() : '';
}

function asStringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.map(asString).filter(Boolean) : [];
}

function normalizeConfidence(value: unknown): number | undefined {
	const raw = Number(value);
	if (!Number.isFinite(raw)) { return undefined; }
	return Math.max(0, Math.min(1, raw > 1 && raw <= 100 ? raw / 100 : raw));
}

function severityIcon(severity: string): string {
	switch (severity.toLowerCase()) {
		case 'critical': return '🔴';
		case 'high': return '🟠';
		case 'medium': return '🟡';
		case 'low': return '🔵';
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

function capitalize(value: string): string {
	return value.charAt(0).toUpperCase() + value.slice(1);
}

function truncate(value: string, max: number): string {
	return value.length > max ? `${value.slice(0, max - 3)}...` : value;
}

function escapeTable(value: string): string {
	return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function formatTimestamp(iso: string): string {
	try { return new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
	catch { return iso; }
}
