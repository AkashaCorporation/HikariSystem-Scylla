/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import type { ExportFinding, ExportResult } from './types';

// ---------------------------------------------------------------------------
// JSON Exporter
// ---------------------------------------------------------------------------

export function exportJson(findings: ExportFinding[], outputPath: string): ExportResult {
	const data = {
		generatedAt: new Date().toISOString(),
		generator: 'Scylla Export Engine',
		version: '0.1.0',
		totalFindings: findings.length,
		findings,
	};

	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, JSON.stringify(data, null, 2), 'utf8');

	return {
		generatedAt: data.generatedAt,
		format: 'json',
		outputPath,
		findingsCount: findings.length,
	};
}

// ---------------------------------------------------------------------------
// CSV Exporter
// ---------------------------------------------------------------------------

export function exportCsv(findings: ExportFinding[], outputPath: string): ExportResult {
	const headers = ['ID', 'Title', 'Severity', 'Status', 'Target', 'Tags', 'Created At', 'Updated At', 'Summary'];
	const rows = findings.map(f => [
		csvEscape(f.id),
		csvEscape(f.title),
		csvEscape(f.severity),
		csvEscape(f.status),
		csvEscape(f.target),
		csvEscape(f.tags.join('; ')),
		csvEscape(f.createdAt),
		csvEscape(f.updatedAt),
		csvEscape(f.summary),
	].join(','));

	const csv = [headers.join(','), ...rows].join('\n');

	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, csv, 'utf8');

	return {
		generatedAt: new Date().toISOString(),
		format: 'csv',
		outputPath,
		findingsCount: findings.length,
	};
}

function csvEscape(value: string): string {
	if (value.includes(',') || value.includes('"') || value.includes('\n')) {
		return `"${value.replace(/"/g, '""')}"`;
	}
	return value;
}

// ---------------------------------------------------------------------------
// SARIF 2.1 Exporter
// ---------------------------------------------------------------------------

export function exportSarif(findings: ExportFinding[], outputPath: string): ExportResult {
	const severityToLevel: Record<string, string> = {
		critical: 'error',
		high: 'error',
		medium: 'warning',
		low: 'note',
		info: 'none',
	};

	const severityToRank: Record<string, number> = {
		critical: 9.5,
		high: 8.0,
		medium: 5.5,
		low: 3.0,
		info: 1.0,
	};

	const rules = findings.map((f, i) => ({
		id: f.id || `SCYLLA-${String(i + 1).padStart(3, '0')}`,
		name: f.title.replace(/[^a-zA-Z0-9]/g, ''),
		shortDescription: { text: f.title },
		fullDescription: { text: f.summary || f.title },
		help: {
			text: f.remediation || 'No remediation guidance provided.',
			markdown: f.remediation ? `## Remediation\n\n${f.remediation}` : undefined,
		},
		properties: {
			tags: f.tags,
			severity: f.severity,
			'security-severity': String(severityToRank[f.severity] ?? 5.0),
		},
	}));

	const results = findings.map((f, i) => ({
		ruleId: f.id || `SCYLLA-${String(i + 1).padStart(3, '0')}`,
		ruleIndex: i,
		level: severityToLevel[f.severity] ?? 'warning',
		message: {
			text: f.summary || f.title,
		},
		locations: [
			{
				physicalLocation: {
					artifactLocation: {
						uri: f.target,
						uriBaseId: '%SRCROOT%',
					},
				},
			},
		],
		properties: {
			status: f.status,
			target: f.target,
			createdAt: f.createdAt,
			evidence: f.evidence,
		},
	}));

	const sarif = {
		$schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
		version: '2.1.0',
		runs: [
			{
				tool: {
					driver: {
						name: 'Scylla',
						organization: 'HikariSystem',
						semanticVersion: '2.0.0',
						informationUri: 'https://github.com/AkashaCorporation/HikariSystem-Scylla',
						rules,
					},
				},
				results,
				invocations: [
					{
						executionSuccessful: true,
						startTimeUtc: new Date().toISOString(),
					},
				],
			},
		],
	};

	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf8');

	return {
		generatedAt: new Date().toISOString(),
		format: 'sarif',
		outputPath,
		findingsCount: findings.length,
	};
}
