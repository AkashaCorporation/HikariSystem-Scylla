/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ExportFinding } from './types';

// ---------------------------------------------------------------------------
// Findings Loader — reads .scylla/findings/*.md with YAML front matter
// ---------------------------------------------------------------------------

const DEFAULT_FINDINGS_DIR = path.join('.scylla', 'findings');

export function loadFindings(findingsDir?: string, filters?: { severity?: string; status?: string }): ExportFinding[] {
	const dir = resolveFindingsDir(findingsDir);
	if (!fs.existsSync(dir)) { return []; }

	const files = fs.readdirSync(dir).filter(f => f.endsWith('.md')).map(f => path.join(dir, f));
	const findings: ExportFinding[] = [];

	for (const file of files) {
		try {
			const content = fs.readFileSync(file, 'utf8');
			const finding = parseFindingMarkdown(content);
			if (!finding) { continue; }

			// Apply filters
			if (filters?.severity && finding.severity !== filters.severity) { continue; }
			if (filters?.status && finding.status !== filters.status) { continue; }

			findings.push(finding);
		} catch { /* skip corrupt files */ }
	}

	return findings.sort((a, b) => {
		const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
		return (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
	});
}

function parseFindingMarkdown(content: string): ExportFinding | null {
	// Extract YAML front matter
	const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
	if (!fmMatch) { return null; }

	const fm = fmMatch[1];
	const getValue = (key: string): string => {
		const match = fm.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
		return match ? match[1].trim().replace(/^["']|["']$/g, '') : '';
	};

	const getArray = (key: string): string[] => {
		const lines: string[] = [];
		const regex = new RegExp(`^${key}:\\s*$`, 'm');
		const start = fm.match(regex);
		if (!start) { return []; }

		const startIndex = fm.indexOf(start[0]) + start[0].length;
		const remaining = fm.slice(startIndex);
		for (const line of remaining.split(/\r?\n/)) {
			const itemMatch = line.match(/^\s+-\s+(.+)$/);
			if (itemMatch) {
				lines.push(itemMatch[1].trim());
			} else if (line.trim().length > 0 && !line.match(/^\s+-/)) {
				break;
			}
		}
		return lines;
	};

	const id = getValue('id');
	const title = getValue('title');
	if (!id || !title) { return null; }

	// Extract body sections
	const body = content.slice(fmMatch[0].length);
	const getSection = (heading: string): string => {
		const regex = new RegExp(`##\\s+${heading}\\s*\\r?\\n([\\s\\S]*?)(?=\\r?\\n##\\s|$)`);
		const match = body.match(regex);
		return match ? match[1].trim() : '';
	};

	const evidenceSection = getSection('Evidence');
	const evidence = evidenceSection
		.split(/\r?\n/)
		.filter(l => l.startsWith('- '))
		.map(l => l.slice(2).trim());

	return {
		id,
		title,
		severity: getValue('severity') || 'medium',
		status: getValue('status') || 'open',
		target: getValue('target') || 'unknown',
		createdAt: getValue('createdAt'),
		updatedAt: getValue('updatedAt'),
		tags: getArray('tags').filter(t => t !== 'pending'),
		summary: getSection('Summary'),
		reproduction: getSection('Reproduction'),
		remediation: getSection('Remediation'),
		evidence,
	};
}

function resolveFindingsDir(findingsDir?: string): string {
	if (findingsDir && path.isAbsolute(findingsDir)) { return findingsDir; }
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
	return path.join(workspaceRoot, findingsDir ?? DEFAULT_FINDINGS_DIR);
}
