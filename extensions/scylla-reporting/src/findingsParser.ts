/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import type { FindingEntry } from './types';

/**
 * Parse YAML frontmatter from a finding markdown file.
 */
export function parseFindingFile(filePath: string): FindingEntry | null {
	try {
		const content = fs.readFileSync(filePath, 'utf8');
		const frontmatter = extractFrontmatter(content);
		if (!frontmatter) { return null; }

		return {
			id: String(frontmatter.id ?? path.basename(filePath, '.md')),
			title: String(frontmatter.title ?? 'Untitled'),
			severity: String(frontmatter.severity ?? 'info'),
			status: String(frontmatter.status ?? 'open'),
			target: String(frontmatter.target ?? ''),
			summary: String(frontmatter.summary ?? extractSummaryFromBody(content)),
			tags: Array.isArray(frontmatter.tags) ? frontmatter.tags.map(String) : [],
		};
	} catch {
		return null;
	}
}

/**
 * Scan a directory for finding markdown files and parse them.
 */
export function loadFindings(findingsDir: string): FindingEntry[] {
	if (!fs.existsSync(findingsDir)) { return []; }

	const files = fs.readdirSync(findingsDir)
		.filter(f => f.endsWith('.md'))
		.map(f => path.join(findingsDir, f));

	const findings: FindingEntry[] = [];
	for (const file of files) {
		const finding = parseFindingFile(file);
		if (finding) { findings.push(finding); }
	}

	// Sort by severity
	const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
	findings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

	return findings;
}

function extractFrontmatter(content: string): Record<string, unknown> | null {
	const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
	if (!match) { return null; }

	const yaml = match[1];
	const result: Record<string, unknown> = {};

	for (const line of yaml.split('\n')) {
		const kvMatch = line.match(/^(\w+)\s*:\s*(.+)$/);
		if (kvMatch) {
			const key = kvMatch[1];
			let value: unknown = kvMatch[2].trim();

			// Handle quoted strings
			if ((typeof value === 'string') && value.startsWith('"') && value.endsWith('"')) {
				value = value.slice(1, -1);
			} else if ((typeof value === 'string') && value.startsWith("'") && value.endsWith("'")) {
				value = value.slice(1, -1);
			}

			// Handle arrays (simple YAML inline format)
			if (typeof value === 'string' && value.startsWith('[') && value.endsWith(']')) {
				value = value.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
			}

			result[key] = value;
		}
	}

	return result;
}

function extractSummaryFromBody(content: string): string {
	// Get first paragraph after frontmatter
	const afterFrontmatter = content.replace(/^---[\s\S]*?---\s*/, '');
	const firstParagraph = afterFrontmatter.split(/\n\n/)[0]?.trim() ?? '';
	return firstParagraph.slice(0, 200);
}
