/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import type {
	FindingActors,
	FindingClassification,
	FindingEntry,
	FindingSource,
} from './types';

interface ParsedFrontmatter {
	values: Record<string, unknown>;
	body: string;
}

/** Parse one Scylla finding without silently discarding lifecycle metadata. */
export function parseFindingFile(filePath: string): FindingEntry | null {
	try {
		const content = fs.readFileSync(filePath, 'utf8');
		const parsed = parseFrontmatter(content);
		if (!parsed) { return null; }

		const frontmatter = parsed.values;
		const classification = normalizeClassification(frontmatter.classification, frontmatter.status);
		const source = normalizeSource(frontmatter);
		const actors = normalizeActors(frontmatter);
		const tags = asStringArray(frontmatter.tags)
			.filter(tag => tag.length > 0 && tag.toLowerCase() !== 'pending');

		return {
			id: asString(frontmatter.id) || path.basename(filePath, '.md'),
			title: asString(frontmatter.title) || 'Untitled',
			severity: normalizeSeverity(frontmatter.severity),
			status: asString(frontmatter.status) || 'open',
			classification,
			confidence: normalizeConfidence(frontmatter.confidence),
			source,
			actors,
			target: asString(frontmatter.target),
			createdAt: asString(frontmatter.createdAt) || undefined,
			updatedAt: asString(frontmatter.updatedAt) || undefined,
			summary: extractSection(parsed.body, 'Summary') || extractFirstParagraph(parsed.body),
			reproduction: extractSection(parsed.body, 'Reproduction') || undefined,
			remediation: extractSection(parsed.body, 'Remediation') || undefined,
			evidence: extractEvidence(parsed.body),
			tags,
			filePath,
		};
	} catch {
		return null;
	}
}

/** Scan a findings directory recursively, preserving deterministic ordering. */
export function loadFindings(findingsDir: string): FindingEntry[] {
	if (!fs.existsSync(findingsDir)) { return []; }

	const findings = walkMarkdownFiles(findingsDir)
		.map(parseFindingFile)
		.filter((finding): finding is FindingEntry => finding !== null);

	const classificationOrder: Record<FindingClassification, number> = {
		validated: 0,
		candidate: 1,
		observation: 2,
	};
	const severityOrder: Record<string, number> = {
		critical: 0,
		high: 1,
		medium: 2,
		low: 3,
		info: 4,
	};

	findings.sort((a, b) => {
		const classDelta = classificationOrder[a.classification] - classificationOrder[b.classification];
		if (classDelta !== 0) { return classDelta; }
		const severityDelta = (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
		if (severityDelta !== 0) { return severityDelta; }
		return a.title.localeCompare(b.title);
	});

	return findings;
}

/**
 * Small, deliberately constrained YAML-frontmatter parser.
 * Scylla writes scalar keys and indented block lists. Supporting those forms
 * avoids a packaged YAML dependency while preserving all current metadata.
 */
export function parseFrontmatter(content: string): ParsedFrontmatter | null {
	const normalized = content.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
	if (!normalized.startsWith('---\n')) { return null; }
	const end = normalized.indexOf('\n---', 4);
	if (end === -1) { return null; }

	const raw = normalized.slice(4, end);
	const body = normalized.slice(end + 4).replace(/^\n/, '');
	const values: Record<string, unknown> = {};
	let currentListKey: string | undefined;

	for (const rawLine of raw.split('\n')) {
		const line = rawLine.replace(/\s+$/, '');
		if (!line.trim() || line.trimStart().startsWith('#')) { continue; }

		const listMatch = line.match(/^\s+-\s*(.*)$/);
		if (listMatch && currentListKey) {
			const current = Array.isArray(values[currentListKey]) ? values[currentListKey] as unknown[] : [];
			current.push(parseScalar(listMatch[1]));
			values[currentListKey] = current;
			continue;
		}

		const keyValue = line.match(/^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$/);
		if (!keyValue) {
			currentListKey = undefined;
			continue;
		}

		const [, key, rawValue] = keyValue;
		if (rawValue.trim().length === 0) {
			values[key] = [];
			currentListKey = key;
		} else {
			values[key] = parseScalar(rawValue.trim());
			currentListKey = undefined;
		}
	}

	return { values, body };
}

function parseScalar(raw: string): unknown {
	const value = raw.trim();
	if (!value) { return ''; }
	if ((value.startsWith('"') && value.endsWith('"')) ||
		(value.startsWith("'") && value.endsWith("'"))) {
		return unquote(value);
	}
	if (value.startsWith('[') && value.endsWith(']')) {
		return splitInlineArray(value.slice(1, -1)).map(parseScalar);
	}
	if (/^(true|false)$/i.test(value)) { return value.toLowerCase() === 'true'; }
	if (/^(null|~)$/i.test(value)) { return null; }
	if (/^-?\d+(?:\.\d+)?$/.test(value)) { return Number(value); }
	return stripInlineComment(value);
}

function splitInlineArray(value: string): string[] {
	const parts: string[] = [];
	let current = '';
	let quote: string | undefined;
	for (let i = 0; i < value.length; i++) {
		const character = value[i];
		if ((character === '"' || character === "'") && value[i - 1] !== '\\') {
			quote = quote === character ? undefined : (quote ?? character);
			current += character;
			continue;
		}
		if (character === ',' && !quote) {
			parts.push(current.trim());
			current = '';
			continue;
		}
		current += character;
	}
	if (current.trim()) { parts.push(current.trim()); }
	return parts;
}

function unquote(value: string): string {
	const quote = value[0];
	const body = value.slice(1, -1);
	if (quote === '"') {
		try { return JSON.parse(value) as string; } catch { return body; }
	}
	return body.replace(/''/g, "'");
}

function stripInlineComment(value: string): string {
	const comment = value.match(/^(.*?)\s+#(?:\s|$)/);
	return (comment?.[1] ?? value).trim();
}

function normalizeClassification(value: unknown, status: unknown): FindingClassification {
	const normalized = asString(value).toLowerCase();
	if (normalized === 'validated' || normalized === 'candidate' || normalized === 'observation') {
		return normalized;
	}
	// Legacy records are not promoted merely because classification is absent.
	return asString(status).toLowerCase() === 'validated' ? 'validated' : 'candidate';
}

function normalizeSeverity(value: unknown): string {
	const severity = asString(value).toLowerCase();
	return ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'info';
}

function normalizeConfidence(value: unknown): number | undefined {
	const raw = typeof value === 'number' ? value : Number(asString(value));
	if (!Number.isFinite(raw)) { return undefined; }
	const normalized = raw > 1 && raw <= 100 ? raw / 100 : raw;
	return Math.max(0, Math.min(1, normalized));
}

function normalizeSource(values: Record<string, unknown>): FindingSource | undefined {
	const source: FindingSource = {};
	const scanner = asString(values.sourceScanner);
	const command = asString(values.sourceCommand);
	const strategy = asString(values.sourceStrategy);
	if (scanner) { source.scanner = scanner; }
	if (command) { source.command = command; }
	if (strategy) { source.strategy = strategy; }
	return Object.keys(source).length > 0 ? source : undefined;
}

function normalizeActors(values: Record<string, unknown>): FindingActors | undefined {
	const actors: FindingActors = {};
	const attackerProfile = asString(values.attackerProfile);
	const baselineProfile = asString(values.baselineProfile);
	const resourceOwnerProfile = asString(values.resourceOwnerProfile);
	if (attackerProfile) { actors.attackerProfile = attackerProfile; }
	if (baselineProfile) { actors.baselineProfile = baselineProfile; }
	if (resourceOwnerProfile) { actors.resourceOwnerProfile = resourceOwnerProfile; }
	return Object.keys(actors).length > 0 ? actors : undefined;
}

function asString(value: unknown): string {
	if (value === undefined || value === null) { return ''; }
	return String(value).trim();
}

function asStringArray(value: unknown): string[] {
	if (Array.isArray(value)) { return value.map(asString).filter(Boolean); }
	const scalar = asString(value);
	return scalar ? [scalar] : [];
}

function extractSection(body: string, heading: string): string {
	const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	const match = body.match(new RegExp(`^##\\s+${escaped}\\s*$\\n([\\s\\S]*?)(?=^##\\s+|\\s*$)`, 'mi'));
	return match?.[1]?.trim() ?? '';
}

function extractEvidence(body: string): string[] {
	const section = extractSection(body, 'Evidence');
	if (!section) { return []; }
	const bullets = section.split('\n')
		.map(line => line.match(/^\s*[-*]\s+(.+)$/)?.[1]?.trim())
		.filter((item): item is string => Boolean(item));
	return bullets.length > 0 ? bullets : [section];
}

function extractFirstParagraph(body: string): string {
	const withoutTitle = body.replace(/^#\s+.+\n+/, '');
	return withoutTitle.split(/\n\s*\n/).map(part => part.trim()).find(Boolean) ?? '';
}

function walkMarkdownFiles(root: string): string[] {
	const output: string[] = [];
	const visit = (directory: string): void => {
		for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
			const fullPath = path.join(directory, entry.name);
			if (entry.isDirectory()) {
				visit(fullPath);
			} else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
				output.push(fullPath);
			}
		}
	};
	visit(root);
	return output.sort();
}
