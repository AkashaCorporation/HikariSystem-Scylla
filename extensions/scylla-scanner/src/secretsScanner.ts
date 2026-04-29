/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { SecretsScanResult, VulnFinding, VulnSeverity } from './types';

interface SecretPattern {
	name: string;
	pattern: string;
	severity: VulnSeverity;
	category: string;
	contextRequired?: boolean;
}

interface SecretPatternsFile {
	patterns: SecretPattern[];
}

export async function scanSecrets(
	options: {
		url?: string;
		content?: string;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<SecretsScanResult> {
	const start = Date.now();
	const findings: VulnFinding[] = [];
	let sourcesScanned = 0;
	const target = options.url ?? '(content)';

	const patternsFile = loadJson<SecretPatternsFile>('secret-patterns.json');
	const patterns = patternsFile.patterns.filter(p => !p.contextRequired);

	// Collect content to scan
	const contentSources: Array<{ content: string; source: string }> = [];

	if (options.content) {
		contentSources.push({ content: options.content, source: 'provided content' });
	}

	if (options.url) {
		try {
			const sendOptions: Record<string, unknown> = {
				url: options.url,
				method: 'GET',
				timeoutMs: options.timeoutMs ?? 15_000,
				followRedirects: true,
				quiet: true,
				maxBodyBytes: 1024 * 1024,
			};
			if (options.headers) { sendOptions.headers = options.headers; }
			if (options.cookie) {
				sendOptions.headers = { ...(sendOptions.headers as Record<string, string> ?? {}), cookie: options.cookie };
			}

			const result = await vscode.commands.executeCommand<{
				response: { bodyText: string; headers: Record<string, string | string[]> };
			}>('scylla.http.sendHeadless', sendOptions);

			if (result?.response) {
				contentSources.push({ content: result.response.bodyText, source: options.url });

				// Also scan response headers
				const headerContent = Object.entries(result.response.headers)
					.map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
					.join('\n');
				contentSources.push({ content: headerContent, source: `${options.url} (headers)` });
			}
		} catch {
			// Network error
		}
	}

	// Scan each content source
	for (const { content, source } of contentSources) {
		sourcesScanned++;

		for (const pattern of patterns) {
			const regex = new RegExp(pattern.pattern, 'gi');
			let match: RegExpExecArray | null;

			while ((match = regex.exec(content)) !== null) {
				const matchedValue = match[0];
				// Avoid false positives on very common short strings
				if (matchedValue.length < 8) { continue; }

				// Check if it's not inside a comment or documentation
				const surrounding = content.substring(
					Math.max(0, match.index - 50),
					Math.min(content.length, match.index + matchedValue.length + 50)
				);

				// Skip if it looks like example/placeholder
				if (/example|placeholder|your[_-]?key|xxx|test|dummy|sample/i.test(surrounding)) {
					continue;
				}

				const maskedValue = maskSecret(matchedValue);

				findings.push({
					type: 'secret',
					severity: pattern.severity,
					title: `Exposed ${pattern.name}`,
					url: source,
					payload: maskedValue,
					evidence: `Pattern "${pattern.name}" matched in ${source}. Category: ${pattern.category}`,
					confidence: 0.80,
					details: `Potential ${pattern.name} found in ${source}. The value matches the pattern for ${pattern.category} credentials. Masked value: ${maskedValue}`,
				});
			}
		}
	}

	// Deduplicate by type+url
	const deduped = deduplicateFindings(findings);

	return {
		generatedAt: new Date().toISOString(),
		target,
		sourcesScanned,
		findings: deduped,
		elapsedMs: Date.now() - start,
	};
}

function maskSecret(value: string): string {
	if (value.length <= 8) { return '****'; }
	const visible = Math.min(4, Math.floor(value.length / 4));
	return value.slice(0, visible) + '****' + value.slice(-visible);
}

function deduplicateFindings(findings: VulnFinding[]): VulnFinding[] {
	const seen = new Set<string>();
	return findings.filter(f => {
		const key = `${f.title}:${f.payload}`;
		if (seen.has(key)) { return false; }
		seen.add(key);
		return true;
	});
}

function loadJson<T>(filename: string): T {
	for (const p of [path.join(__dirname, 'payloads', filename), path.join(__dirname, '..', 'src', 'payloads', filename), path.join(__dirname, '..', 'payloads', filename)]) {
		if (fs.existsSync(p)) { return JSON.parse(fs.readFileSync(p, 'utf8')); }
	}
	throw new Error(`Payload file not found: ${filename}`);
}

export function generateSecretsReport(result: SecretsScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - Secrets Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Sources Scanned:** ${result.sourcesScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No exposed secrets or credentials detected.');
	} else {
		// Group by severity
		const bySeverity: Record<string, VulnFinding[]> = {};
		for (const f of result.findings) {
			(bySeverity[f.severity] ??= []).push(f);
		}

		for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
			const group = bySeverity[severity];
			if (!group || group.length === 0) { continue; }

			lines.push(`## ${severity.toUpperCase()} (${group.length})`);
			lines.push('');
			for (const f of group) {
				lines.push(`### ${f.title}`);
				lines.push(`- **Value:** \`${f.payload}\``);
				lines.push(`- **Source:** ${f.url}`);
				lines.push(`- **Evidence:** ${f.evidence}`);
				lines.push('');
			}
		}
	}

	return lines.join('\n');
}
