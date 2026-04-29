/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { TECH_PATTERNS } from './techPatterns';
import type { DetectedTechnology, TechDetectResult } from './types';

const DEFAULT_TIMEOUT_MS = 15_000;

export async function detectTechnologies(
	url: string,
	timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<TechDetectResult> {
	const start = Date.now();

	const result = await vscode.commands.executeCommand<{
		response: {
			statusCode: number;
			headers: Record<string, string | string[]>;
			bodyText: string;
			finalUrl: string;
		};
	}>('scylla.http.sendHeadless', {
		url,
		method: 'GET',
		timeoutMs,
		followRedirects: true,
		quiet: true,
		maxBodyBytes: 256 * 1024,
	});

	if (!result?.response) {
		throw new Error(`Failed to fetch ${url}`);
	}

	const { response } = result;
	const detected: DetectedTechnology[] = [];
	const seen = new Set<string>();

	// Flatten headers to Record<string, string>
	const flatHeaders: Record<string, string> = {};
	for (const [key, value] of Object.entries(response.headers)) {
		flatHeaders[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
	}

	for (const tech of TECH_PATTERNS) {
		let matched = false;
		let version: string | undefined;
		let evidence = '';
		let maxConfidence = 0;

		// Check header patterns
		if (tech.headerPatterns) {
			for (const hp of tech.headerPatterns) {
				const headerValue = flatHeaders[hp.header.toLowerCase()];
				if (headerValue) {
					const m = hp.pattern.exec(headerValue);
					if (m) {
						matched = true;
						maxConfidence = Math.max(maxConfidence, 0.9);
						evidence = `Header ${hp.header}: ${headerValue.slice(0, 80)}`;
						if (hp.versionGroup !== undefined && m[hp.versionGroup]) {
							version = m[hp.versionGroup];
						}
					}
				}
			}
		}

		// Check body patterns
		if (tech.bodyPatterns) {
			for (const bp of tech.bodyPatterns) {
				const m = bp.pattern.exec(response.bodyText);
				if (m) {
					matched = true;
					maxConfidence = Math.max(maxConfidence, 0.7);
					if (!evidence) {
						evidence = `Body match: ${m[0].slice(0, 80)}`;
					}
					if (bp.versionGroup !== undefined && m[bp.versionGroup]) {
						version = m[bp.versionGroup];
					}
				}
			}
		}

		if (matched && !seen.has(tech.name)) {
			seen.add(tech.name);
			detected.push({
				name: tech.name,
				category: tech.category,
				version,
				confidence: maxConfidence,
				evidence,
			});
		}
	}

	// Sort by confidence descending
	detected.sort((a, b) => b.confidence - a.confidence);

	return {
		generatedAt: new Date().toISOString(),
		url,
		technologies: detected,
		headers: flatHeaders,
		elapsedMs: Date.now() - start,
	};
}

export function generateTechDetectReport(result: TechDetectResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Recon - Technology Detection Report');
	lines.push('');
	lines.push(`- **URL:** \`${result.url}\``);
	lines.push(`- **Technologies Found:** ${result.technologies.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.technologies.length === 0) {
		lines.push('No technologies detected.');
	} else {
		lines.push('## Detected Technologies');
		lines.push('');
		lines.push('| Technology | Category | Version | Confidence | Evidence |');
		lines.push('|-----------|----------|---------|------------|----------|');
		for (const tech of result.technologies) {
			const ver = tech.version ?? '-';
			const conf = `${Math.round(tech.confidence * 100)}%`;
			const ev = tech.evidence.slice(0, 50);
			lines.push(`| **${tech.name}** | ${tech.category} | ${ver} | ${conf} | ${ev} |`);
		}
		lines.push('');
	}

	lines.push('## Response Headers');
	lines.push('');
	const securityHeaders = ['strict-transport-security', 'x-content-type-options', 'x-frame-options',
		'x-xss-protection', 'content-security-policy', 'referrer-policy', 'permissions-policy'];

	lines.push('### Security Headers');
	lines.push('');
	for (const sh of securityHeaders) {
		const val = result.headers[sh];
		const status = val ? 'Present' : 'Missing';
		lines.push(`- **${sh}:** ${val ? `\`${val.slice(0, 80)}\`` : `*${status}*`}`);
	}
	lines.push('');

	return lines.join('\n');
}
