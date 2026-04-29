/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { DomxssScanResult, VulnFinding } from './types';

// ---------------------------------------------------------------------------
// Dangerous sink patterns
// ---------------------------------------------------------------------------

const SINK_PATTERNS: Array<{ pattern: RegExp; name: string; severity: 'medium' | 'info' }> = [
	// Direct DOM manipulation
	{ pattern: /\.innerHTML\s*=/, name: 'innerHTML assignment', severity: 'medium' },
	{ pattern: /\.outerHTML\s*=/, name: 'outerHTML assignment', severity: 'medium' },
	{ pattern: /document\.write\s*\(/, name: 'document.write', severity: 'medium' },
	{ pattern: /document\.writeln\s*\(/, name: 'document.writeln', severity: 'medium' },

	// Code execution
	{ pattern: /\beval\s*\(/, name: 'eval', severity: 'medium' },
	{ pattern: /setTimeout\s*\(\s*["'`]/, name: 'setTimeout(string)', severity: 'medium' },
	{ pattern: /setInterval\s*\(\s*["'`]/, name: 'setInterval(string)', severity: 'medium' },

	// Navigation / redirection
	{ pattern: /location\s*=\s*/, name: 'location assignment', severity: 'medium' },
	{ pattern: /location\.href\s*=/, name: 'location.href assignment', severity: 'medium' },
	{ pattern: /location\.assign\s*\(/, name: 'location.assign', severity: 'medium' },
	{ pattern: /location\.replace\s*\(/, name: 'location.replace', severity: 'medium' },

	// jQuery sinks
	{ pattern: /\.html\s*\(/, name: 'jQuery .html()', severity: 'medium' },
	{ pattern: /\.append\s*\(/, name: 'jQuery .append()', severity: 'info' },
	{ pattern: /\.after\s*\(/, name: 'jQuery .after()', severity: 'info' },
	{ pattern: /\.before\s*\(/, name: 'jQuery .before()', severity: 'info' },
	{ pattern: /\.prepend\s*\(/, name: 'jQuery .prepend()', severity: 'info' },

	// React
	{ pattern: /dangerouslySetInnerHTML/, name: 'dangerouslySetInnerHTML (React)', severity: 'medium' },

	// Vue
	{ pattern: /v-html/, name: 'v-html (Vue)', severity: 'medium' },

	// Angular
	{ pattern: /\[innerHTML\]/, name: '[innerHTML] (Angular)', severity: 'medium' },
];

// ---------------------------------------------------------------------------
// User-controllable source patterns
// ---------------------------------------------------------------------------

const SOURCE_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
	{ pattern: /location\.search/, name: 'location.search' },
	{ pattern: /location\.hash/, name: 'location.hash' },
	{ pattern: /location\.href/, name: 'location.href' },
	{ pattern: /document\.URL/, name: 'document.URL' },
	{ pattern: /document\.referrer/, name: 'document.referrer' },
	{ pattern: /document\.cookie/, name: 'document.cookie' },
	{ pattern: /window\.name/, name: 'window.name' },
	{ pattern: /window\.postMessage/, name: 'window.postMessage' },
	{ pattern: /postMessage\s*\(/, name: 'postMessage' },
	{ pattern: /addEventListener\s*\(\s*['"]message['"]/, name: 'message event listener' },
	{ pattern: /URLSearchParams/, name: 'URLSearchParams' },
];

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

export async function scanDomxss(
	targetUrl: string,
	options: {
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<DomxssScanResult> {
	const start = Date.now();
	const findings: VulnFinding[] = [];
	let jsFilesAnalyzed = 0;
	const timeoutMs = options.timeoutMs ?? 15_000;

	// Step 1: Fetch the target page
	const pageHtml = await fetchUrl(targetUrl, timeoutMs, options.headers, options.cookie);
	if (!pageHtml) {
		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			jsFilesAnalyzed: 0,
			findings: [],
			elapsedMs: Date.now() - start,
		};
	}

	// Step 2: Extract inline scripts
	const inlineScripts = extractInlineScripts(pageHtml);
	for (let i = 0; i < inlineScripts.length; i++) {
		jsFilesAnalyzed++;
		const scriptFindings = analyzeJavaScript(
			inlineScripts[i],
			targetUrl,
			`inline-script-${i + 1}`,
		);
		findings.push(...scriptFindings);
	}

	// Step 3: Extract linked JS file URLs and download each
	const jsUrls = extractLinkedJsUrls(pageHtml, targetUrl);
	for (const jsUrl of jsUrls) {
		const jsContent = await fetchUrl(jsUrl, timeoutMs, options.headers, options.cookie);
		if (!jsContent) { continue; }
		jsFilesAnalyzed++;

		const scriptFindings = analyzeJavaScript(jsContent, targetUrl, jsUrl);
		findings.push(...scriptFindings);
	}

	// Deduplicate
	const deduped = deduplicateFindings(findings);

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		jsFilesAnalyzed,
		findings: deduped,
		elapsedMs: Date.now() - start,
	};
}

// ---------------------------------------------------------------------------
// JavaScript analysis
// ---------------------------------------------------------------------------

function analyzeJavaScript(
	jsContent: string,
	targetUrl: string,
	sourceLabel: string,
): VulnFinding[] {
	const findings: VulnFinding[] = [];

	// Detect sources present in this script
	const detectedSources: string[] = [];
	for (const src of SOURCE_PATTERNS) {
		if (src.pattern.test(jsContent)) {
			detectedSources.push(src.name);
		}
	}

	// Detect sinks present in this script
	for (const sink of SINK_PATTERNS) {
		// Reset lastIndex for stateful regexes
		sink.pattern.lastIndex = 0;

		const lines = jsContent.split('\n');
		for (let lineNum = 0; lineNum < lines.length; lineNum++) {
			const line = lines[lineNum];
			if (!sink.pattern.test(line)) { continue; }

			// Build context snippet (surrounding lines)
			const contextStart = Math.max(0, lineNum - 2);
			const contextEnd = Math.min(lines.length, lineNum + 3);
			const context = lines.slice(contextStart, contextEnd).join('\n');

			// Check if any source is referenced nearby (within +/- 10 lines)
			const nearbyStart = Math.max(0, lineNum - 10);
			const nearbyEnd = Math.min(lines.length, lineNum + 11);
			const nearbyBlock = lines.slice(nearbyStart, nearbyEnd).join('\n');

			const nearbySources: string[] = [];
			for (const src of SOURCE_PATTERNS) {
				if (src.pattern.test(nearbyBlock)) {
					nearbySources.push(src.name);
				}
			}

			if (nearbySources.length > 0) {
				// Source-to-sink flow detected - higher severity
				findings.push({
					type: 'domxss',
					severity: 'medium',
					title: `DOM XSS: Source-to-Sink Flow (${sink.name})`,
					url: targetUrl,
					payload: `sink: ${sink.name} | sources: ${nearbySources.join(', ')}`,
					evidence: `Sink "${sink.name}" found near source(s) [${nearbySources.join(', ')}] in ${sourceLabel} at line ${lineNum + 1}`,
					confidence: 0.70,
					details: `Potential DOM XSS vector detected in ${sourceLabel}. ` +
						`User-controllable source(s) [${nearbySources.join(', ')}] flow into dangerous sink "${sink.name}" ` +
						`near line ${lineNum + 1}.\n\nContext:\n${context}`,
				});
			} else if (detectedSources.length > 0) {
				// Sink found and sources exist in the same file, but not nearby
				findings.push({
					type: 'domxss',
					severity: 'info',
					title: `DOM XSS: Sink Found (${sink.name})`,
					url: targetUrl,
					payload: `sink: ${sink.name}`,
					evidence: `Sink "${sink.name}" found in ${sourceLabel} at line ${lineNum + 1}. Sources in same file: ${detectedSources.join(', ')}`,
					confidence: 0.40,
					details: `Dangerous sink "${sink.name}" detected in ${sourceLabel} at line ${lineNum + 1}. ` +
						`User-controllable sources [${detectedSources.join(', ')}] exist in the same file but were not found in immediate proximity. ` +
						`Manual review recommended.\n\nContext:\n${context}`,
				});
			}

			// Only report first occurrence of this sink type per file
			break;
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// HTML parsing helpers
// ---------------------------------------------------------------------------

function extractInlineScripts(html: string): string[] {
	const scripts: string[] = [];
	const regex = /<script(?:\s[^>]*)?>([^]*?)<\/script>/gi;
	let match: RegExpExecArray | null;

	while ((match = regex.exec(html)) !== null) {
		const tag = match[0];
		// Skip external scripts (those with src attribute)
		if (/\bsrc\s*=/i.test(tag.substring(0, tag.indexOf('>')))) { continue; }

		const content = match[1].trim();
		if (content.length > 0) {
			scripts.push(content);
		}
	}

	return scripts;
}

function extractLinkedJsUrls(html: string, baseUrl: string): string[] {
	const urls: string[] = [];
	const seen = new Set<string>();
	const regex = /<script\s[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
	let match: RegExpExecArray | null;

	while ((match = regex.exec(html)) !== null) {
		const src = match[1].trim();
		if (!src) { continue; }

		let resolvedUrl: string;
		try {
			resolvedUrl = new URL(src, baseUrl).href;
		} catch {
			continue;
		}

		if (!seen.has(resolvedUrl)) {
			seen.add(resolvedUrl);
			urls.push(resolvedUrl);
		}
	}

	return urls;
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async function fetchUrl(
	url: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<string | null> {
	try {
		const sendOptions: Record<string, unknown> = {
			url,
			method: 'GET',
			timeoutMs,
			followRedirects: true,
			quiet: true,
			maxBodyBytes: 1024 * 1024,
		};

		if (headers) { sendOptions.headers = { ...headers }; }
		if (cookie) {
			sendOptions.headers = {
				...(sendOptions.headers as Record<string, string> ?? {}),
				cookie,
			};
		}

		const result = await vscode.commands.executeCommand<{
			response: {
				statusCode: number;
				bodyText: string;
				elapsedMs: number;
				headers?: Record<string, string>;
			};
		}>('scylla.http.sendHeadless', sendOptions);

		if (!result?.response) { return null; }
		return result.response.bodyText;
	} catch {
		return null;
	}
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

function deduplicateFindings(findings: VulnFinding[]): VulnFinding[] {
	const seen = new Set<string>();
	return findings.filter(f => {
		const key = `${f.title}:${f.payload}`;
		if (seen.has(key)) { return false; }
		seen.add(key);
		return true;
	});
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

export function generateDomxssReport(result: DomxssScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - DOM XSS Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **JS Files Analyzed:** ${result.jsFilesAnalyzed}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No DOM XSS vulnerabilities detected.');
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
				lines.push('');
				lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
				lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
				lines.push(`- **Payload:** \`${f.payload}\``);
				lines.push(`- **Evidence:** ${f.evidence}`);
				lines.push('');
				lines.push(f.details);
				lines.push('');
			}
		}
	}

	return lines.join('\n');
}
