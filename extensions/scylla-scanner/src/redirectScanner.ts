/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { ParameterTarget, RedirectScanResult, VulnFinding } from './types';

const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 15_000;

const REDIRECT_PAYLOADS = [
	'https://evil.com',
	'//evil.com',
	'/\\evil.com',
	'https://evil.com%00',
	'https://evil.com%23',
	'javascript:alert(1)',
	'/%09/evil.com',
	'/evil.com',
	'https:evil.com',
	'\\evil.com',
	'/%2f%2fevil.com',
	'/evil%252ecom',
];

const COMMON_REDIRECT_PARAMS = [
	'url', 'redirect', 'next', 'return', 'goto', 'continue',
	'dest', 'destination', 'redir', 'target', 'out', 'ref',
	'link', 'forward',
];

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

const META_REFRESH_PATTERN = /<meta\s+http-equiv\s*=\s*["']?refresh["']?\s+content\s*=\s*["']?\d+;\s*url\s*=\s*([^"'\s>]+)/i;
const JS_REDIRECT_PATTERNS = [
	/window\.location\s*=\s*["']([^"']+)["']/i,
	/window\.location\.href\s*=\s*["']([^"']+)["']/i,
	/window\.location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i,
	/window\.location\.assign\s*\(\s*["']([^"']+)["']\s*\)/i,
	/document\.location\s*=\s*["']([^"']+)["']/i,
	/document\.location\.href\s*=\s*["']([^"']+)["']/i,
];

export async function scanRedirect(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
		autoDetectParams?: boolean;
	} = {}
): Promise<RedirectScanResult> {
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const autoDetect = options.autoDetectParams ?? true;

	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	// Build effective parameter list
	let effectiveParams = parameters.filter(
		p => p.location === 'query' || p.location === 'body'
	);

	// Auto-detect redirect-susceptible parameters from the URL
	if (autoDetect && effectiveParams.length === 0) {
		try {
			const url = new URL(targetUrl);
			for (const [name, value] of url.searchParams) {
				if (COMMON_REDIRECT_PARAMS.includes(name.toLowerCase())) {
					effectiveParams.push({ name, value, location: 'query' });
				}
			}
		} catch {
			// invalid URL, skip auto-detect
		}
	}

	// If still empty and auto-detect enabled, test common params anyway
	if (autoDetect && effectiveParams.length === 0) {
		for (const name of COMMON_REDIRECT_PARAMS) {
			effectiveParams.push({ name, value: '', location: 'query' });
		}
	}

	for (const param of effectiveParams) {
		parametersScanned++;

		for (const payload of REDIRECT_PAYLOADS) {
			const response = await sendRedirectProbe(
				targetUrl, param, payload, timeoutMs, options.headers, options.cookie
			);
			if (!response) {
				if (delayMs > 0) { await sleep(delayMs); }
				continue;
			}

			// Check 1: HTTP redirect via status code + Location header
			if (REDIRECT_STATUS_CODES.has(response.statusCode) && response.locationHeader) {
				if (isExternalRedirect(response.locationHeader)) {
					findings.push({
						type: 'open-redirect',
						severity: 'high',
						title: `Open Redirect (HTTP ${response.statusCode})`,
						url: targetUrl,
						parameter: param.name,
						payload,
						evidence: `Server returned ${response.statusCode} with Location: ${response.locationHeader}`,
						confidence: 0.95,
						details: `Open redirect detected in parameter "${param.name}" (${param.location}). `
							+ `The server responded with HTTP ${response.statusCode} and a Location header pointing to an external domain. `
							+ `Payload: ${payload}`,
					});
					if (delayMs > 0) { await sleep(delayMs); }
					continue;
				}
			}

			// Check 2: Meta refresh redirect in body
			if (response.bodyText) {
				const metaMatch = META_REFRESH_PATTERN.exec(response.bodyText);
				if (metaMatch && isExternalRedirect(metaMatch[1])) {
					findings.push({
						type: 'open-redirect',
						severity: 'medium',
						title: 'Open Redirect (Meta Refresh)',
						url: targetUrl,
						parameter: param.name,
						payload,
						evidence: `Response body contains meta refresh redirecting to: ${metaMatch[1]}`,
						confidence: 0.85,
						details: `Open redirect via meta refresh tag detected in parameter "${param.name}" (${param.location}). `
							+ `The response HTML contains a <meta http-equiv="refresh"> tag pointing to an attacker-controlled domain. `
							+ `Payload: ${payload}`,
					});
					if (delayMs > 0) { await sleep(delayMs); }
					continue;
				}

				// Check 3: JavaScript redirect in body
				for (const pattern of JS_REDIRECT_PATTERNS) {
					const jsMatch = pattern.exec(response.bodyText);
					if (jsMatch && isExternalRedirect(jsMatch[1])) {
						findings.push({
							type: 'open-redirect',
							severity: 'medium',
							title: 'Open Redirect (JavaScript)',
							url: targetUrl,
							parameter: param.name,
							payload,
							evidence: `Response body contains JavaScript redirect to: ${jsMatch[1]}`,
							confidence: 0.80,
							details: `Open redirect via JavaScript detected in parameter "${param.name}" (${param.location}). `
								+ `The response body contains a JavaScript redirect (e.g., window.location) pointing to an attacker-controlled domain. `
								+ `Payload: ${payload}`,
						});
						break;
					}
				}
			}

			if (delayMs > 0) { await sleep(delayMs); }
		}
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		parametersScanned,
		findings,
		elapsedMs: Date.now() - start,
	};
}

async function sendRedirectProbe(
	targetUrl: string,
	param: ParameterTarget,
	payload: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ bodyText: string; statusCode: number; locationHeader: string } | null> {
	try {
		const url = new URL(targetUrl);

		const sendOptions: Record<string, unknown> = {
			timeoutMs,
			followRedirects: false,
			quiet: true,
			maxBodyBytes: 64 * 1024,
		};

		if (headers) { sendOptions.headers = { ...headers }; }
		if (cookie) {
			sendOptions.headers = {
				...(sendOptions.headers as Record<string, string> ?? {}),
				cookie,
			};
		}

		if (param.location === 'query') {
			url.searchParams.set(param.name, payload);
			sendOptions.url = url.href;
			sendOptions.method = 'GET';
		} else if (param.location === 'body') {
			sendOptions.url = url.href;
			sendOptions.method = 'POST';
			sendOptions.body = `${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
			sendOptions.headers = {
				...(sendOptions.headers as Record<string, string> ?? {}),
				'content-type': 'application/x-www-form-urlencoded',
			};
		} else {
			return null;
		}

		const result = await vscode.commands.executeCommand<{
			response: {
				statusCode: number;
				bodyText: string;
				headers: Record<string, string>;
			};
		}>('scylla.http.sendHeadless', sendOptions);

		if (!result?.response) { return null; }

		// Extract Location header (case-insensitive lookup)
		let locationHeader = '';
		if (result.response.headers) {
			for (const [key, value] of Object.entries(result.response.headers)) {
				if (key.toLowerCase() === 'location') {
					locationHeader = value;
					break;
				}
			}
		}

		return {
			bodyText: result.response.bodyText,
			statusCode: result.response.statusCode,
			locationHeader,
		};
	} catch {
		return null;
	}
}

function isExternalRedirect(target: string): boolean {
	const normalized = target.trim().toLowerCase();

	// Check for evil.com or any clearly external domain in the redirect target
	if (normalized.includes('evil.com')) { return true; }

	// javascript: scheme
	if (normalized.startsWith('javascript:')) { return true; }

	// Protocol-relative URL pointing externally
	if (normalized.startsWith('//') && !normalized.startsWith('///')) { return true; }

	// Absolute URL with external scheme
	try {
		const parsed = new URL(target.trim(), 'http://internal.placeholder');
		if (parsed.hostname !== 'internal.placeholder' && parsed.hostname !== 'localhost') {
			return true;
		}
	} catch {
		// Not parseable as URL
	}

	// Backslash-based redirect tricks
	if (normalized.startsWith('\\') && normalized.length > 1) { return true; }

	return false;
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateRedirectReport(result: RedirectScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - Open Redirect Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Scanned:** ${result.parametersScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No open redirect vulnerabilities detected.');
	} else {
		for (const f of result.findings) {
			lines.push(`## ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Parameter:** \`${f.parameter}\``);
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Payload:** \`${f.payload}\``);
			lines.push(`- **Evidence:** ${f.evidence}`);
			lines.push('');
			lines.push(f.details);
			lines.push('');
		}
	}

	return lines.join('\n');
}
