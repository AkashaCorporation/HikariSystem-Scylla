/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import type { ParamsScanResult, VulnFinding } from './types';

const DEFAULT_DELAY_MS = 50;
const DEFAULT_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Built-in hidden parameter wordlist (~70 common params)
// ---------------------------------------------------------------------------

const DEFAULT_WORDLIST: string[] = [
	// Debug / admin
	'debug', 'admin', 'test', 'verbose', 'trace', 'log', 'dev', 'staging',

	// Auth / session
	'token', 'api_key', 'apikey', 'jwt', 'access_token', 'oauth', 'auth',
	'session', 'sid', 'secret', 'key', 'password', 'passwd',

	// CRUD / identifiers
	'id', 'uid', 'user_id', 'order_id', 'item_id', 'pid', 'page', 'limit',
	'offset', 'sort', 'order', 'filter', 'search', 'q', 'query',

	// Config / feature flags
	'config', 'settings', 'version', 'mode', 'env', 'feature', 'flag',
	'enable', 'disable', 'lang', 'locale', 'theme',

	// File / path
	'file', 'path', 'url', 'include', 'require', 'src', 'dest', 'dir',
	'folder', 'template', 'view', 'layout',

	// Dangerous / RCE
	'rce', 'shell', 'system', 'eval', 'code', 'cmd', 'exec', 'command', 'run',

	// Cache / bypass
	'cache', 'bypass', 'refresh', 'reload', 'nocache', 'no_cache',

	// API / redirect
	'format', 'callback', 'jsonp', 'redirect', 'next', 'return', 'continue',
	'goto', 'returnTo', 'return_url', 'redirect_uri',
];

// ---------------------------------------------------------------------------
// Response signature
// ---------------------------------------------------------------------------

interface ResponseSignature {
	statusCode: number;
	bodyLength: number;
	bodyHash: string;
}

function computeSignature(statusCode: number, body: string): ResponseSignature {
	return {
		statusCode,
		bodyLength: body.length,
		bodyHash: crypto.createHash('md5').update(body).digest('hex'),
	};
}

function signaturesMatch(a: ResponseSignature, b: ResponseSignature): boolean {
	if (a.statusCode !== b.statusCode) { return false; }
	if (a.bodyHash !== b.bodyHash) { return false; }
	// Small length variation tolerance (e.g. timestamps, nonces)
	if (Math.abs(a.bodyLength - b.bodyLength) > 10) { return false; }
	return true;
}

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

export async function scanParams(
	targetUrl: string,
	options: {
		wordlist?: string[];
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<ParamsScanResult> {
	const start = Date.now();
	const findings: VulnFinding[] = [];
	const discoveredParams: string[] = [];
	const wordlist = options.wordlist ?? DEFAULT_WORDLIST;
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	// Step 1: Get baseline response
	const baseline = await getBaseline(targetUrl, timeoutMs, options.headers, options.cookie);
	if (!baseline) {
		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			paramsTested: 0,
			findings: [],
			discoveredParams: [],
			elapsedMs: Date.now() - start,
		};
	}

	// Filter out parameters already present in the URL
	const existingParams = extractExistingParams(targetUrl);
	const paramsToTest = wordlist.filter(p => !existingParams.has(p));

	// Step 2: Test each parameter
	let paramsTested = 0;
	for (const param of paramsToTest) {
		paramsTested++;

		const testUrl = appendParam(targetUrl, param, 'scyllafuzz');
		const response = await fetchResponse(testUrl, timeoutMs, options.headers, options.cookie);

		if (!response) {
			if (delayMs > 0) { await sleep(delayMs); }
			continue;
		}

		const testSig = computeSignature(response.statusCode, response.bodyText);

		// Compare to baseline
		if (!signaturesMatch(baseline.signature, testSig)) {
			discoveredParams.push(param);

			// Determine severity based on param category
			const severity = categorizeSeverity(param);

			findings.push({
				type: 'hidden-param',
				severity,
				title: `Hidden Parameter Discovered: ${param}`,
				url: testUrl,
				parameter: param,
				payload: `${param}=scyllafuzz`,
				evidence: buildEvidence(baseline.signature, testSig),
				confidence: 0.75,
				details: `Adding parameter "${param}" to the request caused a different response. ` +
					`Baseline: status=${baseline.signature.statusCode}, length=${baseline.signature.bodyLength}. ` +
					`With param: status=${testSig.statusCode}, length=${testSig.bodyLength}. ` +
					`This parameter may be processed server-side and could expose hidden functionality.`,
			});
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		paramsTested,
		findings,
		discoveredParams,
		elapsedMs: Date.now() - start,
	};
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

async function getBaseline(
	url: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ signature: ResponseSignature } | null> {
	// Take two measurements to ensure a stable baseline
	const r1 = await fetchResponse(url, timeoutMs, headers, cookie);
	if (!r1) { return null; }

	const r2 = await fetchResponse(url, timeoutMs, headers, cookie);
	if (!r2) { return null; }

	const sig1 = computeSignature(r1.statusCode, r1.bodyText);
	const sig2 = computeSignature(r2.statusCode, r2.bodyText);

	// If baseline is unstable (dynamic page), use the second measurement
	// but note that false positives are more likely
	if (!signaturesMatch(sig1, sig2)) {
		// Take a third measurement as tiebreaker
		const r3 = await fetchResponse(url, timeoutMs, headers, cookie);
		if (r3) {
			return { signature: computeSignature(r3.statusCode, r3.bodyText) };
		}
	}

	return { signature: sig1 };
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async function fetchResponse(
	url: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ statusCode: number; bodyText: string; elapsedMs: number } | null> {
	try {
		const sendOptions: Record<string, unknown> = {
			url,
			method: 'GET',
			timeoutMs,
			followRedirects: true,
			quiet: true,
			maxBodyBytes: 256 * 1024,
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
		return {
			statusCode: result.response.statusCode,
			bodyText: result.response.bodyText,
			elapsedMs: result.response.elapsedMs,
		};
	} catch {
		return null;
	}
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

function appendParam(baseUrl: string, name: string, value: string): string {
	try {
		const url = new URL(baseUrl);
		url.searchParams.set(name, value);
		return url.href;
	} catch {
		// Fallback for malformed URLs
		const separator = baseUrl.includes('?') ? '&' : '?';
		return `${baseUrl}${separator}${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
	}
}

function extractExistingParams(url: string): Set<string> {
	try {
		const parsed = new URL(url);
		return new Set(parsed.searchParams.keys());
	} catch {
		return new Set();
	}
}

// ---------------------------------------------------------------------------
// Severity classification
// ---------------------------------------------------------------------------

function categorizeSeverity(param: string): 'medium' | 'low' | 'info' {
	const dangerous = new Set([
		'rce', 'shell', 'system', 'eval', 'code', 'cmd', 'exec', 'command', 'run',
		'debug', 'admin', 'include', 'require', 'file', 'path', 'template',
	]);
	const interesting = new Set([
		'token', 'api_key', 'apikey', 'jwt', 'access_token', 'oauth', 'auth',
		'session', 'sid', 'secret', 'key', 'password', 'passwd', 'config',
		'settings', 'redirect', 'return', 'goto', 'returnTo', 'return_url',
		'redirect_uri', 'url', 'callback',
	]);

	if (dangerous.has(param)) { return 'medium'; }
	if (interesting.has(param)) { return 'low'; }
	return 'info';
}

// ---------------------------------------------------------------------------
// Evidence helper
// ---------------------------------------------------------------------------

function buildEvidence(baseline: ResponseSignature, test: ResponseSignature): string {
	const diffs: string[] = [];
	if (baseline.statusCode !== test.statusCode) {
		diffs.push(`status code changed: ${baseline.statusCode} -> ${test.statusCode}`);
	}
	if (baseline.bodyHash !== test.bodyHash) {
		diffs.push(`body content changed (length: ${baseline.bodyLength} -> ${test.bodyLength})`);
	}
	return `Response differs from baseline: ${diffs.join('; ')}`;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

export function generateParamsReport(result: ParamsScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - Hidden Parameter Discovery Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Tested:** ${result.paramsTested}`);
	lines.push(`- **Discovered:** ${result.discoveredParams.length}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No hidden parameters discovered.');
	} else {
		lines.push(`## Discovered Parameters: ${result.discoveredParams.join(', ')}`);
		lines.push('');

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
				lines.push(`- **Parameter:** \`${f.parameter}\``);
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
