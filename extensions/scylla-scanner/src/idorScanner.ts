/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { loadParametersFromCrawl, loadTargetsFromCrawl } from './artifacts';
import type {
	CrawlResultFile,
	IdorFinding,
	IdorScanResult,
	IdorStrategy,
	VulnFinding,
} from './types';

// ---------------------------------------------------------------------------
// IDOR Scanner — Insecure Direct Object Reference Detection
// ---------------------------------------------------------------------------

const DEFAULT_SENSITIVE_PATTERNS = [
	'\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+\\b',                          // email
	'\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b',                   // phone (US)
	'\\b\\d{3}[-.\\s]?\\d{2}[-.\\s]?\\d{4}\\b',                   // SSN
	'\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6011)[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b', // credit card
	'\\b\\d+\\s+[\\w\\s]+(?:st|nd|rd|th|ave|blvd|dr|ln|rd|way|ct)\\b', // address
];

// Regex to find numeric/UUID identifiers in URL paths and query params
const ID_PATTERNS = [
	/\/(\d+)(?:\/|$|\?)/g,                                          // /users/123
	/[?&](?:id|user_id|userId|account_id|order_id|item_id|pid|uid|oid)=(\d+)/gi, // ?id=123
	/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)/gi, // UUID
	/[?&](?:id|uid|uuid|token)=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, // ?id=UUID
];

interface IdorTestCase {
	originalUrl: string;
	testedUrl: string;
	method: string;
	strategy: IdorStrategy;
	paramName?: string;
	originalValue?: string;
	testedValue?: string;
}

interface ScanOptions {
	strategies?: IdorStrategy[];
	sensitivePatterns?: string[];
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	profiles?: string[];
}

/** Extract the lowercased host from a URL (or bare host) for per-host header caching. */
function hostOf(url: string): string {
	try { return new URL(url.includes('://') ? url : `http://${url}`).hostname.toLowerCase(); }
	catch { return url.toLowerCase(); }
}

export async function scanIdor(
	target: string,
	crawlResultFile?: string,
	options?: ScanOptions,
): Promise<IdorScanResult> {
	const startTime = Date.now();
	const strategies: IdorStrategy[] = options?.strategies ?? ['sequential', 'zero-id', 'remove-param'];
	const sensitiveRegexes = buildSensitiveRegexes(options?.sensitivePatterns);
	const findings: IdorFinding[] = [];

	// Load endpoints from crawl results
	const endpoints = crawlResultFile
		? loadEndpointsFromCrawl(crawlResultFile)
		: [{ url: target, method: 'GET' }];

	// Extract identifiable endpoints (URLs with IDs)
	const testCases = generateTestCases(endpoints, strategies);

	// Resolve auth headers PER REQUEST HOST (not once per target) so cookies stay
	// domain-scoped: a crawl can yield endpoints on different hosts, and reusing a
	// single target-scoped header map would re-leak cookies cross-host. Headers are
	// cached by profile+host to avoid re-querying the auth extension per request.
	const usingProfiles = !!(options?.profiles && options.profiles.length >= 2);
	const staticHeaders: Record<string, string> = { ...options?.headers };
	if (options?.cookie) { staticHeaders['cookie'] = options.cookie; }
	const headerCache = new Map<string, Record<string, string>>();

	const resolveHeaders = async (profileName: string, url: string): Promise<Record<string, string>> => {
		if (!usingProfiles) { return staticHeaders; }
		const key = `${profileName}\n${hostOf(url)}`;
		const cached = headerCache.get(key);
		if (cached) { return cached; }
		let headers: Record<string, string> = {};
		try {
			const result = await vscode.commands.executeCommand<{ headers: Record<string, string> }>(
				'scylla.auth.getHeadersHeadless',
				{ profileName, targetUrl: url }
			);
			if (result?.headers) { headers = result.headers; }
		} catch {
			// Auth extension not available
		}
		headerCache.set(key, headers);
		return headers;
	};

	const profileNames = usingProfiles && options?.profiles ? options.profiles : ['default'];

	for (const testCase of testCases) {
		// Strategy: send original request as User A, modified request as User A (or User B if available)
		const userAProfile = profileNames[0];
		const userBProfile = profileNames.length >= 2 ? profileNames[1] : profileNames[0];

		try {
			// Request 1: Original URL with User A (headers scoped to this URL's host)
			const originalResponse = await performHttpRequest(
				testCase.method,
				testCase.originalUrl,
				await resolveHeaders(userAProfile, testCase.originalUrl),
				options?.timeoutMs,
			);

			if (options?.delayMs) { await sleep(options.delayMs); }

			// Request 2: Modified URL (with swapped ID) using User B's session (headers scoped to this URL's host)
			const modifiedResponse = await performHttpRequest(
				testCase.method === 'method-swap' ? swapMethod(testCase.method) : testCase.method,
				testCase.testedUrl,
				await resolveHeaders(userBProfile, testCase.testedUrl),
				options?.timeoutMs,
			);

			// Compare responses
			const originalHash = hashBody(originalResponse.body);
			const modifiedHash = hashBody(modifiedResponse.body);

			const isIdor = detectIdor(
				originalResponse,
				modifiedResponse,
				originalHash,
				modifiedHash,
				testCase.strategy,
			);

			if (isIdor) {
				const sensitiveData = findSensitiveData(modifiedResponse.body, sensitiveRegexes);

				findings.push({
					type: 'idor',
					severity: sensitiveData.length > 0 ? 'high' : 'medium',
					title: `IDOR: ${testCase.strategy} on ${truncateUrl(testCase.originalUrl)}`,
					url: testCase.originalUrl,
					parameter: testCase.paramName,
					payload: testCase.testedValue ?? testCase.testedUrl,
					evidence: `Original status: ${originalResponse.statusCode}, Modified status: ${modifiedResponse.statusCode}. ` +
						`Body match: ${originalHash === modifiedHash ? 'identical' : 'different'}. ` +
						(sensitiveData.length > 0 ? `Sensitive data found: ${sensitiveData.join(', ')}` : 'No sensitive data patterns detected.'),
					confidence: calculateIdorConfidence(originalResponse, modifiedResponse, sensitiveData, testCase.strategy),
					details: `Strategy: ${testCase.strategy}. Tested "${testCase.originalValue}" → "${testCase.testedValue}". ` +
						`Response indicates the server returned data for a different user/object.`,
					originalUrl: testCase.originalUrl,
					testedUrl: testCase.testedUrl,
					strategy: testCase.strategy,
					originalResponse: {
						statusCode: originalResponse.statusCode,
						bodyHash: originalHash,
						contentLength: originalResponse.body.length,
					},
					modifiedResponse: {
						statusCode: modifiedResponse.statusCode,
						bodyHash: modifiedHash,
						contentLength: modifiedResponse.body.length,
					},
					sensitiveDataFound: sensitiveData,
				});
			}
		} catch {
			// Skip failed requests
		}

		if (options?.delayMs) { await sleep(options.delayMs); }
	}

	return {
		generatedAt: new Date().toISOString(),
		target,
		endpointsTested: testCases.length,
		strategiesUsed: strategies,
		findings,
		elapsedMs: Date.now() - startTime,
	};
}

export function generateIdorReport(result: IdorScanResult): string {
	const lines: string[] = [];
	lines.push('# IDOR Scan Report');
	lines.push('');
	lines.push(`**Target:** \`${result.target}\``);
	lines.push(`**Generated:** ${result.generatedAt}`);
	lines.push(`**Endpoints Tested:** ${result.endpointsTested}`);
	lines.push(`**Strategies:** ${result.strategiesUsed.join(', ')}`);
	lines.push(`**Findings:** ${result.findings.length}`);
	lines.push(`**Duration:** ${result.elapsedMs}ms`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('✅ No IDOR vulnerabilities detected.');
	} else {
		lines.push('---');
		lines.push('');
		for (let i = 0; i < result.findings.length; i++) {
			const f = result.findings[i];
			lines.push(`## ${i + 1}. ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Strategy:** ${f.strategy}`);
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Original URL:** \`${f.originalUrl}\``);
			lines.push(`- **Tested URL:** \`${f.testedUrl}\``);
			if (f.sensitiveDataFound.length > 0) {
				lines.push(`- **⚠️ Sensitive Data:** ${f.sensitiveDataFound.join(', ')}`);
			}
			lines.push('');
			lines.push(`**Evidence:** ${f.evidence}`);
			lines.push('');
			lines.push(`**Details:** ${f.details}`);
			lines.push('');
		}
	}

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Test Case Generation
// ---------------------------------------------------------------------------

function generateTestCases(
	endpoints: Array<{ url: string; method: string }>,
	strategies: IdorStrategy[],
): IdorTestCase[] {
	const testCases: IdorTestCase[] = [];

	for (const endpoint of endpoints) {
		for (const pattern of ID_PATTERNS) {
			// Reset regex lastIndex
			pattern.lastIndex = 0;
			let match: RegExpExecArray | null;

			while ((match = pattern.exec(endpoint.url)) !== null) {
				const originalValue = match[1];
				const fullMatch = match[0];

				for (const strategy of strategies) {
					const replacements = getReplacements(originalValue, strategy);

					for (const replacement of replacements) {
						const testedUrl = endpoint.url.replace(fullMatch,
							fullMatch.replace(originalValue, replacement));

						testCases.push({
							originalUrl: endpoint.url,
							testedUrl,
							method: strategy === 'method-swap' ? swapMethod(endpoint.method) : endpoint.method,
							strategy,
							paramName: extractParamName(fullMatch),
							originalValue,
							testedValue: replacement,
						});
					}
				}
			}
		}
	}

	return testCases;
}

function getReplacements(originalValue: string, strategy: IdorStrategy): string[] {
	switch (strategy) {
		case 'sequential': {
			const num = parseInt(originalValue, 10);
			if (!isNaN(num)) {
				return [String(num + 1), String(num - 1)];
			}
			return [];
		}
		case 'zero-id':
			return ['0', '1', '-1'];
		case 'uuid-swap':
			// Generate a random UUID to test with
			if (originalValue.length === 36 && originalValue.includes('-')) {
				return [crypto.randomUUID()];
			}
			return [];
		case 'remove-param':
			return [''];
		case 'method-swap':
			return [originalValue]; // Same ID, different method
		default:
			return [];
	}
}

// ---------------------------------------------------------------------------
// IDOR Detection Logic
// ---------------------------------------------------------------------------

interface HttpResult {
	statusCode: number;
	body: string;
	headers: Record<string, string>;
}

function detectIdor(
	original: HttpResult,
	modified: HttpResult,
	originalHash: string,
	modifiedHash: string,
	strategy: IdorStrategy,
): boolean {
	// If modified request got 401/403/404, not an IDOR
	if (modified.statusCode === 401 || modified.statusCode === 403 || modified.statusCode === 404) {
		return false;
	}

	// If modified request got same 200 with different content — potential IDOR
	if (modified.statusCode >= 200 && modified.statusCode < 300) {
		// Different body = different user's data = IDOR
		if (originalHash !== modifiedHash && modified.body.length > 50) {
			return true;
		}

		// For zero-id and remove-param: even same body might indicate broken access control
		if (strategy === 'zero-id' || strategy === 'remove-param') {
			if (modified.body.length > 50) {
				return true;
			}
		}
	}

	// Method swap: if changing GET to POST (or vice versa) still returns 200
	if (strategy === 'method-swap' && modified.statusCode >= 200 && modified.statusCode < 300) {
		return true;
	}

	return false;
}

function calculateIdorConfidence(
	original: HttpResult,
	modified: HttpResult,
	sensitiveData: string[],
	strategy: IdorStrategy,
): number {
	let confidence = 0.3; // Base confidence

	// Higher confidence if different body content
	if (hashBody(original.body) !== hashBody(modified.body)) {
		confidence += 0.2;
	}

	// Higher confidence if sensitive data was found
	if (sensitiveData.length > 0) {
		confidence += 0.3;
	}

	// Higher confidence for sequential strategy (more reliable)
	if (strategy === 'sequential') {
		confidence += 0.1;
	}

	// Lower confidence for zero-id (might just be default behavior)
	if (strategy === 'zero-id') {
		confidence -= 0.1;
	}

	return Math.min(Math.max(confidence, 0.1), 1.0);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findSensitiveData(body: string, regexes: RegExp[]): string[] {
	const found: string[] = [];
	for (const regex of regexes) {
		if (regex.test(body)) {
			found.push(regex.source.slice(0, 30) + '...');
		}
	}
	return found;
}

function buildSensitiveRegexes(patterns?: string[]): RegExp[] {
	const sources = patterns && patterns.length > 0 ? patterns : DEFAULT_SENSITIVE_PATTERNS;
	return sources.map(p => {
		try { return new RegExp(p, 'i'); }
		catch { return null; }
	}).filter((r): r is RegExp => r !== null);
}

function hashBody(body: string): string {
	return crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
}

function extractParamName(match: string): string | undefined {
	const paramMatch = match.match(/[?&]([^=]+)=/);
	return paramMatch?.[1];
}

function swapMethod(method: string): string {
	return method.toUpperCase() === 'GET' ? 'POST' : 'GET';
}

function truncateUrl(url: string): string {
	try {
		const parsed = new URL(url);
		return `${parsed.hostname}${parsed.pathname.slice(0, 40)}`;
	} catch {
		return url.slice(0, 50);
	}
}

function loadEndpointsFromCrawl(filePath: string): Array<{ url: string; method: string }> {
	try {
		const urls = loadTargetsFromCrawl(filePath);
		return urls.map(url => ({ url, method: 'GET' }));
	} catch {
		return [];
	}
}

async function performHttpRequest(
	method: string,
	url: string,
	headers: Record<string, string>,
	timeoutMs?: number,
): Promise<HttpResult> {
	try {
		const result = await vscode.commands.executeCommand<{
			response: { statusCode: number; bodyText: string; headers: Record<string, string> };
		}>('scylla.http.sendHeadless', {
			url,
			method,
			headers,
			timeoutMs: timeoutMs ?? 10_000,
			quiet: true,
			maxBodyBytes: 512_000,
		});

		return {
			statusCode: result?.response?.statusCode ?? 0,
			body: result?.response?.bodyText ?? '',
			headers: result?.response?.headers as Record<string, string> ?? {},
		};
	} catch {
		return { statusCode: 0, body: '', headers: {} };
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}
