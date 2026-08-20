/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { loadTargetsFromCrawl } from './artifacts';
import type {
	IdorFinding,
	IdorScanResult,
	IdorStrategy,
} from './types';

// ---------------------------------------------------------------------------
// IDOR Scanner — Insecure Direct Object Reference Detection
// ---------------------------------------------------------------------------

const DEFAULT_SENSITIVE_PATTERNS = [
	'\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+\\b',
	'\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b',
	'\\b\\d{3}[-.\\s]?\\d{2}[-.\\s]?\\d{4}\\b',
	'\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6011)[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b',
	'\\b\\d+\\s+[\\w\\s]+(?:st|nd|rd|th|ave|blvd|dr|ln|rd|way|ct)\\b',
];

const ID_PATTERNS = [
	/\/(\d+)(?:\/|$|\?)/g,
	/[?&](?:id|user_id|userId|account_id|order_id|item_id|pid|uid|oid)=(\d+)/gi,
	/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)/gi,
	/[?&](?:id|uid|uuid|token)=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi,
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

interface HttpResult {
	statusCode: number;
	body: string;
	headers: Record<string, string>;
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

	const endpoints = crawlResultFile
		? loadEndpointsFromCrawl(crawlResultFile)
		: [{ url: target, method: 'GET' }];
	const testCases = generateTestCases(endpoints, strategies);

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
			// Auth extension not available. The scan will not assert cross-user IDOR.
		}
		headerCache.set(key, headers);
		return headers;
	};

	// A real cross-user authorization claim requires two identities. Without two
	// profiles we still enumerate test cases, but deliberately emit no IDOR findings:
	// a 2xx response to a mutated identifier alone is only an observation, not proof.
	if (!usingProfiles || !options?.profiles) {
		return {
			generatedAt: new Date().toISOString(),
			target,
			endpointsTested: testCases.length,
			strategiesUsed: strategies,
			findings,
			elapsedMs: Date.now() - startTime,
		};
	}

	const attackerProfile = options.profiles[0];
	const victimProfile = options.profiles[1];

	for (const testCase of testCases) {
		try {
			// Baseline 1: attacker accesses its original resource-shaped URL.
			const attackerOriginal = await performHttpRequest(
				testCase.method,
				testCase.originalUrl,
				await resolveHeaders(attackerProfile, testCase.originalUrl),
				options.timeoutMs,
			);

			if (options.delayMs) { await sleep(options.delayMs); }

			// Baseline 2: victim accesses the exact mutated URL. This is the critical
			// ownership/visibility baseline that the old implementation was missing.
			const victimBaseline = await performHttpRequest(
				testCase.method,
				testCase.testedUrl,
				await resolveHeaders(victimProfile, testCase.testedUrl),
				options.timeoutMs,
			);

			if (options.delayMs) { await sleep(options.delayMs); }

			// Cross-user probe: attacker requests the same URL proven reachable by victim.
			const attackerCross = await performHttpRequest(
				testCase.method,
				testCase.testedUrl,
				await resolveHeaders(attackerProfile, testCase.testedUrl),
				options.timeoutMs,
			);

			if (!isSuccessful(victimBaseline.statusCode) || !isSuccessful(attackerCross.statusCode)) {
				continue;
			}

			const victimHash = hashBody(victimBaseline.body);
			const attackerCrossHash = hashBody(attackerCross.body);
			const equivalent = responsesEquivalent(victimBaseline, attackerCross);

			// Only promote to a finding when the unauthorized identity receives an
			// equivalent representation of a resource the victim can access. A generic
			// 2xx or merely "different body" is intentionally insufficient.
			if (!equivalent) {
				continue;
			}

			const sensitiveData = findSensitiveData(attackerCross.body, sensitiveRegexes);
			const confidence = calculateIdorConfidence(victimBaseline, attackerCross, sensitiveData);

			findings.push({
				type: 'idor',
				severity: sensitiveData.length > 0 ? 'high' : 'medium',
				title: `IDOR candidate: ${testCase.strategy} on ${truncateUrl(testCase.originalUrl)}`,
				url: testCase.originalUrl,
				parameter: testCase.paramName,
				payload: testCase.testedValue ?? testCase.testedUrl,
				evidence: `Victim profile "${victimProfile}" received ${victimBaseline.statusCode} for ${testCase.testedUrl}; ` +
					`attacker profile "${attackerProfile}" received ${attackerCross.statusCode} for the same URL. ` +
					`Equivalent response: yes (victim hash ${victimHash}, attacker hash ${attackerCrossHash}). ` +
					(sensitiveData.length > 0 ? `Sensitive data patterns: ${sensitiveData.join(', ')}` : 'No configured sensitive-data pattern matched.'),
				confidence,
				details: `Cross-profile authorization candidate. Strategy: ${testCase.strategy}. ` +
					`Identifier mutation: "${testCase.originalValue}" → "${testCase.testedValue}". ` +
					`Attacker baseline status on original URL: ${attackerOriginal.statusCode}. ` +
					`The finding is based on victim-vs-attacker equivalence for the exact same mutated resource URL, not on status code alone.`,
				originalUrl: testCase.originalUrl,
				testedUrl: testCase.testedUrl,
				strategy: testCase.strategy,
				originalResponse: {
					statusCode: victimBaseline.statusCode,
					bodyHash: victimHash,
					contentLength: victimBaseline.body.length,
				},
				modifiedResponse: {
					statusCode: attackerCross.statusCode,
					bodyHash: attackerCrossHash,
					contentLength: attackerCross.body.length,
				},
				sensitiveDataFound: sensitiveData,
			});
		} catch {
			// Network/parser errors are observations, not authorization findings.
		}

		if (options.delayMs) { await sleep(options.delayMs); }
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
	lines.push(`**Test Cases:** ${result.endpointsTested}`);
	lines.push(`**Strategies:** ${result.strategiesUsed.join(', ')}`);
	lines.push(`**Cross-profile Candidates:** ${result.findings.length}`);
	lines.push(`**Duration:** ${result.elapsedMs}ms`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No cross-profile IDOR candidates met the evidence threshold.');
	} else {
		for (let i = 0; i < result.findings.length; i++) {
			const finding = result.findings[i];
			lines.push(`## ${i + 1}. ${finding.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${finding.severity.toUpperCase()}`);
			lines.push(`- **Strategy:** ${finding.strategy}`);
			lines.push(`- **Confidence:** ${Math.round(finding.confidence * 100)}%`);
			lines.push(`- **Original URL:** \`${finding.originalUrl}\``);
			lines.push(`- **Tested URL:** \`${finding.testedUrl}\``);
			lines.push('');
			lines.push(`**Evidence:** ${finding.evidence}`);
			lines.push('');
			lines.push(`**Details:** ${finding.details}`);
			lines.push('');
		}
	}

	return lines.join('\n');
}

function generateTestCases(
	endpoints: Array<{ url: string; method: string }>,
	strategies: IdorStrategy[],
): IdorTestCase[] {
	const testCases: IdorTestCase[] = [];

	for (const endpoint of endpoints) {
		for (const pattern of ID_PATTERNS) {
			pattern.lastIndex = 0;
			let match: RegExpExecArray | null;
			while ((match = pattern.exec(endpoint.url)) !== null) {
				const originalValue = match[1];
				const fullMatch = match[0];
				for (const strategy of strategies) {
					for (const replacement of getReplacements(originalValue, strategy)) {
						const testedUrl = endpoint.url.replace(fullMatch, fullMatch.replace(originalValue, replacement));
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
			return Number.isNaN(num) ? [] : [String(num + 1), String(num - 1)];
		}
		case 'zero-id':
			return ['0', '1', '-1'];
		case 'uuid-swap':
			return originalValue.length === 36 && originalValue.includes('-') ? [crypto.randomUUID()] : [];
		case 'remove-param':
			return [''];
		case 'method-swap':
			return [originalValue];
		default:
			return [];
	}
}

function responsesEquivalent(victim: HttpResult, attacker: HttpResult): boolean {
	if (hashBody(victim.body) === hashBody(attacker.body)) {
		return victim.body.length > 0;
	}

	// Allow small non-semantic variance (timestamps, request IDs, counters) while
	// avoiding the old "any different 2xx body == IDOR" mistake.
	const maxLength = Math.max(victim.body.length, attacker.body.length);
	if (maxLength === 0) { return false; }
	const lengthDiff = Math.abs(victim.body.length - attacker.body.length) / maxLength;
	return lengthDiff <= 0.02 && normalizedBody(victim.body) === normalizedBody(attacker.body);
}

function normalizedBody(body: string): string {
	return body
		.replace(/"(?:request_?id|trace_?id|timestamp|created_at|updated_at)"\s*:\s*"[^"]*"/gi, '"$1":"<dynamic>"')
		.replace(/\s+/g, ' ')
		.trim();
}

function calculateIdorConfidence(victim: HttpResult, attacker: HttpResult, sensitiveData: string[]): number {
	let confidence = hashBody(victim.body) === hashBody(attacker.body) ? 0.85 : 0.72;
	if (sensitiveData.length > 0) { confidence += 0.08; }
	return Math.min(confidence, 0.95);
}

function isSuccessful(statusCode: number): boolean {
	return statusCode >= 200 && statusCode < 300;
}

function findSensitiveData(body: string, regexes: RegExp[]): string[] {
	const found: string[] = [];
	for (const regex of regexes) {
		regex.lastIndex = 0;
		if (regex.test(body)) { found.push(regex.source.slice(0, 30) + '...'); }
	}
	return found;
}

function buildSensitiveRegexes(patterns?: string[]): RegExp[] {
	const sources = patterns && patterns.length > 0 ? patterns : DEFAULT_SENSITIVE_PATTERNS;
	return sources.map(pattern => {
		try { return new RegExp(pattern, 'i'); }
		catch { return null; }
	}).filter((regex): regex is RegExp => regex !== null);
}

function hashBody(body: string): string {
	return crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
}

function extractParamName(match: string): string | undefined {
	return match.match(/[?&]([^=]+)=/)?.[1];
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
		return loadTargetsFromCrawl(filePath).map(url => ({ url, method: 'GET' }));
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
