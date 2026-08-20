/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { loadTargetsFromCrawl } from './artifacts';
import type {
	PrivescFinding,
	PrivescScanResult,
} from './types';

// ---------------------------------------------------------------------------
// Privilege Escalation Scanner — Vertical Broken Access Control
// ---------------------------------------------------------------------------

interface ScanOptions {
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
}

interface HttpResult {
	statusCode: number;
	body: string;
	headers: Record<string, string>;
}

interface PrivescAnalysis {
	candidate: boolean;
	equivalent: boolean;
	confidence: number;
}

/** Extract the lowercased host from a URL (or bare host) for per-host header caching. */
function hostOf(url: string): string {
	try { return new URL(url.includes('://') ? url : `http://${url}`).hostname.toLowerCase(); }
	catch { return url.toLowerCase(); }
}

/**
 * URL heuristics are discovery hints only. They never establish that an endpoint
 * is privileged. A finding still requires a high-priv baseline and a low-priv
 * response that is equivalent enough to that baseline to justify review.
 */
const ADMIN_PATH_PATTERNS = [
	/\/admin/i,
	/\/dashboard/i,
	/\/manage/i,
	/\/settings/i,
	/\/config/i,
	/\/users/i,
	/\/control/i,
	/\/panel/i,
	/\/console/i,
	/\/internal/i,
	/\/staff/i,
	/\/moderator/i,
	/\/billing/i,
	/\/analytics/i,
	/\/reports/i,
	/\/audit/i,
	/\/permissions/i,
	/\/roles/i,
	/\/api\/v\d+\/admin/i,
	/\/api\/admin/i,
	/\/api\/internal/i,
];

export async function scanPrivesc(
	target: string,
	crawlResultFile: string | undefined,
	highPrivProfile: string,
	lowPrivProfile: string,
	options?: ScanOptions,
): Promise<PrivescScanResult> {
	const startTime = Date.now();
	const findings: PrivescFinding[] = [];
	const headerCache = new Map<string, Record<string, string>>();

	const resolveHeaders = async (profileName: string, url: string): Promise<Record<string, string> | undefined> => {
		const key = `${profileName}\n${hostOf(url)}`;
		const cached = headerCache.get(key);
		if (cached) { return cached; }
		const headers = await getProfileHeaders(profileName, url);
		if (!headers) { return undefined; }
		headerCache.set(key, headers);
		return headers;
	};

	// Both identities are mandatory. A missing auth context is not a negative test;
	// silently replacing it with anonymous headers would corrupt the comparison.
	const initialHigh = await resolveHeaders(highPrivProfile, target);
	const initialLow = await resolveHeaders(lowPrivProfile, target);
	if (!initialHigh || !initialLow) {
		return emptyResult(target, startTime);
	}

	const allEndpoints = crawlResultFile ? loadEndpointsFromCrawl(crawlResultFile) : [target];
	const adminLike = allEndpoints.filter(isAdminEndpoint);
	const endpointsToTest = adminLike.length > 0 ? adminLike : allEndpoints.slice(0, 50);

	// P0 safety rule: PrivEsc is observation-only with GET. The previous scanner
	// automatically fired POST/PUT/DELETE at admin-like routes and treated any 2xx
	// as critical. State-changing probes will return later behind explicit consent.
	for (const endpoint of endpointsToTest) {
		try {
			const highHeaders = await resolveHeaders(highPrivProfile, endpoint);
			const lowHeaders = await resolveHeaders(lowPrivProfile, endpoint);
			if (!highHeaders || !lowHeaders) { continue; }

			const highResponse = await performHttpRequest(
				'GET',
				endpoint,
				{ ...options?.headers, ...highHeaders },
				options?.timeoutMs,
			);
			if (options?.delayMs) { await sleep(options.delayMs); }

			// If the high-priv identity cannot access it, this is not a useful
			// privileged baseline and must not be used to accuse the low-priv role.
			if (!isSuccessful(highResponse.statusCode)) { continue; }

			const lowResponse = await performHttpRequest(
				'GET',
				endpoint,
				{ ...options?.headers, ...lowHeaders },
				options?.timeoutMs,
			);

			const analysis = analyzePrivesc(highResponse, lowResponse);
			if (!analysis.candidate) { continue; }

			findings.push({
				type: 'privesc',
				severity: analysis.equivalent ? 'high' : 'medium',
				title: `Privilege escalation candidate: ${truncateUrl(endpoint)}`,
				url: endpoint,
				payload: `GET as "${lowPrivProfile}" against high-priv baseline "${highPrivProfile}"`,
				evidence: `High-priv profile "${highPrivProfile}" received ${highResponse.statusCode} (${highResponse.body.length} bytes). ` +
					`Low-priv profile "${lowPrivProfile}" received ${lowResponse.statusCode} (${lowResponse.body.length} bytes). ` +
					`Equivalent representation: ${analysis.equivalent ? 'yes' : 'partial'}.`,
				confidence: analysis.confidence,
				details: `This is a read-only authorization candidate derived from a same-endpoint, cross-role baseline. ` +
					`The endpoint-name heuristic only selected the target for testing; it did not determine impact. ` +
					`No POST, PUT, PATCH, or DELETE request was issued by this scanner.`,
				adminEndpoint: endpoint,
				method: 'GET',
				adminResponse: {
					statusCode: highResponse.statusCode,
					contentLength: highResponse.body.length,
				},
				lowPrivResponse: {
					statusCode: lowResponse.statusCode,
					contentLength: lowResponse.body.length,
				},
				fullAccess: analysis.equivalent,
				parameter: undefined,
			});
		} catch {
			// A failed request is not evidence of authorization behavior.
		}

		if (options?.delayMs) { await sleep(options.delayMs); }
	}

	return {
		generatedAt: new Date().toISOString(),
		target,
		adminEndpointsTested: endpointsToTest.length,
		findings,
		elapsedMs: Date.now() - startTime,
	};
}

export function generatePrivescReport(result: PrivescScanResult): string {
	const lines: string[] = [];
	lines.push('# Privilege Escalation Scan Report');
	lines.push('');
	lines.push(`**Target:** \`${result.target}\``);
	lines.push(`**Generated:** ${result.generatedAt}`);
	lines.push(`**Read-only Endpoints Tested:** ${result.adminEndpointsTested}`);
	lines.push(`**Authorization Candidates:** ${result.findings.length}`);
	lines.push(`**Duration:** ${result.elapsedMs}ms`);
	lines.push('');
	lines.push('> Safety mode: this scanner issues GET requests only. State-changing privilege probes are disabled by default.');
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No cross-role candidates met the evidence threshold.');
	} else {
		for (let i = 0; i < result.findings.length; i++) {
			const finding = result.findings[i];
			lines.push(`## ${i + 1}. ${finding.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${finding.severity.toUpperCase()}`);
			lines.push(`- **Method:** ${finding.method}`);
			lines.push(`- **Equivalent Access:** ${finding.fullAccess ? 'YES' : 'Partial'}`);
			lines.push(`- **Confidence:** ${Math.round(finding.confidence * 100)}%`);
			lines.push(`- **High-Priv Response:** ${finding.adminResponse.statusCode} (${finding.adminResponse.contentLength} bytes)`);
			lines.push(`- **Low-Priv Response:** ${finding.lowPrivResponse.statusCode} (${finding.lowPrivResponse.contentLength} bytes)`);
			lines.push('');
			lines.push(`**Evidence:** ${finding.evidence}`);
			lines.push('');
		}
	}

	return lines.join('\n');
}

function analyzePrivesc(high: HttpResult, low: HttpResult): PrivescAnalysis {
	if (!isSuccessful(low.statusCode)) {
		return { candidate: false, equivalent: false, confidence: 0 };
	}

	const highHash = semanticHash(high.body);
	const lowHash = semanticHash(low.body);
	if (highHash === lowHash && high.body.length > 0) {
		return { candidate: true, equivalent: true, confidence: 0.9 };
	}

	// A 2xx alone is never enough. Permit a lower-confidence candidate only when
	// response shape is strongly similar; it is intentionally not labeled "full access".
	const maxLength = Math.max(high.body.length, low.body.length);
	if (maxLength === 0) {
		return { candidate: false, equivalent: false, confidence: 0 };
	}
	const lengthRatio = Math.abs(high.body.length - low.body.length) / maxLength;
	if (lengthRatio <= 0.05 && normalizedBody(high.body) === normalizedBody(low.body)) {
		return { candidate: true, equivalent: false, confidence: 0.72 };
	}

	return { candidate: false, equivalent: false, confidence: 0 };
}

function semanticHash(body: string): string {
	return crypto.createHash('sha256').update(normalizedBody(body)).digest('hex').slice(0, 16);
}

function normalizedBody(body: string): string {
	return body
		.replace(/"(?:request_?id|trace_?id|timestamp|created_at|updated_at)"\s*:\s*"[^"]*"/gi, '"dynamic":"<redacted>"')
		.replace(/\s+/g, ' ')
		.trim();
}

function isSuccessful(statusCode: number): boolean {
	return statusCode >= 200 && statusCode < 300;
}

function isAdminEndpoint(url: string): boolean {
	return ADMIN_PATH_PATTERNS.some(pattern => pattern.test(url));
}

async function getProfileHeaders(profileName: string, targetUrl?: string): Promise<Record<string, string> | undefined> {
	try {
		const result = await vscode.commands.executeCommand<{ headers: Record<string, string> }>(
			'scylla.auth.getHeadersHeadless',
			{ profileName, targetUrl }
		);
		return result?.headers;
	} catch {
		return undefined;
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

function loadEndpointsFromCrawl(filePath: string): string[] {
	try { return loadTargetsFromCrawl(filePath); }
	catch { return []; }
}

function emptyResult(target: string, startTime: number): PrivescScanResult {
	return {
		generatedAt: new Date().toISOString(),
		target,
		adminEndpointsTested: 0,
		findings: [],
		elapsedMs: Date.now() - startTime,
	};
}

function truncateUrl(url: string): string {
	try {
		const parsed = new URL(url);
		return `${parsed.hostname}${parsed.pathname.slice(0, 40)}`;
	} catch {
		return url.slice(0, 50);
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}
