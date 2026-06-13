/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { loadTargetsFromCrawl } from './artifacts';
import type {
	PrivescFinding,
	PrivescScanResult,
	VulnFinding,
} from './types';

// ---------------------------------------------------------------------------
// Privilege Escalation Scanner — Vertical Broken Access Control
// ---------------------------------------------------------------------------

/**
 * Scans for vertical privilege escalation by:
 * 1. Crawling as high-priv profile → collecting admin-only endpoints
 * 2. Replaying each admin-only request with low-priv profile's session
 * 3. If low-priv gets 200 with similar body → vertical privesc
 */

interface ScanOptions {
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
}

/**
 * List of URL patterns that typically indicate admin or privileged endpoints.
 * Used to prioritize which discovered URLs to test.
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

	// Step 1: Get auth headers for both profiles (scoped to the target host so
	// cookies don't leak cross-host and pollute the access-control comparison).
	const highPrivHeaders = await getProfileHeaders(highPrivProfile, target);
	const lowPrivHeaders = await getProfileHeaders(lowPrivProfile, target);

	if (!highPrivHeaders || !lowPrivHeaders) {
		return {
			generatedAt: new Date().toISOString(),
			target,
			adminEndpointsTested: 0,
			findings: [],
			elapsedMs: Date.now() - startTime,
		};
	}

	// Step 2: Load endpoints (from crawl or single target)
	const allEndpoints = crawlResultFile
		? loadEndpointsFromCrawl(crawlResultFile)
		: [target];

	// Step 3: Filter to admin-like endpoints
	const adminEndpoints = allEndpoints.filter(url => isAdminEndpoint(url));

	// If no admin endpoints found from heuristics, test all endpoints
	const endpointsToTest = adminEndpoints.length > 0 ? adminEndpoints : allEndpoints.slice(0, 50);

	// Step 4: For each admin endpoint, test with low-priv profile
	for (const endpoint of endpointsToTest) {
		try {
			// Request as admin
			const adminResponse = await performHttpRequest(
				'GET',
				endpoint,
				{ ...options?.headers, ...highPrivHeaders },
				options?.timeoutMs,
			);

			if (options?.delayMs) { await sleep(options.delayMs); }

			// Skip if admin doesn't get 200 (endpoint might not exist)
			if (adminResponse.statusCode < 200 || adminResponse.statusCode >= 400) {
				continue;
			}

			// Request as low-priv user
			const lowPrivResponse = await performHttpRequest(
				'GET',
				endpoint,
				{ ...options?.headers, ...lowPrivHeaders },
				options?.timeoutMs,
			);

			// Analyze
			const isPrivesc = analyzePrivesc(adminResponse, lowPrivResponse);

			if (isPrivesc.vulnerable) {
				findings.push({
					type: 'privesc',
					severity: isPrivesc.fullAccess ? 'critical' : 'high',
					title: `Privilege Escalation: ${truncateUrl(endpoint)}`,
					url: endpoint,
					payload: `Admin endpoint accessed as "${lowPrivProfile}"`,
					evidence: `Admin profile "${highPrivProfile}" got ${adminResponse.statusCode} (${adminResponse.body.length} bytes). ` +
						`Low-priv profile "${lowPrivProfile}" got ${lowPrivResponse.statusCode} (${lowPrivResponse.body.length} bytes). ` +
						(isPrivesc.fullAccess
							? 'Low-priv user received identical content — critical vertical privilege escalation.'
							: 'Low-priv user got 200 with different content — possible partial exposure.'),
					confidence: isPrivesc.fullAccess ? 0.9 : 0.7,
					details: `Admin endpoint "${endpoint}" is accessible to low-privilege profile "${lowPrivProfile}". ` +
						`This indicates broken access control — the server does not enforce authorization checks.`,
					adminEndpoint: endpoint,
					method: 'GET',
					adminResponse: {
						statusCode: adminResponse.statusCode,
						contentLength: adminResponse.body.length,
					},
					lowPrivResponse: {
						statusCode: lowPrivResponse.statusCode,
						contentLength: lowPrivResponse.body.length,
					},
					fullAccess: isPrivesc.fullAccess,
					parameter: undefined,
				});
			}
		} catch {
			// Skip failed requests
		}

		if (options?.delayMs) { await sleep(options.delayMs); }
	}

	// Step 5: Also test admin endpoints with POST/PUT/DELETE methods
	for (const endpoint of adminEndpoints.slice(0, 20)) {
		for (const method of ['POST', 'PUT', 'DELETE']) {
			try {
				const lowPrivResponse = await performHttpRequest(
					method,
					endpoint,
					{ ...options?.headers, ...lowPrivHeaders, 'content-type': 'application/json' },
					options?.timeoutMs,
				);

				// If low-priv user can POST/PUT/DELETE to admin endpoint = critical
				if (lowPrivResponse.statusCode >= 200 && lowPrivResponse.statusCode < 400 &&
					lowPrivResponse.statusCode !== 405) {
					findings.push({
						type: 'privesc',
						severity: 'critical',
						title: `Privilege Escalation: ${method} ${truncateUrl(endpoint)}`,
						url: endpoint,
						payload: `${method} as "${lowPrivProfile}" to admin endpoint`,
						evidence: `Low-priv profile "${lowPrivProfile}" can ${method} to admin endpoint. Status: ${lowPrivResponse.statusCode}.`,
						confidence: 0.85,
						details: `Admin endpoint "${endpoint}" accepts ${method} requests from low-privilege profile "${lowPrivProfile}". ` +
							`This could allow data modification or deletion by unauthorized users.`,
						adminEndpoint: endpoint,
						method,
						adminResponse: { statusCode: 200, contentLength: 0 },
						lowPrivResponse: {
							statusCode: lowPrivResponse.statusCode,
							contentLength: lowPrivResponse.body.length,
						},
						fullAccess: true,
						parameter: undefined,
					});
				}
			} catch {
				// Skip
			}

			if (options?.delayMs) { await sleep(options.delayMs); }
		}
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
	lines.push(`**Admin Endpoints Tested:** ${result.adminEndpointsTested}`);
	lines.push(`**Findings:** ${result.findings.length}`);
	lines.push(`**Duration:** ${result.elapsedMs}ms`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('✅ No privilege escalation vulnerabilities detected.');
	} else {
		lines.push('---');
		lines.push('');
		for (let i = 0; i < result.findings.length; i++) {
			const f = result.findings[i];
			lines.push(`## ${i + 1}. ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Method:** ${f.method}`);
			lines.push(`- **Full Access:** ${f.fullAccess ? '⚠️ YES' : 'Partial'}`);
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Admin Response:** ${f.adminResponse.statusCode} (${f.adminResponse.contentLength} bytes)`);
			lines.push(`- **Low-Priv Response:** ${f.lowPrivResponse.statusCode} (${f.lowPrivResponse.contentLength} bytes)`);
			lines.push('');
			lines.push(`**Evidence:** ${f.evidence}`);
			lines.push('');
		}
	}

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Detection Logic
// ---------------------------------------------------------------------------

interface PrivescAnalysis {
	vulnerable: boolean;
	fullAccess: boolean;
}

function analyzePrivesc(
	adminResponse: HttpResult,
	lowPrivResponse: HttpResult,
): PrivescAnalysis {
	// If low-priv gets 401/403 → properly protected
	if (lowPrivResponse.statusCode === 401 || lowPrivResponse.statusCode === 403) {
		return { vulnerable: false, fullAccess: false };
	}

	// If low-priv gets 404 → endpoint doesn't exist for them (could be hidden)
	if (lowPrivResponse.statusCode === 404) {
		return { vulnerable: false, fullAccess: false };
	}

	// If low-priv gets 200 with similar content length → full access
	if (lowPrivResponse.statusCode >= 200 && lowPrivResponse.statusCode < 300) {
		const lengthDiff = Math.abs(adminResponse.body.length - lowPrivResponse.body.length);
		const fullAccess = lengthDiff < Math.max(adminResponse.body.length * 0.1, 100);
		return { vulnerable: true, fullAccess };
	}

	// If low-priv gets 302 redirect → might be redirecting to login (not vulnerable)
	if (lowPrivResponse.statusCode === 302 || lowPrivResponse.statusCode === 301) {
		return { vulnerable: false, fullAccess: false };
	}

	return { vulnerable: false, fullAccess: false };
}

function isAdminEndpoint(url: string): boolean {
	return ADMIN_PATH_PATTERNS.some(pattern => pattern.test(url));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface HttpResult {
	statusCode: number;
	body: string;
	headers: Record<string, string>;
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
	try {
		return loadTargetsFromCrawl(filePath);
	} catch {
		return [];
	}
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
