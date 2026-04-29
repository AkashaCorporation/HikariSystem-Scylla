/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { HeadersScanResult, VulnFinding, VulnSeverity } from './types';

const DEFAULT_TIMEOUT_MS = 15_000;

interface HeaderCheck {
	/** Canonical header name (lowercase for comparison). */
	header: string;
	/** Display-friendly header name. */
	displayName: string;
	/** Severity when the header is missing. */
	missingSeverity: VulnSeverity;
	/** Description when missing. */
	missingDescription: string;
	/**
	 * If the header is present, optionally inspect its value.
	 * Return a VulnFinding if misconfigured, or null if OK.
	 */
	inspectValue?: (value: string, targetUrl: string) => VulnFinding | null;
}

interface DisclosureCheck {
	/** Canonical header name (lowercase). */
	header: string;
	displayName: string;
	severity: VulnSeverity;
	/**
	 * Evaluate whether the present header represents a finding.
	 * Return a VulnFinding or null.
	 */
	inspect: (value: string, targetUrl: string) => VulnFinding | null;
}

// -----------------------------------------------------------------------
// Header baseline definitions
// -----------------------------------------------------------------------

const SECURITY_HEADER_CHECKS: HeaderCheck[] = [
	{
		header: 'strict-transport-security',
		displayName: 'Strict-Transport-Security',
		missingSeverity: 'medium',
		missingDescription: 'HSTS header is missing. Without it, browsers will not enforce HTTPS, leaving users vulnerable to SSL-stripping attacks.',
		inspectValue(value: string, targetUrl: string): VulnFinding | null {
			// Warn if max-age is too low (< 6 months = 15552000)
			const match = value.match(/max-age=(\d+)/i);
			if (match) {
				const maxAge = parseInt(match[1], 10);
				if (maxAge < 15552000) {
					return {
						type: 'headers',
						severity: 'low',
						title: 'HSTS max-age Too Short',
						url: targetUrl,
						payload: 'N/A',
						evidence: `Strict-Transport-Security: ${value}`,
						confidence: 0.9,
						details: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). A minimum of 15552000 seconds (180 days) is recommended.`,
					};
				}
			}
			return null;
		},
	},
	{
		header: 'x-content-type-options',
		displayName: 'X-Content-Type-Options',
		missingSeverity: 'low',
		missingDescription: 'X-Content-Type-Options header is missing. Without "nosniff", browsers may MIME-sniff responses, enabling content-type confusion attacks.',
		inspectValue(value: string, targetUrl: string): VulnFinding | null {
			if (value.toLowerCase().trim() !== 'nosniff') {
				return {
					type: 'headers',
					severity: 'low',
					title: 'X-Content-Type-Options Misconfigured',
					url: targetUrl,
					payload: 'N/A',
					evidence: `X-Content-Type-Options: ${value}`,
					confidence: 0.9,
					details: `Expected "nosniff" but found "${value}".`,
				};
			}
			return null;
		},
	},
	{
		header: 'x-frame-options',
		displayName: 'X-Frame-Options',
		missingSeverity: 'medium',
		missingDescription: 'X-Frame-Options header is missing. The page may be embeddable in iframes, enabling clickjacking attacks. Consider using CSP frame-ancestors as a modern alternative.',
	},
	{
		header: 'content-security-policy',
		displayName: 'Content-Security-Policy',
		missingSeverity: 'medium',
		missingDescription: 'Content-Security-Policy header is missing. CSP is a critical defense-in-depth mechanism against XSS and data injection attacks.',
		inspectValue(value: string, targetUrl: string): VulnFinding | null {
			// Check for overly permissive directives
			if (/\bunsafe-inline\b/.test(value) && /\bunsafe-eval\b/.test(value)) {
				return {
					type: 'headers',
					severity: 'medium',
					title: 'CSP Contains unsafe-inline and unsafe-eval',
					url: targetUrl,
					payload: 'N/A',
					evidence: `Content-Security-Policy: ${value.length > 200 ? value.substring(0, 200) + '...' : value}`,
					confidence: 0.8,
					details: 'The Content-Security-Policy uses both \'unsafe-inline\' and \'unsafe-eval\', significantly reducing its effectiveness against XSS.',
				};
			}
			return null;
		},
	},
	{
		header: 'x-xss-protection',
		displayName: 'X-XSS-Protection',
		missingSeverity: 'info',
		missingDescription: 'X-XSS-Protection header is absent. While deprecated in modern browsers, its absence is noted for completeness.',
		inspectValue(value: string, targetUrl: string): VulnFinding | null {
			if (value.trim() === '0') {
				return {
					type: 'headers',
					severity: 'info',
					title: 'X-XSS-Protection Explicitly Disabled',
					url: targetUrl,
					payload: 'N/A',
					evidence: `X-XSS-Protection: ${value}`,
					confidence: 0.9,
					details: 'X-XSS-Protection is explicitly set to "0", disabling the browser\'s built-in XSS filter. While the header is deprecated, setting it to 0 with no CSP in place removes a layer of defense.',
				};
			}
			return null;
		},
	},
	{
		header: 'referrer-policy',
		displayName: 'Referrer-Policy',
		missingSeverity: 'low',
		missingDescription: 'Referrer-Policy header is missing. Without it, the browser may send the full URL (including query parameters) as the Referer to third-party sites, potentially leaking sensitive data.',
	},
	{
		header: 'permissions-policy',
		displayName: 'Permissions-Policy',
		missingSeverity: 'low',
		missingDescription: 'Permissions-Policy header is missing. This header restricts access to browser features (camera, microphone, geolocation, etc.) and should be set to limit feature exposure.',
	},
	{
		header: 'cache-control',
		displayName: 'Cache-Control',
		missingSeverity: 'low',
		missingDescription: 'Cache-Control header is missing. Sensitive pages may be cached by proxies or browsers, allowing unauthorized access to previously rendered content.',
		inspectValue(value: string, targetUrl: string): VulnFinding | null {
			const lv = value.toLowerCase();
			// Warn if the page allows public caching with no revalidation
			if (lv.includes('public') && !lv.includes('no-store') && !lv.includes('no-cache')) {
				return {
					type: 'headers',
					severity: 'low',
					title: 'Cache-Control Allows Public Caching',
					url: targetUrl,
					payload: 'N/A',
					evidence: `Cache-Control: ${value}`,
					confidence: 0.7,
					details: 'Cache-Control is set to "public" without "no-store" or "no-cache". If the page contains sensitive data, it may be cached by intermediate proxies.',
				};
			}
			return null;
		},
	},
];

const DISCLOSURE_CHECKS: DisclosureCheck[] = [
	{
		header: 'x-powered-by',
		displayName: 'X-Powered-By',
		severity: 'info',
		inspect(value: string, targetUrl: string): VulnFinding {
			return {
				type: 'headers',
				severity: 'info',
				title: 'Information Disclosure: X-Powered-By',
				url: targetUrl,
				payload: 'N/A',
				evidence: `X-Powered-By: ${value}`,
				confidence: 0.95,
				details: `The X-Powered-By header exposes the server technology ("${value}"). This information helps attackers fingerprint the stack and target known vulnerabilities.`,
			};
		},
	},
	{
		header: 'server',
		displayName: 'Server',
		severity: 'info',
		inspect(value: string, targetUrl: string): VulnFinding | null {
			// Only flag if the header is overly detailed (contains version info)
			if (/\d+\.\d+/.test(value)) {
				return {
					type: 'headers',
					severity: 'info',
					title: 'Information Disclosure: Server Version',
					url: targetUrl,
					payload: 'N/A',
					evidence: `Server: ${value}`,
					confidence: 0.9,
					details: `The Server header discloses detailed version information ("${value}"). Attackers can use this to identify known vulnerabilities for the specific version.`,
				};
			}
			return null;
		},
	},
];

// The set of security headers we check for presence
const SECURITY_HEADER_NAMES = SECURITY_HEADER_CHECKS.map(c => c.displayName);

// -----------------------------------------------------------------------
// Scanner entry point
// -----------------------------------------------------------------------

export async function scanHeaders(
	targetUrl: string,
	options: {
		headers?: Record<string, string>;
		cookie?: string;
		timeoutMs?: number;
	} = {}
): Promise<HeadersScanResult> {
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	const findings: VulnFinding[] = [];
	const presentHeaders: string[] = [];
	const missingHeaders: string[] = [];
	const start = Date.now();

	// Send a single GET request
	const responseHeaders = await fetchHeaders(targetUrl, timeoutMs, options.headers, options.cookie);

	if (!responseHeaders) {
		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			findings: [{
				type: 'headers',
				severity: 'info',
				title: 'Unable to Fetch Headers',
				url: targetUrl,
				payload: 'N/A',
				evidence: 'HTTP request failed or timed out',
				confidence: 1.0,
				details: 'The scanner was unable to retrieve HTTP response headers from the target. The host may be unreachable or the request timed out.',
			}],
			presentHeaders: [],
			missingHeaders: SECURITY_HEADER_NAMES,
			elapsedMs: Date.now() - start,
		};
	}

	const isHttps = targetUrl.startsWith('https://') || targetUrl.startsWith('https%3A');

	// Evaluate security header presence / absence
	for (const check of SECURITY_HEADER_CHECKS) {
		const value = responseHeaders[check.header];

		// HSTS only applies to HTTPS origins
		if (check.header === 'strict-transport-security' && !isHttps) {
			continue;
		}

		if (value === undefined) {
			missingHeaders.push(check.displayName);
			findings.push({
				type: 'headers',
				severity: check.missingSeverity,
				title: `Missing Security Header: ${check.displayName}`,
				url: targetUrl,
				payload: 'N/A',
				evidence: `Header "${check.displayName}" is absent from the response.`,
				confidence: 1.0,
				details: check.missingDescription,
			});
		} else {
			presentHeaders.push(check.displayName);
			// Inspect the value for misconfigurations
			if (check.inspectValue) {
				const finding = check.inspectValue(value, targetUrl);
				if (finding) {
					findings.push(finding);
				}
			}
		}
	}

	// Information disclosure checks
	for (const check of DISCLOSURE_CHECKS) {
		const value = responseHeaders[check.header];
		if (value !== undefined) {
			const finding = check.inspect(value, targetUrl);
			if (finding) {
				findings.push(finding);
			}
		}
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		findings,
		presentHeaders,
		missingHeaders,
		elapsedMs: Date.now() - start,
	};
}

async function fetchHeaders(
	targetUrl: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<Record<string, string> | null> {
	try {
		const requestHeaders: Record<string, string> = { ...(headers ?? {}) };
		if (cookie) {
			requestHeaders['cookie'] = cookie;
		}

		const result = await vscode.commands.executeCommand<{
			response: {
				statusCode: number;
				bodyText: string;
				elapsedMs: number;
				headers?: Record<string, string>;
			};
		}>('scylla.http.sendHeadless', {
			url: targetUrl,
			method: 'GET',
			timeoutMs,
			followRedirects: true,
			quiet: true,
			headers: requestHeaders,
		});

		if (!result?.response?.headers) { return null; }

		// Normalize header keys to lowercase
		const normalized: Record<string, string> = {};
		for (const [key, value] of Object.entries(result.response.headers)) {
			normalized[key.toLowerCase()] = value;
		}
		return normalized;
	} catch {
		return null;
	}
}

export function generateHeadersReport(result: HeadersScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - Security Headers Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Present Headers:** ${result.presentHeaders.length}`);
	lines.push(`- **Missing Headers:** ${result.missingHeaders.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.presentHeaders.length > 0) {
		lines.push('## Present Security Headers');
		lines.push('');
		for (const h of result.presentHeaders) {
			lines.push(`- ${h}`);
		}
		lines.push('');
	}

	if (result.missingHeaders.length > 0) {
		lines.push('## Missing Security Headers');
		lines.push('');
		for (const h of result.missingHeaders) {
			lines.push(`- ${h}`);
		}
		lines.push('');
	}

	if (result.findings.length === 0) {
		lines.push('No security header issues detected.');
	} else {
		lines.push('## Detailed Findings');
		lines.push('');
		for (const f of result.findings) {
			lines.push(`### ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Evidence:** ${f.evidence}`);
			lines.push('');
			lines.push(f.details);
			lines.push('');
		}
	}

	return lines.join('\n');
}
