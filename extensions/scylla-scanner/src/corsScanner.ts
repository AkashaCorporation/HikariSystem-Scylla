/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { CorsScanResult, VulnFinding } from './types';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_DELAY_MS = 100;

interface CorsTestCase {
	name: string;
	origin: string;
	severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
	description: string;
}

function buildTestCases(targetUrl: string): CorsTestCase[] {
	const url = new URL(targetUrl);
	const targetHost = url.hostname;
	const targetProtocol = url.protocol;

	const cases: CorsTestCase[] = [
		// 1. Arbitrary origin reflection
		{
			name: 'arbitrary-origin',
			origin: 'https://evil.com',
			severity: 'critical',
			description: 'Arbitrary origin reflection: the server reflects any Origin, allowing any attacker-controlled site to read authenticated responses.',
		},
		// 2. Null origin (sandboxed iframe / data URI)
		{
			name: 'null-origin',
			origin: 'null',
			severity: 'high',
			description: 'Null origin accepted: the server allows the "null" Origin, exploitable via sandboxed iframes or data: URIs.',
		},
		// 3a. Subdomain bypass - prefix match (evil.example.com)
		{
			name: 'subdomain-prefix',
			origin: `https://evil.${targetHost}`,
			severity: 'medium',
			description: `Subdomain prefix bypass: the server accepts origins under a fabricated subdomain (evil.${targetHost}), suggesting weak wildcard or suffix matching.`,
		},
		// 3b. Subdomain bypass - suffix match (example.com.evil.com)
		{
			name: 'subdomain-suffix',
			origin: `https://${targetHost}.evil.com`,
			severity: 'medium',
			description: `Subdomain suffix bypass: the server accepts an attacker domain with the target as a prefix (${targetHost}.evil.com), suggesting inadequate origin validation.`,
		},
		// 5. Localhost acceptance
		{
			name: 'localhost',
			origin: 'http://localhost',
			severity: 'low',
			description: 'Localhost origin accepted: the server allows http://localhost, which may be exploitable if an attacker can run code on the victim\'s machine.',
		},
		{
			name: 'localhost-ip',
			origin: 'http://127.0.0.1',
			severity: 'low',
			description: 'Loopback IP origin accepted: the server allows http://127.0.0.1, similar risk to localhost acceptance.',
		},
	];

	// 4. Protocol downgrade: only test if the target is HTTPS
	if (targetProtocol === 'https:') {
		cases.splice(4, 0, {
			name: 'protocol-downgrade',
			origin: `http://${targetHost}`,
			severity: 'medium',
			description: `Protocol downgrade accepted: the HTTPS site allows an HTTP origin (http://${targetHost}), enabling a MitM attacker on the network to steal cross-origin data.`,
		});
	}

	return cases;
}

async function sendCorsRequest(
	targetUrl: string,
	method: 'OPTIONS' | 'GET',
	origin: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{
	statusCode: number;
	headers: Record<string, string>;
	elapsedMs: number;
} | null> {
	try {
		const requestHeaders: Record<string, string> = {
			...(headers ?? {}),
			'Origin': origin,
		};

		if (cookie) {
			requestHeaders['cookie'] = cookie;
		}

		if (method === 'OPTIONS') {
			requestHeaders['Access-Control-Request-Method'] = 'GET';
			requestHeaders['Access-Control-Request-Headers'] = 'Content-Type, Authorization';
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
			method,
			timeoutMs,
			followRedirects: true,
			quiet: true,
			headers: requestHeaders,
		});

		if (!result?.response) { return null; }

		// Normalize header keys to lowercase
		const normalizedHeaders: Record<string, string> = {};
		if (result.response.headers) {
			for (const [key, value] of Object.entries(result.response.headers)) {
				normalizedHeaders[key.toLowerCase()] = value;
			}
		}

		return {
			statusCode: result.response.statusCode,
			headers: normalizedHeaders,
			elapsedMs: result.response.elapsedMs,
		};
	} catch {
		return null;
	}
}

function evaluateCorsResponse(
	testCase: CorsTestCase,
	targetUrl: string,
	responseHeaders: Record<string, string>,
	method: 'OPTIONS' | 'GET',
): VulnFinding | null {
	const acao = responseHeaders['access-control-allow-origin'];
	const acac = responseHeaders['access-control-allow-credentials'];

	if (!acao) { return null; }

	const credentialsAllowed = acac?.toLowerCase() === 'true';

	// Check if the origin is reflected or wildcarded
	const originReflected = acao === testCase.origin;
	const isWildcard = acao === '*';

	if (!originReflected && !isWildcard) { return null; }

	// 6. Wildcard with credentials (special case - always a misconfiguration)
	if (isWildcard && credentialsAllowed) {
		return {
			type: 'cors',
			severity: 'critical',
			title: 'CORS: Wildcard Origin with Credentials',
			url: targetUrl,
			payload: `Origin: ${testCase.origin}`,
			evidence: `ACAO: ${acao}, ACAC: ${acac} (via ${method})`,
			confidence: 0.95,
			details: `The server returns Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true. While browsers block this combination, it indicates a severe misconfiguration. Tested with Origin: ${testCase.origin}.`,
		};
	}

	// Wildcard alone without credentials is generally acceptable for public APIs
	if (isWildcard && !credentialsAllowed) { return null; }

	// Origin is reflected - determine severity based on the test case
	let severity = testCase.severity;
	let confidence = 0.9;

	// Upgrade severity to critical if credentials are also allowed with arbitrary origin
	if (testCase.name === 'arbitrary-origin' && credentialsAllowed) {
		severity = 'critical';
		confidence = 0.95;
	} else if (testCase.name === 'arbitrary-origin' && !credentialsAllowed) {
		// Reflected but no credentials - downgrade
		severity = 'medium';
		confidence = 0.8;
	}

	if (testCase.name === 'null-origin' && credentialsAllowed) {
		severity = 'high';
		confidence = 0.9;
	} else if (testCase.name === 'null-origin' && !credentialsAllowed) {
		severity = 'medium';
		confidence = 0.75;
	}

	const credStr = credentialsAllowed ? ' with credentials' : ' without credentials';

	return {
		type: 'cors',
		severity,
		title: `CORS Misconfiguration: ${testCase.name}`,
		url: targetUrl,
		payload: `Origin: ${testCase.origin}`,
		evidence: `ACAO: ${acao}, ACAC: ${acac ?? '(absent)'} (via ${method})`,
		confidence,
		details: `${testCase.description} The server reflected the origin${credStr}.`,
	};
}

export async function scanCors(
	targetUrl: string,
	options: {
		headers?: Record<string, string>;
		cookie?: string;
		timeoutMs?: number;
		delayMs?: number;
	} = {}
): Promise<CorsScanResult> {
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;

	const findings: VulnFinding[] = [];
	const start = Date.now();
	const testCases = buildTestCases(targetUrl);

	for (const testCase of testCases) {
		// Send a preflight OPTIONS request first
		const preflightResponse = await sendCorsRequest(
			targetUrl, 'OPTIONS', testCase.origin, timeoutMs,
			options.headers, options.cookie,
		);

		if (preflightResponse) {
			const finding = evaluateCorsResponse(
				testCase, targetUrl, preflightResponse.headers, 'OPTIONS',
			);
			if (finding) {
				findings.push(finding);
			}
		}

		if (delayMs > 0) { await sleep(delayMs); }

		// Send a GET request with the same Origin header
		const getResponse = await sendCorsRequest(
			targetUrl, 'GET', testCase.origin, timeoutMs,
			options.headers, options.cookie,
		);

		if (getResponse) {
			// Only add if we didn't already find the same issue via preflight
			const existingPreflight = findings.find(
				f => f.type === 'cors' && f.payload === `Origin: ${testCase.origin}`
			);
			if (!existingPreflight) {
				const finding = evaluateCorsResponse(
					testCase, targetUrl, getResponse.headers, 'GET',
				);
				if (finding) {
					findings.push(finding);
				}
			}
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		findings,
		elapsedMs: Date.now() - start,
	};
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateCorsReport(result: CorsScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - CORS Misconfiguration Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No CORS misconfigurations detected.');
	} else {
		for (const f of result.findings) {
			lines.push(`## ${f.title}`);
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

	return lines.join('\n');
}
