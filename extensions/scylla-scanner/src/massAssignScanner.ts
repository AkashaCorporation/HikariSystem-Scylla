/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as vscode from 'vscode';
import { loadTargetsFromCrawl } from './artifacts';
import type {
	MassAssignCategory,
	MassAssignFinding,
	MassAssignScanResult,
	CrawlResultFile,
} from './types';

// ---------------------------------------------------------------------------
// Mass Assignment Scanner — Parameter Pollution / Attribute Binding
// ---------------------------------------------------------------------------

/**
 * Payload sets organized by category.
 * These are extra fields injected into POST/PUT/PATCH requests
 * to test if the server blindly accepts them.
 */
const PAYLOAD_SETS: Record<MassAssignCategory, Record<string, unknown>[]> = {
	'role-escalation': [
		{ role: 'admin' },
		{ isAdmin: true },
		{ is_admin: true },
		{ is_staff: 1 },
		{ admin: true },
		{ user_role: 'administrator' },
		{ type: 'admin' },
		{ permissions: ['admin', 'write', 'delete'] },
		{ group: 'administrators' },
		{ level: 999 },
	],
	'financial': [
		{ price: 0 },
		{ amount: 0.01 },
		{ discount: 100 },
		{ total: 0 },
		{ quantity: -1 },
		{ balance: 999999 },
		{ credits: 999999 },
		{ fee: 0 },
		{ tax: 0 },
	],
	'verification-bypass': [
		{ verified: true },
		{ email_verified: true },
		{ emailVerified: true },
		{ confirmed: true },
		{ active: true },
		{ approved: true },
		{ status: 'approved' },
		{ account_status: 'active' },
		{ banned: false },
	],
	'password-change': [
		{ password: 'scylla_test_pass123!' },
		{ new_password: 'scylla_test_pass123!' },
		{ password_confirmation: 'scylla_test_pass123!' },
	],
};

interface ScanOptions {
	categories?: MassAssignCategory[];
	customFields?: Record<string, unknown>;
	profileName?: string;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
}

export async function scanMassAssign(
	target: string,
	crawlResultFile: string | undefined,
	options?: ScanOptions,
): Promise<MassAssignScanResult> {
	const startTime = Date.now();
	const findings: MassAssignFinding[] = [];

	const categories: MassAssignCategory[] = options?.categories ??
		['role-escalation', 'financial', 'verification-bypass'];

	// Get auth headers
	const authHeaders = await getAuthHeaders(options?.profileName, options?.headers, options?.cookie);

	// Find POST/PUT/PATCH endpoints
	const endpoints = crawlResultFile
		? loadFormEndpoints(crawlResultFile)
		: extractEndpointFromUrl(target);

	let endpointsTested = 0;

	for (const endpoint of endpoints) {
		endpointsTested++;

		for (const category of categories) {
			const payloads = PAYLOAD_SETS[category] ?? [];

			for (const payload of payloads) {
				try {
					// Step 1: Send original request (baseline)
					const originalBody = endpoint.originalBody ?? {};
					const originalResponse = await performHttpRequest(
						endpoint.method,
						endpoint.url,
						JSON.stringify(originalBody),
						{
							'content-type': 'application/json',
							...authHeaders,
						},
						options?.timeoutMs,
					);

					if (options?.delayMs) { await sleep(options.delayMs); }

					// Step 2: Send request with injected fields
					const modifiedBody = { ...originalBody, ...payload };
					const modifiedResponse = await performHttpRequest(
						endpoint.method,
						endpoint.url,
						JSON.stringify(modifiedBody),
						{
							'content-type': 'application/json',
							...authHeaders,
						},
						options?.timeoutMs,
					);

					// Step 3: Analyze
					const isVulnerable = analyzeMassAssign(
						originalResponse,
						modifiedResponse,
						payload,
					);

					if (isVulnerable) {
						const injectedFieldNames = Object.keys(payload).join(', ');

						findings.push({
							type: 'mass-assignment',
							severity: category === 'role-escalation' ? 'critical' :
								category === 'financial' ? 'high' :
									category === 'password-change' ? 'critical' : 'medium',
							title: `Mass Assignment: ${injectedFieldNames} on ${truncateUrl(endpoint.url)}`,
							url: endpoint.url,
							payload: JSON.stringify(payload),
							evidence: `Original: ${originalResponse.statusCode} (${originalResponse.body.length} bytes). ` +
								`Modified: ${modifiedResponse.statusCode} (${modifiedResponse.body.length} bytes). ` +
								`Server accepted injected field(s): ${injectedFieldNames}.`,
							confidence: calculateConfidence(originalResponse, modifiedResponse, category),
							details: `Endpoint ${endpoint.method} ${endpoint.url} accepted extra field(s) "${injectedFieldNames}" ` +
								`(category: ${category}). The server did not reject or strip unauthorized fields from the request body.`,
							endpoint: endpoint.url,
							method: endpoint.method,
							injectedFields: payload,
							category,
							originalResponse: {
								statusCode: originalResponse.statusCode,
								bodySnippet: originalResponse.body.slice(0, 200),
							},
							modifiedResponse: {
								statusCode: modifiedResponse.statusCode,
								bodySnippet: modifiedResponse.body.slice(0, 200),
							},
							parameter: injectedFieldNames,
						});
					}
				} catch {
					// Skip failed requests
				}

				if (options?.delayMs) { await sleep(options.delayMs); }
			}
		}
	}

	// Also test custom fields if provided
	if (options?.customFields && Object.keys(options.customFields).length > 0) {
		for (const endpoint of endpoints) {
			try {
				const originalBody = endpoint.originalBody ?? {};
				const modifiedBody = { ...originalBody, ...options.customFields };

				const modifiedResponse = await performHttpRequest(
					endpoint.method,
					endpoint.url,
					JSON.stringify(modifiedBody),
					{ 'content-type': 'application/json', ...authHeaders },
					options?.timeoutMs,
				);

				if (modifiedResponse.statusCode >= 200 && modifiedResponse.statusCode < 400) {
					const fieldNames = Object.keys(options.customFields).join(', ');
					findings.push({
						type: 'mass-assignment',
						severity: 'medium',
						title: `Mass Assignment (Custom): ${fieldNames} on ${truncateUrl(endpoint.url)}`,
						url: endpoint.url,
						payload: JSON.stringify(options.customFields),
						evidence: `Custom fields accepted. Status: ${modifiedResponse.statusCode}.`,
						confidence: 0.5,
						details: `Custom fields "${fieldNames}" were accepted by ${endpoint.method} ${endpoint.url}.`,
						endpoint: endpoint.url,
						method: endpoint.method,
						injectedFields: options.customFields,
						category: 'role-escalation',
						originalResponse: { statusCode: 0, bodySnippet: '' },
						modifiedResponse: {
							statusCode: modifiedResponse.statusCode,
							bodySnippet: modifiedResponse.body.slice(0, 200),
						},
						parameter: fieldNames,
					});
				}
			} catch {
				// Skip
			}
		}
	}

	return {
		generatedAt: new Date().toISOString(),
		target,
		endpointsTested,
		findings,
		elapsedMs: Date.now() - startTime,
	};
}

export function generateMassAssignReport(result: MassAssignScanResult): string {
	const lines: string[] = [];
	lines.push('# Mass Assignment Scan Report');
	lines.push('');
	lines.push(`**Target:** \`${result.target}\``);
	lines.push(`**Generated:** ${result.generatedAt}`);
	lines.push(`**Endpoints Tested:** ${result.endpointsTested}`);
	lines.push(`**Findings:** ${result.findings.length}`);
	lines.push(`**Duration:** ${result.elapsedMs}ms`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('✅ No mass assignment vulnerabilities detected.');
	} else {
		lines.push('---');
		lines.push('');
		for (let i = 0; i < result.findings.length; i++) {
			const f = result.findings[i];
			lines.push(`## ${i + 1}. ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Category:** ${f.category}`);
			lines.push(`- **Method:** ${f.method}`);
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Injected Fields:** \`${JSON.stringify(f.injectedFields)}\``);
			lines.push('');
			lines.push(`**Evidence:** ${f.evidence}`);
			lines.push('');
		}
	}

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Detection logic
// ---------------------------------------------------------------------------

interface HttpResult {
	statusCode: number;
	body: string;
	headers: Record<string, string>;
}

function analyzeMassAssign(
	original: HttpResult,
	modified: HttpResult,
	payload: Record<string, unknown>,
): boolean {
	// If modified request failed → not vulnerable (server rejected it)
	if (modified.statusCode >= 400) {
		return false;
	}

	// If modified request succeeded (2xx/3xx)
	if (modified.statusCode >= 200 && modified.statusCode < 400) {
		// Check if the injected fields appear in the response body
		for (const [key, value] of Object.entries(payload)) {
			const stringValue = String(value);
			if (modified.body.includes(`"${key}"`) || modified.body.includes(`"${key}":${stringValue}`)) {
				return true;
			}
		}

		// If the modified request got the same status but different response → server processed the fields
		if (modified.statusCode === original.statusCode && modified.body !== original.body) {
			// Body changed = server likely processed the extra fields
			const lengthDiff = Math.abs(modified.body.length - original.body.length);
			if (lengthDiff > 10) {
				return true;
			}
		}

		// If the status code improved (e.g., went from 422 to 200) → something was accepted
		if (modified.statusCode < original.statusCode && modified.statusCode < 300) {
			return true;
		}
	}

	return false;
}

function calculateConfidence(
	original: HttpResult,
	modified: HttpResult,
	category: MassAssignCategory,
): number {
	let confidence = 0.4;

	// Higher confidence if response body differs
	if (original.body !== modified.body) {
		confidence += 0.2;
	}

	// Higher confidence for role escalation (most impactful)
	if (category === 'role-escalation' || category === 'password-change') {
		confidence += 0.1;
	}

	// Higher confidence if injected values appear in response
	confidence += 0.1;

	return Math.min(confidence, 1.0);
}

// ---------------------------------------------------------------------------
// Endpoint Discovery
// ---------------------------------------------------------------------------

interface FormEndpoint {
	url: string;
	method: string;
	originalBody?: Record<string, unknown>;
}

function loadFormEndpoints(crawlResultFile: string): FormEndpoint[] {
	try {
		const raw = fs.readFileSync(crawlResultFile, 'utf8');
		const crawl: CrawlResultFile = JSON.parse(raw);
		const endpoints: FormEndpoint[] = [];

		// Extract from forms
		if (Array.isArray(crawl.forms)) {
			for (const form of crawl.forms) {
				const body: Record<string, unknown> = {};
				for (const input of form.inputs) {
					body[input.name] = input.value ?? `test_${input.name}`;
				}
				endpoints.push({
					url: form.action,
					method: (form.method || 'POST').toUpperCase(),
					originalBody: body,
				});
			}
		}

		// Also add POST endpoints discovered during crawl
		if (Array.isArray(crawl.discovered)) {
			for (const entry of crawl.discovered) {
				if (entry.method && entry.method.toUpperCase() !== 'GET') {
					endpoints.push({
						url: entry.url,
						method: entry.method.toUpperCase(),
						originalBody: {},
					});
				}
			}
		}

		return endpoints.length > 0 ? endpoints : extractEndpointFromUrl(crawl.discovered?.[0]?.url ?? '');
	} catch {
		return [];
	}
}

function extractEndpointFromUrl(target: string): FormEndpoint[] {
	if (!target) { return []; }
	return [
		{ url: target, method: 'POST', originalBody: {} },
		{ url: target, method: 'PUT', originalBody: {} },
	];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getAuthHeaders(
	profileName?: string,
	staticHeaders?: Record<string, string>,
	cookie?: string,
): Promise<Record<string, string>> {
	const headers: Record<string, string> = { ...staticHeaders };
	if (cookie) { headers['cookie'] = cookie; }

	if (profileName) {
		try {
			const result = await vscode.commands.executeCommand<{ headers: Record<string, string> }>(
				'scylla.auth.getHeadersHeadless',
				{ profileName }
			);
			if (result?.headers) {
				Object.assign(headers, result.headers);
			}
		} catch {
			// Auth extension not available
		}
	}

	return headers;
}

async function performHttpRequest(
	method: string,
	url: string,
	body: string | undefined,
	headers: Record<string, string>,
	timeoutMs?: number,
): Promise<HttpResult> {
	try {
		const result = await vscode.commands.executeCommand<{
			response: { statusCode: number; bodyText: string; headers: Record<string, string> };
		}>('scylla.http.sendHeadless', {
			url,
			method,
			body,
			headers,
			timeoutMs: timeoutMs ?? 10_000,
			quiet: true,
			maxBodyBytes: 256_000,
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
