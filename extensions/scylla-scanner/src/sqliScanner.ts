/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ParameterTarget, SqliScanResult, VulnFinding } from './types';

const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 15_000;
const TIME_BLIND_DELAY = 5;
const TIME_BLIND_THRESHOLD = 4;
const TIME_BLIND_CONFIRMATIONS = 2;

interface ErrorPayloads {
	generic: string[];
	mysql: string[];
	postgresql: string[];
	mssql: string[];
	sqlite: string[];
	oracle: string[];
}

interface TimePayloads {
	mysql: string[];
	postgresql: string[];
	mssql: string[];
	sqlite: string[];
	oracle: string[];
}

interface Signatures {
	mysql: string[];
	postgresql: string[];
	mssql: string[];
	sqlite: string[];
	oracle: string[];
}

export async function scanSqli(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		techniques?: Array<'error' | 'time-blind'>;
		dbms?: Array<'mysql' | 'postgresql' | 'mssql' | 'sqlite' | 'oracle'>;
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<SqliScanResult> {
	const techniques = options.techniques ?? ['error', 'time-blind'];
	const dbmsTargets = options.dbms ?? ['mysql', 'postgresql', 'mssql', 'sqlite', 'oracle'];
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	const errorPayloads = loadJson<ErrorPayloads>('sqli-error.json');
	const timePayloads = loadJson<TimePayloads>('sqli-time.json');
	const signatures = loadJson<Signatures>('sqli-signatures.json');

	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	for (const param of parameters) {
		if (param.location !== 'query' && param.location !== 'body') { continue; }
		parametersScanned++;

		// Error-based detection
		if (techniques.includes('error')) {
			const found = await testErrorBased(
				targetUrl, param, errorPayloads, signatures, dbmsTargets,
				timeoutMs, delayMs, options.headers, options.cookie
			);
			findings.push(...found);
		}

		// Time-based blind detection
		if (techniques.includes('time-blind')) {
			const found = await testTimeBased(
				targetUrl, param, timePayloads, dbmsTargets,
				timeoutMs, delayMs, options.headers, options.cookie
			);
			findings.push(...found);
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

async function testErrorBased(
	targetUrl: string,
	param: ParameterTarget,
	payloads: ErrorPayloads,
	signatures: Signatures,
	dbmsTargets: string[],
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<VulnFinding[]> {
	const findings: VulnFinding[] = [];
	const testedPayloads = new Set<string>();

	// Generic payloads first
	for (const payload of payloads.generic) {
		if (testedPayloads.has(payload)) { continue; }
		testedPayloads.add(payload);

		const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (!response) { continue; }

		// Check against all DBMS signatures
		for (const dbms of dbmsTargets) {
			const dbmsSignatures = signatures[dbms as keyof Signatures];
			if (!dbmsSignatures) { continue; }

			for (const sig of dbmsSignatures) {
				const regex = new RegExp(sig, 'i');
				if (regex.test(response.bodyText)) {
					findings.push({
						type: 'sqli',
						severity: 'critical',
						title: `SQL Injection (Error-based, ${dbms.toUpperCase()})`,
						url: targetUrl,
						parameter: param.name,
						payload,
						evidence: `DBMS error pattern matched: ${sig}`,
						confidence: 0.95,
						details: `Error-based SQL injection detected in parameter "${param.name}" (${param.location}). DBMS: ${dbms}. The application returned a database error message when injecting: ${payload}`,
					});
					return findings; // One confirmed finding per param is enough
				}
			}
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	// DBMS-specific payloads
	for (const dbms of dbmsTargets) {
		const dbmsPayloads = payloads[dbms as keyof ErrorPayloads];
		if (!dbmsPayloads || !Array.isArray(dbmsPayloads)) { continue; }

		for (const payload of dbmsPayloads) {
			if (testedPayloads.has(payload)) { continue; }
			testedPayloads.add(payload);

			const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
			if (!response) { continue; }

			const dbmsSignatures = signatures[dbms as keyof Signatures];
			if (!dbmsSignatures) { continue; }

			for (const sig of dbmsSignatures) {
				const regex = new RegExp(sig, 'i');
				if (regex.test(response.bodyText)) {
					findings.push({
						type: 'sqli',
						severity: 'critical',
						title: `SQL Injection (Error-based, ${dbms.toUpperCase()})`,
						url: targetUrl,
						parameter: param.name,
						payload,
						evidence: `DBMS-specific error pattern matched: ${sig}`,
						confidence: 0.95,
						details: `Error-based SQL injection detected in parameter "${param.name}" using ${dbms}-specific payload.`,
					});
					return findings;
				}
			}

			if (delayMs > 0) { await sleep(delayMs); }
		}
	}

	return findings;
}

async function testTimeBased(
	targetUrl: string,
	param: ParameterTarget,
	payloads: TimePayloads,
	dbmsTargets: string[],
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<VulnFinding[]> {
	const findings: VulnFinding[] = [];

	// Get baseline response time (3 measurements)
	let baselineTotal = 0;
	for (let i = 0; i < 3; i++) {
		const response = await sendWithPayload(targetUrl, param, param.value, timeoutMs, headers, cookie);
		baselineTotal += response?.elapsedMs ?? 1000;
	}
	const baseline = baselineTotal / 3;

	for (const dbms of dbmsTargets) {
		const dbmsPayloads = payloads[dbms as keyof TimePayloads];
		if (!dbmsPayloads) { continue; }

		for (const payloadTemplate of dbmsPayloads) {
			const payload = payloadTemplate.replace(/\{delay\}/g, String(TIME_BLIND_DELAY));

			// First test
			const response1 = await sendWithPayload(
				targetUrl, param, payload, timeoutMs + TIME_BLIND_DELAY * 1000 + 5000, headers, cookie
			);
			if (!response1) { continue; }

			const timeDiff1 = response1.elapsedMs - baseline;
			if (timeDiff1 < TIME_BLIND_THRESHOLD * 1000) {
				if (delayMs > 0) { await sleep(delayMs); }
				continue;
			}

			// Confirmation tests
			let confirmed = 0;
			for (let i = 0; i < TIME_BLIND_CONFIRMATIONS; i++) {
				const responseN = await sendWithPayload(
					targetUrl, param, payload, timeoutMs + TIME_BLIND_DELAY * 1000 + 5000, headers, cookie
				);
				if (responseN && (responseN.elapsedMs - baseline) >= TIME_BLIND_THRESHOLD * 1000) {
					confirmed++;
				}
				if (delayMs > 0) { await sleep(delayMs); }
			}

			if (confirmed >= TIME_BLIND_CONFIRMATIONS) {
				findings.push({
					type: 'sqli',
					severity: 'critical',
					title: `SQL Injection (Time-based Blind, ${dbms.toUpperCase()})`,
					url: targetUrl,
					parameter: param.name,
					payload,
					evidence: `Response delayed by ~${Math.round(timeDiff1)}ms (baseline: ${Math.round(baseline)}ms, expected delay: ${TIME_BLIND_DELAY}s). Confirmed ${confirmed}/${TIME_BLIND_CONFIRMATIONS} times.`,
					confidence: 0.85,
					details: `Time-based blind SQL injection detected in parameter "${param.name}". Baseline response: ${Math.round(baseline)}ms, injected response: ${Math.round(response1.elapsedMs)}ms. DBMS: ${dbms}.`,
				});
				return findings; // One confirmed finding per param
			}

			if (delayMs > 0) { await sleep(delayMs); }
		}
	}

	return findings;
}

async function sendWithPayload(
	targetUrl: string,
	param: ParameterTarget,
	payload: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ bodyText: string; elapsedMs: number; statusCode: number } | null> {
	try {
		const url = new URL(targetUrl);

		const sendOptions: Record<string, unknown> = {
			timeoutMs,
			followRedirects: true,
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
				elapsedMs: number;
			};
		}>('scylla.http.sendHeadless', sendOptions);

		if (!result?.response) { return null; }
		return {
			bodyText: result.response.bodyText,
			elapsedMs: result.response.elapsedMs,
			statusCode: result.response.statusCode,
		};
	} catch {
		return null;
	}
}

function loadJson<T>(filename: string): T {
	const candidates = [
		path.join(__dirname, 'payloads', filename),
		path.join(__dirname, '..', 'src', 'payloads', filename),
		path.join(__dirname, '..', 'payloads', filename),
	];
	for (const p of candidates) {
		if (fs.existsSync(p)) {
			return JSON.parse(fs.readFileSync(p, 'utf8'));
		}
	}
	throw new Error(`Payload file not found: ${filename}`);
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateSqliReport(result: SqliScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - SQL Injection Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Scanned:** ${result.parametersScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No SQL injection vulnerabilities detected.');
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
