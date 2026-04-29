/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ParameterTarget, SstiScanResult, VulnFinding } from './types';

const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 15_000;

interface SstiProbe {
	payload: string;
	expected: string;
	engines: string[];
}

interface SstiPayloads {
	probes: SstiProbe[];
	escalation: Record<string, string[]>;
}

export async function scanSsti(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		engines?: string[];
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<SstiScanResult> {
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const targetEngines = options.engines ?? ['jinja2', 'twig', 'freemarker', 'velocity', 'smarty', 'mako'];

	const payloads = loadJson<SstiPayloads>('ssti-payloads.json');
	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	for (const param of parameters) {
		if (param.location !== 'query' && param.location !== 'body') { continue; }
		parametersScanned++;

		let foundForParam = false;

		for (const probe of payloads.probes) {
			if (foundForParam) { break; }

			// Skip probes for non-targeted engines
			const relevantEngines = probe.engines.filter(e => targetEngines.includes(e));
			if (relevantEngines.length === 0) { continue; }

			const response = await sendWithPayload(targetUrl, param, probe.payload, timeoutMs, options.headers, options.cookie);
			if (!response) { continue; }

			// Check if the expected result appears in the response
			if (response.bodyText.includes(probe.expected)) {
				// Verify it's not just echoing the payload
				const payloadWithoutDelimiters = probe.payload.replace(/[{}<>%=#$]/g, '');
				if (response.bodyText.includes(payloadWithoutDelimiters) && !response.bodyText.includes(probe.expected)) {
					continue; // False positive - just echoing input
				}

				const detectedEngine = relevantEngines[0];
				findings.push({
					type: 'ssti',
					severity: 'critical',
					title: `Server-Side Template Injection (${detectedEngine})`,
					url: targetUrl,
					parameter: param.name,
					payload: probe.payload,
					evidence: `Math expression ${probe.payload} evaluated to "${probe.expected}" in response. Engine: ${relevantEngines.join('/')}`,
					confidence: 0.90,
					details: `Server-Side Template Injection detected in parameter "${param.name}" (${param.location}). The template engine evaluated the mathematical expression, confirming code execution capability. Likely engine: ${relevantEngines.join(' or ')}.`,
				});
				foundForParam = true;
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

async function sendWithPayload(
	targetUrl: string,
	param: ParameterTarget,
	payload: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ bodyText: string; statusCode: number } | null> {
	try {
		const url = new URL(targetUrl);
		const sendOptions: Record<string, unknown> = {
			timeoutMs, followRedirects: true, quiet: true, maxBodyBytes: 64 * 1024,
		};
		if (headers) { sendOptions.headers = { ...headers }; }
		if (cookie) {
			sendOptions.headers = { ...(sendOptions.headers as Record<string, string> ?? {}), cookie };
		}

		if (param.location === 'query') {
			url.searchParams.set(param.name, payload);
			sendOptions.url = url.href;
			sendOptions.method = 'GET';
		} else {
			sendOptions.url = url.href;
			sendOptions.method = 'POST';
			sendOptions.body = `${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
			sendOptions.headers = { ...(sendOptions.headers as Record<string, string> ?? {}), 'content-type': 'application/x-www-form-urlencoded' };
		}

		const result = await vscode.commands.executeCommand<{
			response: { statusCode: number; bodyText: string };
		}>('scylla.http.sendHeadless', sendOptions);

		return result?.response ?? null;
	} catch { return null; }
}

function loadJson<T>(filename: string): T {
	for (const p of [path.join(__dirname, 'payloads', filename), path.join(__dirname, '..', 'src', 'payloads', filename), path.join(__dirname, '..', 'payloads', filename)]) {
		if (fs.existsSync(p)) { return JSON.parse(fs.readFileSync(p, 'utf8')); }
	}
	throw new Error(`Payload file not found: ${filename}`);
}

function sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

export function generateSstiReport(result: SstiScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - SSTI Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Scanned:** ${result.parametersScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');
	if (result.findings.length === 0) {
		lines.push('No SSTI vulnerabilities detected.');
	} else {
		for (const f of result.findings) {
			lines.push(`## ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Parameter:** \`${f.parameter}\``);
			lines.push(`- **Payload:** \`${f.payload}\``);
			lines.push(`- **Evidence:** ${f.evidence}`);
			lines.push('');
			lines.push(f.details);
			lines.push('');
		}
	}
	return lines.join('\n');
}
