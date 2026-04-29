/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { LfiScanResult, ParameterTarget, VulnFinding } from './types';

const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 15_000;

interface LfiPayloads {
	linux: { files: string[]; signatures: string[] };
	windows: { files: string[]; signatures: string[] };
	traversals: {
		plain: string[];
		'url-encoded': string[];
		'double-encoded': string[];
		'null-byte': string[];
		misc: string[];
	};
	'php-wrappers': string[];
}

export async function scanLfi(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		osTargets?: Array<'linux' | 'windows'>;
		encodings?: Array<'plain' | 'url-encoded' | 'double-encoded' | 'null-byte' | 'php-wrapper'>;
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<LfiScanResult> {
	const osTargets = options.osTargets ?? ['linux', 'windows'];
	const encodings = options.encodings ?? ['plain', 'url-encoded', 'double-encoded', 'null-byte', 'php-wrapper'];
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	const payloads = loadJson<LfiPayloads>('lfi-payloads.json');
	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	for (const param of parameters) {
		if (param.location !== 'query' && param.location !== 'body') { continue; }
		parametersScanned++;

		let foundForParam = false;

		for (const os of osTargets) {
			if (foundForParam) { break; }

			const osData = payloads[os];
			const files = osData.files;
			const signatures = osData.signatures.map(s => new RegExp(s, 'i'));

			// Get traversal paths to try
			const traversals = buildTraversals(payloads, encodings);

			for (const file of files) {
				if (foundForParam) { break; }

				for (const traversal of traversals) {
					const payload = traversal + file.replace(/^\//, '');

					const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, options.headers, options.cookie);
					if (!response) { continue; }

					// Check for file signatures
					for (const sig of signatures) {
						if (sig.test(response.bodyText)) {
							findings.push({
								type: 'lfi',
								severity: 'high',
								title: `Local File Inclusion (${os.toUpperCase()})`,
								url: targetUrl,
								parameter: param.name,
								payload,
								evidence: `File content signature matched: ${sig.source}. File: ${file}`,
								confidence: 0.90,
								details: `Local File Inclusion detected in parameter "${param.name}" (${param.location}). Successfully read ${file} using traversal: ${traversal || 'direct'}. OS: ${os}.`,
							});
							foundForParam = true;
							break;
						}
					}

					if (delayMs > 0) { await sleep(delayMs); }
				}
			}

			// PHP wrapper tests
			if (!foundForParam && encodings.includes('php-wrapper')) {
				for (const wrapper of payloads['php-wrappers']) {
					const payload = wrapper + (files[0]?.replace(/^\//, '') ?? 'index.php');

					const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, options.headers, options.cookie);
					if (!response) { continue; }

					// php://filter/convert.base64-encode returns base64-encoded content
					if (wrapper.includes('base64') && isBase64Content(response.bodyText)) {
						findings.push({
							type: 'lfi',
							severity: 'high',
							title: 'Local File Inclusion (PHP Wrapper)',
							url: targetUrl,
							parameter: param.name,
							payload,
							evidence: 'PHP wrapper returned base64-encoded file content',
							confidence: 0.85,
							details: `LFI via PHP wrapper detected in parameter "${param.name}". The php://filter wrapper successfully read and encoded the target file.`,
						});
						foundForParam = true;
						break;
					}

					if (delayMs > 0) { await sleep(delayMs); }
				}
			}
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

function buildTraversals(payloads: LfiPayloads, encodings: string[]): string[] {
	const traversals: string[] = [''];  // Direct path (no traversal)

	if (encodings.includes('plain')) {
		traversals.push(...payloads.traversals.plain);
	}
	if (encodings.includes('url-encoded')) {
		traversals.push(...payloads.traversals['url-encoded'].map(
			enc => enc.repeat(5)  // 5 levels deep
		));
	}
	if (encodings.includes('double-encoded')) {
		traversals.push(...payloads.traversals['double-encoded'].map(
			enc => enc.repeat(5)
		));
	}
	if (encodings.includes('null-byte')) {
		// Add null byte variants to existing traversals
		const withNull: string[] = [];
		for (const t of payloads.traversals.plain.slice(0, 5)) {
			for (const nb of payloads.traversals['null-byte']) {
				withNull.push(t + nb);
			}
		}
		traversals.push(...withNull);
	}

	// Misc encodings
	traversals.push(...payloads.traversals.misc.map(enc => enc.repeat(5)));

	return [...new Set(traversals)];
}

function isBase64Content(text: string): boolean {
	const trimmed = text.trim();
	if (trimmed.length < 20) { return false; }
	// Check if it looks like base64 (only base64 chars, reasonable length)
	const base64Regex = /^[A-Za-z0-9+/\s]+=*$/;
	const cleanText = trimmed.replace(/\s/g, '');
	return cleanText.length > 20 && cleanText.length < 100000 && base64Regex.test(cleanText);
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

export function generateLfiReport(result: LfiScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - LFI Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Scanned:** ${result.parametersScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');
	if (result.findings.length === 0) {
		lines.push('No LFI vulnerabilities detected.');
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
