/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ParameterTarget, VulnFinding, XssScanResult } from './types';

const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 15_000;

interface XssPayloads {
	html: string[];
	attribute: string[];
	javascript: string[];
	url: string[];
	polyglot: string[];
}

type XssContext = 'html' | 'attribute' | 'javascript' | 'url' | 'unknown';

export async function scanXss(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		contexts?: Array<'html' | 'attribute' | 'javascript' | 'url'>;
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<XssScanResult> {
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	const payloads = loadJson<XssPayloads>('xss-payloads.json');
	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	for (const param of parameters) {
		if (param.location !== 'query' && param.location !== 'body') { continue; }
		parametersScanned++;

		// Step 1: Send a unique canary to check for reflection
		const canary = `scylla_xss_${Math.random().toString(36).slice(2, 10)}`;
		const canaryResponse = await sendWithPayload(targetUrl, param, canary, timeoutMs, options.headers, options.cookie);

		if (!canaryResponse || !canaryResponse.bodyText.includes(canary)) {
			if (delayMs > 0) { await sleep(delayMs); }
			continue; // Not reflected, skip
		}

		// Step 2: Determine the reflection context
		const context = detectContext(canaryResponse.bodyText, canary);

		// Step 3: Send context-appropriate payloads
		const contextPayloads = getPayloadsForContext(payloads, context, options.contexts);

		for (const payloadTemplate of contextPayloads) {
			const payload = payloadTemplate.replace(/\{canary\}/g, canary);

			const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, options.headers, options.cookie);
			if (!response) { continue; }

			// Check if the payload reflects unescaped
			if (isPayloadReflectedUnescaped(response.bodyText, payload, canary)) {
				findings.push({
					type: 'xss',
					severity: 'high',
					title: `Reflected XSS (${context} context)`,
					url: targetUrl,
					parameter: param.name,
					payload,
					evidence: `Payload reflected unescaped in ${context} context. Status: ${response.statusCode}`,
					confidence: 0.90,
					details: `Reflected Cross-Site Scripting detected in parameter "${param.name}" (${param.location}). Context: ${context}. The payload was reflected in the response body without proper encoding or sanitization.`,
				});
				break; // One confirmed finding per param
			}

			if (delayMs > 0) { await sleep(delayMs); }
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		parametersScanned,
		findings,
		elapsedMs: Date.now() - start,
	};
}

function detectContext(body: string, canary: string): XssContext {
	const idx = body.indexOf(canary);
	if (idx === -1) { return 'unknown'; }

	// Get surrounding context (500 chars before)
	const before = body.substring(Math.max(0, idx - 500), idx);

	// Inside a <script> tag?
	const lastScriptOpen = before.lastIndexOf('<script');
	const lastScriptClose = before.lastIndexOf('</script');
	if (lastScriptOpen > lastScriptClose) {
		return 'javascript';
	}

	// Inside an HTML attribute?
	const lastQuote = Math.max(before.lastIndexOf('"'), before.lastIndexOf("'"));
	const lastEquals = before.lastIndexOf('=');
	const lastGt = before.lastIndexOf('>');
	if (lastEquals > lastGt && lastQuote > lastEquals) {
		return 'attribute';
	}

	// Inside href/src attribute? (URL context)
	const attrMatch = before.match(/(?:href|src|action|data)\s*=\s*["']?[^"'>]*$/i);
	if (attrMatch) {
		return 'url';
	}

	return 'html';
}

function getPayloadsForContext(
	payloads: XssPayloads,
	detectedContext: XssContext,
	allowedContexts?: Array<'html' | 'attribute' | 'javascript' | 'url'>
): string[] {
	const result: string[] = [];

	// Always try polyglot first
	result.push(...payloads.polyglot);

	// Context-specific payloads
	if (detectedContext === 'html' && (!allowedContexts || allowedContexts.includes('html'))) {
		result.push(...payloads.html);
	}
	if (detectedContext === 'attribute' && (!allowedContexts || allowedContexts.includes('attribute'))) {
		result.push(...payloads.attribute);
	}
	if (detectedContext === 'javascript' && (!allowedContexts || allowedContexts.includes('javascript'))) {
		result.push(...payloads.javascript);
	}
	if (detectedContext === 'url' && (!allowedContexts || allowedContexts.includes('url'))) {
		result.push(...payloads.url);
	}

	// If unknown context, try everything
	if (detectedContext === 'unknown') {
		result.push(...payloads.html, ...payloads.attribute, ...payloads.javascript);
	}

	return result;
}

function isPayloadReflectedUnescaped(body: string, payload: string, canary: string): boolean {
	// Check for key dangerous patterns that indicate unescaped reflection
	const dangerousPatterns = [
		`<script>alert('${canary}')</script>`,
		`<img src=x onerror=alert('${canary}')>`,
		`<svg onload=alert('${canary}')>`,
		`onerror=alert('${canary}')`,
		`onload=alert('${canary}')`,
		`onmouseover="alert('${canary}')"`,
		`onfocus="alert('${canary}')"`,
		`alert('${canary}')`,
		`<svg/onload=alert('${canary}')`,
	];

	for (const pattern of dangerousPatterns) {
		if (body.includes(pattern)) {
			return true;
		}
	}

	// Check if the raw payload appears (not HTML-encoded)
	if (body.includes(payload)) {
		// Verify it's not just the canary that's reflected but actual dangerous chars
		if (payload.includes('<') && body.includes(payload) && !body.includes(escapeHtml(payload))) {
			return true;
		}
	}

	return false;
}

function escapeHtml(text: string): string {
	return text
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#039;');
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
			maxBodyBytes: 128 * 1024,
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
			response: { statusCode: number; bodyText: string; elapsedMs: number };
		}>('scylla.http.sendHeadless', sendOptions);

		if (!result?.response) { return null; }
		return result.response;
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

export function generateXssReport(result: XssScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - XSS Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Scanned:** ${result.parametersScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No XSS vulnerabilities detected.');
	} else {
		for (const f of result.findings) {
			lines.push(`## ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			lines.push(`- **Parameter:** \`${f.parameter}\``);
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Payload:** \`${f.payload.slice(0, 100)}\``);
			lines.push(`- **Evidence:** ${f.evidence}`);
			lines.push('');
			lines.push(f.details);
			lines.push('');
		}
	}

	return lines.join('\n');
}
