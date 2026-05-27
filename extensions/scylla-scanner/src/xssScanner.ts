import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ParameterTarget, VulnFinding, XssScanResult } from './types';
import { detectDalfoxContext, generateDalfoxPayloads, verifyDalfoxExploit, DalfoxContext } from './xssHeuristics';
import { RateLimiter } from './xsstrike/rateLimiter';
import { WafFuzzer } from './xsstrike/wafFuzzer';
import { JsContexter } from './xsstrike/jsContexter';
import { DynamicGenerator } from './xsstrike/dynamicGenerator';

const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 15_000;

export async function scanXss(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		contexts?: Array<'html' | 'attribute' | 'javascript' | 'url'>;
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
		rateLimitRetryBaseMs?: number;
		maxRetries?: number;
	} = {}
): Promise<XssScanResult> {
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const rateLimitRetryBaseMs = options.rateLimitRetryBaseMs ?? 500;
	const maxRetries = options.maxRetries ?? 3;

	const rateLimiter = new RateLimiter(rateLimitRetryBaseMs, maxRetries);

	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	for (const param of parameters) {
		if (param.location !== 'query' && param.location !== 'body') { continue; }
		parametersScanned++;

		// Step 1: Send a unique canary to check for reflection
		const canary = `scylla_xss_${Math.random().toString(36).slice(2, 10)}`;
		const canaryResponse = await rateLimiter.executeWithBackoff(
			() => sendWithPayload(targetUrl, param, canary, timeoutMs, options.headers, options.cookie),
			(res) => res !== null && res.statusCode < 400
		);

		if (!canaryResponse || !canaryResponse.bodyText.includes(canary)) {
			if (delayMs > 0) { await sleep(delayMs); }
			continue; // Not reflected, skip
		}

		// Step 2: Determine the reflection context using Dalfox heuristics
		const context = detectDalfoxContext(canaryResponse.bodyText, canary);

		// Step 3: Phase 1 - Dalfox Static Polyglots & Templates
		const contextPayloads = generateDalfoxPayloads(context, canary);
		let found = false;

		for (const payload of contextPayloads) {
			const response = await rateLimiter.executeWithBackoff(
				() => sendWithPayload(targetUrl, param, payload, timeoutMs, options.headers, options.cookie),
				(res) => res !== null && res.statusCode < 400
			);
			
			if (!response) { continue; }

			if (verifyDalfoxExploit(response.bodyText, payload, canary, context)) {
				findings.push({
					type: 'xss',
					severity: 'high',
					title: `Reflected XSS (${context} context)`,
					url: targetUrl,
					parameter: param.name,
					payload,
					evidence: `Dalfox Heuristic Verification Passed in ${context} context. Status: ${response.statusCode}`,
					confidence: 0.95,
					details: `Reflected Cross-Site Scripting detected in parameter "${param.name}" (${param.location}). Context: ${context}. The payload structurally bypassed filtering and proved execution capability using Dalfox DOM/AST simulation rules.`,
				});
				found = true;
				break; // Confirmed finding
			}
			if (delayMs > 0) { await sleep(delayMs); }
		}

		if (found) continue; // Move to next parameter

		// Step 4: Phase 2 - XSStrike Dynamic Fuzzing & WAF Evasion
		// If Dalfox templates failed, the WAF is likely filtering specific characters.
		const fuzzer = new WafFuzzer(rateLimiter, targetUrl, timeoutMs, options.headers, options.cookie);
		const filterScores = await fuzzer.detectFilters(param);
		
		const generator = new DynamicGenerator(filterScores);
		let jsBreaker = '';
		
		if (context === 'script') {
			// Find the unbalanced JS syntax before the canary
			const idx = canaryResponse.bodyText.indexOf(canary);
			const jsBefore = canaryResponse.bodyText.substring(Math.max(0, idx - 500), idx);
			jsBreaker = JsContexter.generateBreaker(jsBefore);
		}

		// Convert Dalfox context to XSStrike generator context
		const genContext = (context === 'script' || context === 'html' || context === 'attribute') ? context : 'html';
		const dynamicPayloads = generator.generate(genContext, jsBreaker, canary);

		for (const payload of dynamicPayloads) {
			const response = await rateLimiter.executeWithBackoff(
				() => sendWithPayload(targetUrl, param, payload, timeoutMs, options.headers, options.cookie),
				(res) => res !== null && res.statusCode < 400
			);
			
			if (!response) { continue; }

			if (verifyDalfoxExploit(response.bodyText, payload, canary, context)) {
				findings.push({
					type: 'xss',
					severity: 'critical', // Dynamic evasions get critical severity
					title: `WAF Bypassed Reflected XSS (${context} context)`,
					url: targetUrl,
					parameter: param.name,
					payload,
					evidence: `XSStrike Dynamic Generator Bypassed WAF. Status: ${response.statusCode}`,
					confidence: 0.99,
					details: `Advanced WAF Bypass detected in parameter "${param.name}". XSStrike fuzzing determined the allowed character set and successfully built a context-aware mutated payload (Breaker: ${jsBreaker || 'None'}).`,
				});
				break; 
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
