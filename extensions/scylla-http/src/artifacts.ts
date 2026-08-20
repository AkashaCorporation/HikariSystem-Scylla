/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type {
	CommandOutputOptions,
	HttpRequestDefinition,
	HttpResponseData,
	HttpSendCommandOptions,
	HttpSendResult,
	OutputFormat,
	SavedRequestResult
} from './types';

export const DEFAULT_TIMEOUT_MS = 15_000;
export const DEFAULT_MAX_BODY_BYTES = 512 * 1024;
const REQUESTS_DIR = path.join('.scylla', 'http', 'requests');
const RESPONSES_DIR = path.join('.scylla', 'http', 'responses');
const REDACTED = '[REDACTED]';
const SENSITIVE_HEADERS = new Set([
	'authorization',
	'proxy-authorization',
	'cookie',
	'set-cookie',
	'x-api-key',
	'api-key',
	'x-auth-token',
	'x-access-token',
]);
const SENSITIVE_BODY_KEY = /^(?:password|passwd|pass|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|authorization|cookie)$/i;

export function normalizeRequestDefinition(source?: Partial<HttpRequestDefinition>): HttpRequestDefinition {
	const method = source?.method?.trim().toUpperCase();
	if (!method) {
		throw new Error('Request method is required.');
	}

	let url = source?.url?.trim();
	if (url && !url.toLowerCase().startsWith('http://') && !url.toLowerCase().startsWith('https://')) {
		url = `http://${url}`;
	}

	if (!url || validateHttpUrl(url) !== null) {
		throw new Error('A valid HTTP or HTTPS URL (or IP/hostname) is required.');
	}

	return {
		name: typeof source?.name === 'string' && source.name.trim().length > 0 ? source.name.trim() : undefined,
		method,
		url,
		headers: normalizeHeaders(source?.headers),
		body: typeof source?.body === 'string' && source.body.length > 0 ? source.body : undefined,
		timeoutMs: normalizeTimeout(source?.timeoutMs),
		followRedirects: source?.followRedirects !== false,
		tags: Array.isArray(source?.tags) ? source.tags.filter(tag => typeof tag === 'string' && tag.trim().length > 0) : undefined
	};
}

export function saveRequestDefinition(
	requestDefinition: HttpRequestDefinition,
	explicitOutputPath?: string
): SavedRequestResult {
	const requestFile = explicitOutputPath
		? resolveWritablePath(explicitOutputPath)
		: path.join(ensureWorkspaceRoot(), REQUESTS_DIR, `${buildTimestampPrefix()}-${sanitizeFileName(requestDefinition.name ?? requestDefinition.url)}.scylla-http.json`);

	fs.mkdirSync(path.dirname(requestFile), { recursive: true });
	// Explicit saved request definitions remain replayable by design. Callers should
	// treat them as sensitive artifacts because they may intentionally contain auth.
	fs.writeFileSync(requestFile, JSON.stringify(requestDefinition, null, 2), 'utf8');

	return {
		requestFile,
		request: requestDefinition,
		generatedAt: new Date().toISOString()
	};
}

export function loadRequestDefinition(filePath: string): HttpRequestDefinition {
	const resolvedPath = resolveReadablePath(filePath);
	if (!fs.existsSync(resolvedPath)) {
		throw new Error(`Request file not found: ${resolvedPath}`);
	}

	return parseRequestDocument(fs.readFileSync(resolvedPath, 'utf8'), resolvedPath);
}

export function parseRequestDocument(content: string, filePath: string): HttpRequestDefinition {
	try {
		const parsed = JSON.parse(content) as HttpRequestDefinition;
		return normalizeRequestDefinition(parsed);
	} catch (error: unknown) {
		throw new Error(`Failed to parse Scylla HTTP request file ${filePath}: ${toErrorMessage(error)}`);
	}
}

export function saveResponseArtifact(
	requestDefinition: HttpRequestDefinition,
	response: HttpResponseData,
	generatedAt: string
): string {
	const workspaceRoot = ensureWorkspaceRoot();
	const fileName = `${buildTimestampPrefix()}-${sanitizeFileName(requestDefinition.name ?? requestDefinition.url)}.response.json`;
	const responseFile = path.join(workspaceRoot, RESPONSES_DIR, fileName);
	const requestHeaders = normalizeHeaders(requestDefinition.headers);
	fs.mkdirSync(path.dirname(responseFile), { recursive: true });
	fs.writeFileSync(
		responseFile,
		JSON.stringify(
			{
				generatedAt,
				request: {
					name: requestDefinition.name,
					method: requestDefinition.method.toUpperCase(),
					url: requestDefinition.url,
					headers: redactRequestHeaders(requestHeaders),
					body: redactRequestBody(requestDefinition.body, requestHeaders),
					timeoutMs: requestDefinition.timeoutMs ?? DEFAULT_TIMEOUT_MS,
					followRedirects: requestDefinition.followRedirects !== false
				},
				response: {
					...response,
					headers: redactResponseHeaders(response.headers),
				}
			},
			null,
			2
		),
		'utf8'
	);
	return responseFile;
}

export function writeSendOutput(result: HttpSendResult, output: CommandOutputOptions): void {
	const outputPath = resolveWritablePath(output.path);
	const format = normalizeOutputFormat(outputPath, output.format);
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(outputPath, generateSendReport(result), 'utf8');
		return;
	}

	const { reportMarkdown: _reportMarkdown, ...jsonResult } = result;
	const sanitizedResult = {
		...jsonResult,
		request: {
			...jsonResult.request,
			headers: redactRequestHeaders(jsonResult.request.headers),
			body: redactRequestBody(jsonResult.request.body, jsonResult.request.headers),
		},
		response: {
			...jsonResult.response,
			headers: redactResponseHeaders(jsonResult.response.headers),
		},
	};
	fs.writeFileSync(outputPath, JSON.stringify(sanitizedResult, null, 2), 'utf8');
}

export function generateSendReport(result: HttpSendResult): string {
	const lines: string[] = [];
	const safeRequestHeaders = redactRequestHeaders(result.request.headers);
	const safeResponseHeaders = redactResponseHeaders(result.response.headers);
	const safeRequestBody = redactRequestBody(result.request.body, result.request.headers);

	lines.push('# Scylla HTTP Response Report');
	lines.push('');
	lines.push('## Request');
	lines.push('');
	lines.push(`- Name: ${result.request.name ?? '(unnamed)'}`);
	lines.push(`- Method: ${result.request.method}`);
	lines.push(`- URL: \`${result.request.url}\``);
	lines.push(`- Timeout: ${result.request.timeoutMs} ms`);
	lines.push(`- Follow Redirects: ${result.request.followRedirects ? 'yes' : 'no'}`);
	lines.push(`- Generated: ${result.generatedAt}`);
	if (result.requestFile) {
		lines.push(`- Request File: \`${result.requestFile}\``);
	}
	if (result.responseFile) {
		lines.push(`- Response File: \`${result.responseFile}\``);
	}
	lines.push('');
	lines.push('### Headers');
	lines.push('');
	if (Object.keys(safeRequestHeaders).length === 0) {
		lines.push('- No custom headers');
	} else {
		for (const [name, value] of Object.entries(safeRequestHeaders)) {
			lines.push(`- ${name}: ${value}`);
		}
	}
	lines.push('');
	if (safeRequestBody) {
		lines.push('### Body');
		lines.push('');
		lines.push('```http');
		lines.push(safeRequestBody);
		lines.push('```');
		lines.push('');
	}

	lines.push('## Response');
	lines.push('');
	lines.push(`- Status: ${result.response.statusCode} ${result.response.statusMessage}`.trim());
	lines.push(`- Final URL: \`${result.response.finalUrl}\``);
	lines.push(`- Duration: ${result.response.elapsedMs} ms`);
	lines.push(`- Body Size: ${result.response.bodyBytes} bytes`);
	lines.push(`- Redirects: ${result.response.redirectCount}`);
	lines.push(`- Truncated: ${result.response.truncated ? 'yes' : 'no'}`);
	lines.push('');
	lines.push('### Response Headers');
	lines.push('');
	for (const [name, value] of Object.entries(safeResponseHeaders)) {
		lines.push(`- ${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
	}
	lines.push('');
	lines.push('### Response Body');
	lines.push('');
	lines.push('```text');
	lines.push(trimForReport(result.response.bodyText));
	lines.push('```');
	lines.push('');
	if (result.response.truncated) {
		lines.push('> Response body was truncated to the configured capture limit.');
		lines.push('');
	}
	return lines.join('\n');
}

export function normalizeSendOptions(arg?: vscode.Uri | HttpSendCommandOptions): HttpSendCommandOptions {
	if (!arg || arg instanceof vscode.Uri) {
		return {};
	}
	return arg;
}

export function validateHttpUrl(value: string): string | null {
	if (value.trim().length === 0) {
		return vscode.l10n.t('URL is required.');
	}

	let urlToTest = value.trim();
	if (!urlToTest.toLowerCase().startsWith('http://') && !urlToTest.toLowerCase().startsWith('https://')) {
		urlToTest = `http://${urlToTest}`;
	}

	try {
		const url = new URL(urlToTest);
		if (url.protocol !== 'http:' && url.protocol !== 'https:') {
			return vscode.l10n.t('Only HTTP and HTTPS URLs are supported.');
		}
		return null;
	} catch {
		return vscode.l10n.t('Enter a valid HTTP or HTTPS URL (or Domain/IP).');
	}
}

export function normalizeHeaders(headers?: Record<string, string>): Record<string, string> {
	if (!headers) {
		return {};
	}

	const normalized: Record<string, string> = {};
	for (const [name, value] of Object.entries(headers)) {
		if (typeof value !== 'string') {
			continue;
		}
		const headerName = name.trim().toLowerCase();
		if (headerName.length === 0) {
			continue;
		}
		normalized[headerName] = value;
	}
	return normalized;
}

export function normalizeTimeout(timeoutMs?: number): number {
	if (!Number.isFinite(timeoutMs)) {
		return DEFAULT_TIMEOUT_MS;
	}
	return Math.max(1_000, Math.floor(timeoutMs!));
}

export function normalizeMaxBodyBytes(maxBodyBytes?: number): number {
	if (!Number.isFinite(maxBodyBytes)) {
		return DEFAULT_MAX_BODY_BYTES;
	}
	return Math.max(4_096, Math.floor(maxBodyBytes!));
}

function redactRequestHeaders(headers: Record<string, string>): Record<string, string> {
	const output: Record<string, string> = {};
	for (const [name, value] of Object.entries(headers)) {
		output[name] = SENSITIVE_HEADERS.has(name.toLowerCase()) ? REDACTED : value;
	}
	return output;
}

function redactResponseHeaders(headers: Record<string, string | string[]>): Record<string, string | string[]> {
	const output: Record<string, string | string[]> = {};
	for (const [name, value] of Object.entries(headers)) {
		output[name] = SENSITIVE_HEADERS.has(name.toLowerCase()) ? REDACTED : value;
	}
	return output;
}

function redactRequestBody(body: string | undefined, headers: Record<string, string>): string | undefined {
	if (!body) { return body; }
	const contentType = headers['content-type']?.toLowerCase() ?? '';
	if (contentType.includes('application/json')) {
		try {
			const parsed = JSON.parse(body) as unknown;
			return JSON.stringify(redactJsonValue(parsed));
		} catch {
			return body;
		}
	}
	if (contentType.includes('application/x-www-form-urlencoded')) {
		try {
			const params = new URLSearchParams(body);
			for (const key of Array.from(params.keys())) {
				if (SENSITIVE_BODY_KEY.test(key)) {
					params.set(key, REDACTED);
				}
			}
			return params.toString();
		} catch {
			return body;
		}
	}
	return body;
}

function redactJsonValue(value: unknown, key?: string): unknown {
	if (key && SENSITIVE_BODY_KEY.test(key)) { return REDACTED; }
	if (Array.isArray(value)) {
		return value.map(item => redactJsonValue(item));
	}
	if (value && typeof value === 'object') {
		const output: Record<string, unknown> = {};
		for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
			output[childKey] = redactJsonValue(childValue, childKey);
		}
		return output;
	}
	return value;
}

function trimForReport(text: string): string {
	const normalized = text.trim();
	if (normalized.length === 0) {
		return '(empty response body)';
	}
	if (normalized.length <= 8_000) {
		return normalized;
	}
	return `${normalized.slice(0, 8_000)}\n\n... truncated for report ...`;
}

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

function resolveReadablePath(candidate: string): string {
	return path.isAbsolute(candidate)
		? candidate
		: path.resolve(getPathBaseDir(), candidate);
}

function resolveWritablePath(candidate: string): string {
	const resolvedPath = resolveReadablePath(candidate);
	validateWritablePath(resolvedPath);
	return resolvedPath;
}

function getPathBaseDir(): string {
	return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
}

function validateWritablePath(outputPath: string): void {
	const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
	const homeDir = require('os').homedir();
	const isInWorkspace = workspaceFolders.some((folder: vscode.WorkspaceFolder) => outputPath.startsWith(folder.uri.fsPath));
	const isInHome = outputPath.startsWith(homeDir);
	if (!isInWorkspace && !isInHome) {
		throw new Error(`Output path must be inside the workspace or user home directory: ${outputPath}`);
	}
}

function ensureWorkspaceRoot(): string {
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspaceRoot) {
		throw new Error('A workspace folder is required for Scylla HTTP persistence.');
	}
	return workspaceRoot;
}

function buildTimestampPrefix(): string {
	return new Date().toISOString().replace(/[:.]/g, '-');
}

function sanitizeFileName(value: string): string {
	return value
		.toLowerCase()
		.replace(/https?:\/\//g, '')
		.replace(/[^a-z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^-|-$/g, '')
		.slice(0, 80) || 'request';
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}
