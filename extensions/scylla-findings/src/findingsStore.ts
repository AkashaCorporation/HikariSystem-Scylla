/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'open' | 'validated' | 'in-progress' | 'fixed' | 'accepted';

export interface CreateFindingCommandOptions {
	title?: string;
	severity?: FindingSeverity;
	status?: FindingStatus;
	target?: string;
	summary?: string;
	reproduction?: string;
	remediation?: string;
	evidence?: string[];
	tags?: string[];
	output?: { path?: string };
	quiet?: boolean;
}

export interface AppendEvidenceCommandOptions {
	file?: string;
	heading?: string;
	content?: string;
	quiet?: boolean;
}

export interface CreateFromHttpCommandOptions {
	responseFile?: string;
	title?: string;
	severity?: FindingSeverity;
	status?: FindingStatus;
	target?: string;
	summary?: string;
	note?: string;
	output?: { path?: string };
	quiet?: boolean;
}

export interface FindingDocumentData {
	id: string;
	title: string;
	severity: FindingSeverity;
	status: FindingStatus;
	target: string;
	createdAt: string;
	updatedAt: string;
	tags: string[];
	summary: string;
	reproduction: string;
	remediation: string;
	evidence: string[];
}

export interface FindingCreateResult {
	findingFile: string;
	finding: FindingDocumentData;
	generatedAt: string;
}

interface HttpResponseArtifact {
	generatedAt: string;
	request: {
		name?: string;
		method: string;
		url: string;
		headers: Record<string, string>;
		body?: string;
		timeoutMs: number;
		followRedirects: boolean;
	};
	response: {
		statusCode: number;
		statusMessage: string;
		headers: Record<string, string | string[]>;
		bodyText: string;
		bodyBytes: number;
		truncated: boolean;
		elapsedMs: number;
		redirected: boolean;
		redirectCount: number;
		finalUrl: string;
	};
}

const FINDINGS_DIR = path.join('.scylla', 'findings');
const DEFAULT_STATUS: FindingStatus = 'open';
const DEFAULT_SEVERITY: FindingSeverity = 'medium';

export function createFinding(options?: CreateFindingCommandOptions): FindingCreateResult {
	const normalized = normalizeFindingData(options);
	const findingFile = resolveFindingFilePath(options?.output?.path, normalized.title);
	fs.mkdirSync(path.dirname(findingFile), { recursive: true });
	fs.writeFileSync(findingFile, renderFinding(normalized), 'utf8');

	return {
		findingFile,
		finding: normalized,
		generatedAt: new Date().toISOString()
	};
}

export function appendEvidence(options?: AppendEvidenceCommandOptions): { findingFile: string; heading: string; generatedAt: string } {
	if (!options?.file) {
		throw new Error('scylla.findings.appendEvidenceHeadless requires a "file" argument.');
	}
	if (!options.content || options.content.trim().length === 0) {
		throw new Error('scylla.findings.appendEvidenceHeadless requires non-empty "content".');
	}

	const findingFile = resolveReadablePath(options.file);
	if (!fs.existsSync(findingFile)) {
		throw new Error(`Finding file not found: ${findingFile}`);
	}

	const heading = options.heading?.trim().length ? options.heading.trim() : 'Additional Evidence';
	const evidenceBlock = `\n### ${heading}\n\n${options.content.trim()}\n`;
	const current = fs.readFileSync(findingFile, 'utf8');
	const updated = injectEvidenceBlock(current, evidenceBlock);
	fs.writeFileSync(findingFile, updateFrontMatterTimestamp(updated), 'utf8');

	return {
		findingFile,
		heading,
		generatedAt: new Date().toISOString()
	};
}

export function createFindingFromHttp(options?: CreateFromHttpCommandOptions): FindingCreateResult {
	if (!options?.responseFile) {
		throw new Error('scylla.findings.createFromHttpHeadless requires a "responseFile" argument.');
	}

	const responseArtifact = readHttpResponseArtifact(options.responseFile);
	const target = options.target ?? responseArtifact.request.url;
	const title = options.title ?? buildHttpFindingTitle(responseArtifact);
	const summary = options.summary ?? buildHttpFindingSummary(responseArtifact);
	const evidence = buildHttpEvidence(responseArtifact, options.note);

	return createFinding({
		title,
		severity: options.severity ?? deriveSeverityFromHttp(responseArtifact.response.statusCode),
		status: options.status ?? DEFAULT_STATUS,
		target,
		summary,
		reproduction: buildHttpReproduction(responseArtifact),
		evidence,
		output: options.output
	});
}

export function normalizeSeverity(severity?: FindingSeverity): FindingSeverity {
	switch (severity) {
		case 'critical':
		case 'high':
		case 'medium':
		case 'low':
		case 'info':
			return severity;
		default:
			return DEFAULT_SEVERITY;
	}
}

function normalizeFindingData(options?: CreateFindingCommandOptions): FindingDocumentData {
	const now = new Date().toISOString();
	const title = options?.title?.trim();
	if (!title) {
		throw new Error('Finding title is required.');
	}

	const severity = normalizeSeverity(options?.severity);
	const status = normalizeStatus(options?.status);
	const target = options?.target?.trim() || 'unspecified-target';
	const summary = options?.summary?.trim() || 'Pending analyst summary.';
	const reproduction = options?.reproduction?.trim() || 'Pending reproduction steps.';
	const remediation = options?.remediation?.trim() || 'Pending remediation guidance.';
	const evidence = Array.isArray(options?.evidence)
		? options.evidence.filter(entry => typeof entry === 'string' && entry.trim().length > 0).map(entry => entry.trim())
		: [];
	const tags = Array.isArray(options?.tags)
		? options.tags.filter(tag => typeof tag === 'string' && tag.trim().length > 0).map(tag => tag.trim())
		: [];

	return {
		id: `${buildTimestampPrefix()}-${sanitizeFileName(title)}`,
		title,
		severity,
		status,
		target,
		createdAt: now,
		updatedAt: now,
		tags,
		summary,
		reproduction,
		remediation,
		evidence
	};
}

function normalizeStatus(status?: FindingStatus): FindingStatus {
	switch (status) {
		case 'open':
		case 'validated':
		case 'in-progress':
		case 'fixed':
		case 'accepted':
			return status;
		default:
			return DEFAULT_STATUS;
	}
}

function renderFinding(finding: FindingDocumentData): string {
	const lines: string[] = [];
	lines.push('---');
	lines.push(`id: ${finding.id}`);
	lines.push(`title: ${escapeFrontMatter(finding.title)}`);
	lines.push(`severity: ${finding.severity}`);
	lines.push(`status: ${finding.status}`);
	lines.push(`target: ${escapeFrontMatter(finding.target)}`);
	lines.push(`createdAt: ${finding.createdAt}`);
	lines.push(`updatedAt: ${finding.updatedAt}`);
	lines.push('tags:');
	if (finding.tags.length === 0) {
		lines.push('  - pending');
	} else {
		for (const tag of finding.tags) {
			lines.push(`  - ${escapeFrontMatter(tag)}`);
		}
	}
	lines.push('---');
	lines.push('');
	lines.push(`# ${finding.title}`);
	lines.push('');
	lines.push('## Summary');
	lines.push('');
	lines.push(finding.summary);
	lines.push('');
	lines.push('## Reproduction');
	lines.push('');
	lines.push(finding.reproduction);
	lines.push('');
	lines.push('## Evidence');
	lines.push('');
	if (finding.evidence.length === 0) {
		lines.push('- Pending evidence capture.');
	} else {
		for (const evidenceItem of finding.evidence) {
			lines.push(`- ${evidenceItem}`);
		}
	}
	lines.push('');
	lines.push('## Remediation');
	lines.push('');
	lines.push(finding.remediation);
	lines.push('');
	return lines.join('\n');
}

function injectEvidenceBlock(documentContent: string, evidenceBlock: string): string {
	const marker = '## Evidence';
	const index = documentContent.indexOf(marker);
	if (index === -1) {
		return `${documentContent.trimEnd()}\n\n## Evidence\n${evidenceBlock}`;
	}

	const insertAt = documentContent.indexOf('\n', index + marker.length);
	if (insertAt === -1) {
		return `${documentContent.trimEnd()}\n${evidenceBlock}`;
	}
	return `${documentContent.slice(0, insertAt + 1)}${evidenceBlock}${documentContent.slice(insertAt + 1)}`;
}

function updateFrontMatterTimestamp(documentContent: string): string {
	return documentContent.replace(/^updatedAt:\s+.+$/m, `updatedAt: ${new Date().toISOString()}`);
}

function resolveFindingFilePath(explicitPath: string | undefined, title: string): string {
	if (typeof explicitPath === 'string' && explicitPath.length > 0) {
		const resolved = resolveWritablePath(explicitPath);
		return resolved.toLowerCase().endsWith('.md') ? resolved : `${resolved}.md`;
	}
	const workspaceRoot = ensureWorkspaceRoot();
	return path.join(workspaceRoot, FINDINGS_DIR, `${buildTimestampPrefix()}-${sanitizeFileName(title)}.md`);
}

function readHttpResponseArtifact(filePath: string): HttpResponseArtifact {
	const resolvedPath = resolveReadablePath(filePath);
	if (!fs.existsSync(resolvedPath)) {
		throw new Error(`HTTP response artifact not found: ${resolvedPath}`);
	}
	try {
		return JSON.parse(fs.readFileSync(resolvedPath, 'utf8')) as HttpResponseArtifact;
	} catch (error: unknown) {
		throw new Error(`Failed to parse HTTP response artifact ${resolvedPath}: ${toErrorMessage(error)}`);
	}
}

function buildHttpFindingTitle(artifact: HttpResponseArtifact): string {
	const url = new URL(artifact.request.url);
	return `HTTP Observation: ${artifact.request.method.toUpperCase()} ${url.hostname}${url.pathname}`;
}

function buildHttpFindingSummary(artifact: HttpResponseArtifact): string {
	return `Observed HTTP ${artifact.response.statusCode} ${artifact.response.statusMessage} for ${artifact.request.method.toUpperCase()} ${artifact.request.url}. Review the captured response for security impact and triage.`;
}

function buildHttpReproduction(artifact: HttpResponseArtifact): string {
	return [
		`1. Replay ${artifact.request.method.toUpperCase()} ${artifact.request.url}.`,
		'2. Apply the same headers and body captured in the evidence section.',
		`3. Confirm the response returns status ${artifact.response.statusCode} and the same behavior.`
	].join('\n');
}

function buildHttpEvidence(artifact: HttpResponseArtifact, note?: string): string[] {
	const evidence: string[] = [];
	evidence.push(`Request: ${artifact.request.method.toUpperCase()} ${artifact.request.url}`);
	evidence.push(`Response: ${artifact.response.statusCode} ${artifact.response.statusMessage} in ${artifact.response.elapsedMs} ms`);
	evidence.push(`Final URL: ${artifact.response.finalUrl}`);
	evidence.push(`Redirects: ${artifact.response.redirectCount}`);
	evidence.push(`Body Size: ${artifact.response.bodyBytes} bytes`);
	if (artifact.request.body) {
		evidence.push(`Request Body: \`${trimInline(artifact.request.body, 400)}\``);
	}
	evidence.push(`Response Snippet: \`${trimInline(artifact.response.bodyText, 600)}\``);
	if (note && note.trim().length > 0) {
		evidence.push(`Analyst Note: ${note.trim()}`);
	}
	return evidence;
}

function deriveSeverityFromHttp(statusCode: number): FindingSeverity {
	if (statusCode >= 500) {
		return 'high';
	}
	if (statusCode >= 400) {
		return 'medium';
	}
	return DEFAULT_SEVERITY;
}

function trimInline(value: string, limit: number): string {
	const normalized = value.replace(/\s+/g, ' ').trim();
	if (normalized.length <= limit) {
		return normalized;
	}
	return `${normalized.slice(0, limit)}...`;
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
		throw new Error('A workspace folder is required for Scylla findings persistence.');
	}
	return workspaceRoot;
}

function buildTimestampPrefix(): string {
	return new Date().toISOString().replace(/[:.]/g, '-');
}

function sanitizeFileName(value: string): string {
	return value
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^-|-$/g, '')
		.slice(0, 80) || 'finding';
}

function escapeFrontMatter(value: string): string {
	return value.replace(/"/g, '\\"');
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}
