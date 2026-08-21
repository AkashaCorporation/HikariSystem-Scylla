/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ReportData, ReportGenerateCommandOptions } from './types';

const REPORTS_DIR = path.join('.scylla', 'reports');
const FINDINGS_DIR = path.join('.scylla', 'findings');
const PIPELINE_OUTPUT_DIR = path.join('.scylla', 'pipeline-output');
const ENGAGEMENTS_DIR = path.join('.scylla', 'engagements');

export interface ResolvedReportPaths {
	markdownPath: string;
	htmlPath: string;
	dataPath: string;
	primaryPath: string;
}

export function ensureWorkspaceRoot(): string {
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspaceRoot) {
		throw new Error('A workspace folder is required for Scylla Reporting.');
	}
	return workspaceRoot;
}

export function resolveFindingsDir(options?: ReportGenerateCommandOptions): string {
	const workspaceRoot = ensureWorkspaceRoot();
	if (options?.findingsDir) {
		return resolveAgainstWorkspace(options.findingsDir, workspaceRoot);
	}
	return path.join(workspaceRoot, FINDINGS_DIR);
}

export function resolveScanResultsDir(options?: ReportGenerateCommandOptions): string {
	const workspaceRoot = ensureWorkspaceRoot();
	if (options?.scanResultsDir) {
		return resolveAgainstWorkspace(options.scanResultsDir, workspaceRoot);
	}

	const pipelineRoot = path.join(workspaceRoot, PIPELINE_OUTPUT_DIR);
	const latest = findMostRecentPipelineRun(pipelineRoot);
	return latest ?? pipelineRoot;
}

/**
 * Resolve human-facing report files. The generic Jobs `output` path is an
 * envelope for command JSON, not a report destination. A legacy `output`
 * value is only honored when it explicitly ends in `.md` or `.html`.
 */
export function resolveReportPaths(options?: ReportGenerateCommandOptions): ResolvedReportPaths {
	const workspaceRoot = ensureWorkspaceRoot();
	const explicit = options?.reportOutput?.path ?? legacyReportPath(options?.output?.path);
	const format = options?.format ?? extensionFormat(explicit) ?? 'md';

	let primaryPath: string;
	if (explicit) {
		primaryPath = resolveAgainstWorkspace(explicit, workspaceRoot);
		const currentExtension = path.extname(primaryPath).toLowerCase();
		if (currentExtension !== '.md' && currentExtension !== '.html') {
			primaryPath = `${primaryPath}.${format}`;
		}
	} else {
		const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
		primaryPath = path.join(workspaceRoot, REPORTS_DIR, `scylla-report-${timestamp}.${format}`);
	}

	const base = primaryPath.replace(/\.(?:md|html)$/i, '');
	const markdownPath = `${base}.md`;
	const htmlPath = `${base}.html`;
	const dataPath = `${base}.data.json`;
	return {
		markdownPath,
		htmlPath,
		dataPath,
		primaryPath: format === 'html' ? htmlPath : markdownPath,
	};
}

export function resolvePipelineStatusPath(scanResultsDir: string, explicit?: string): string {
	const workspaceRoot = ensureWorkspaceRoot();
	return explicit
		? resolveAgainstWorkspace(explicit, workspaceRoot)
		: path.join(scanResultsDir, 'scylla-pipeline.status.json');
}

export function resolveEngagementFile(options?: ReportGenerateCommandOptions): string | undefined {
	const workspaceRoot = ensureWorkspaceRoot();
	if (options?.engagementFile) {
		return existingFile(resolveAgainstWorkspace(options.engagementFile, workspaceRoot));
	}

	const engagementsDir = path.join(workspaceRoot, ENGAGEMENTS_DIR);
	const activePath = path.join(engagementsDir, 'active.json');
	const active = loadJsonFile<Record<string, unknown>>(activePath);
	const activeId = typeof active?.engagementId === 'string'
		? active.engagementId
		: typeof active?.activeEngagementId === 'string'
			? active.activeEngagementId
			: undefined;
	if (activeId) {
		const direct = existingFile(path.join(engagementsDir, `${activeId}.json`));
		if (direct) { return direct; }
	}
	return newestJsonFile(engagementsDir, file => path.basename(file).toLowerCase() !== 'active.json');
}

export function resolveAuthorizationMatrixFile(
	options: ReportGenerateCommandOptions | undefined,
	scanResultsDir: string,
): string | undefined {
	const workspaceRoot = ensureWorkspaceRoot();
	if (options?.authorizationMatrixFile) {
		return existingFile(resolveAgainstWorkspace(options.authorizationMatrixFile, workspaceRoot));
	}
	const exact = existingFile(path.join(scanResultsDir, 'authorization-matrix.json'));
	if (exact) { return exact; }
	return newestJsonFile(scanResultsDir, file => path.basename(file).toLowerCase().includes('authorizationmatrix'));
}

export function writeReport(content: string, outputPath: string): void {
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, content, 'utf8');
}

export function writeReportData(data: ReportData, outputPath: string): void {
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, JSON.stringify(data, null, 2), 'utf8');
}

export function loadJsonFile<T>(filePath: string): T | null {
	try {
		if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) { return null; }
		return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
	} catch {
		return null;
	}
}

export function listJsonFiles(dir: string): string[] {
	if (!fs.existsSync(dir)) { return []; }
	const result: string[] = [];
	const walk = (current: string): void => {
		for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
			const fullPath = path.join(current, entry.name);
			if (entry.isDirectory()) {
				walk(fullPath);
			} else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
				result.push(fullPath);
			}
		}
	};
	walk(dir);
	return result.sort();
}

function resolveAgainstWorkspace(value: string, workspaceRoot: string): string {
	return path.isAbsolute(value) ? value : path.join(workspaceRoot, value);
}

function legacyReportPath(value?: string): string | undefined {
	if (!value) { return undefined; }
	return /\.(?:md|html)$/i.test(value) ? value : undefined;
}

function extensionFormat(value?: string): 'md' | 'html' | undefined {
	if (!value) { return undefined; }
	return path.extname(value).toLowerCase() === '.html' ? 'html'
		: path.extname(value).toLowerCase() === '.md' ? 'md'
			: undefined;
}

function existingFile(filePath: string): string | undefined {
	try {
		return fs.existsSync(filePath) && fs.statSync(filePath).isFile() ? filePath : undefined;
	} catch {
		return undefined;
	}
}

function newestJsonFile(dir: string, accept: (filePath: string) => boolean): string | undefined {
	return listJsonFiles(dir)
		.filter(accept)
		.map(filePath => ({ filePath, mtime: safeMtime(filePath) }))
		.sort((a, b) => b.mtime - a.mtime)[0]?.filePath;
}

function safeMtime(filePath: string): number {
	try { return fs.statSync(filePath).mtimeMs; } catch { return 0; }
}

function findMostRecentPipelineRun(root: string): string | undefined {
	if (!fs.existsSync(root)) { return undefined; }
	const candidates: Array<{ directory: string; mtime: number }> = [];
	const walk = (directory: string): void => {
		for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
			if (!entry.isDirectory()) { continue; }
			const child = path.join(directory, entry.name);
			const status = path.join(child, 'scylla-pipeline.status.json');
			if (fs.existsSync(status)) {
				candidates.push({ directory: child, mtime: safeMtime(status) });
			}
			walk(child);
		}
	};
	walk(root);
	return candidates.sort((a, b) => b.mtime - a.mtime)[0]?.directory;
}
