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
		return path.isAbsolute(options.findingsDir)
			? options.findingsDir
			: path.join(workspaceRoot, options.findingsDir);
	}
	return path.join(workspaceRoot, FINDINGS_DIR);
}

export function resolveScanResultsDir(options?: ReportGenerateCommandOptions): string {
	const workspaceRoot = ensureWorkspaceRoot();
	if (options?.scanResultsDir) {
		return path.isAbsolute(options.scanResultsDir)
			? options.scanResultsDir
			: path.join(workspaceRoot, options.scanResultsDir);
	}
	return path.join(workspaceRoot, PIPELINE_OUTPUT_DIR);
}

export function resolveOutputPath(options?: ReportGenerateCommandOptions): string {
	const workspaceRoot = ensureWorkspaceRoot();
	if (options?.output?.path) {
		return path.isAbsolute(options.output.path)
			? options.output.path
			: path.join(workspaceRoot, options.output.path);
	}
	const format = options?.format ?? 'md';
	const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
	const fileName = `scylla-report-${timestamp}.${format}`;
	return path.join(workspaceRoot, REPORTS_DIR, fileName);
}

export function writeReport(content: string, outputPath: string): void {
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, content, 'utf8');
}

export function writeReportData(data: ReportData, outputPath: string): void {
	const jsonPath = outputPath.replace(/\.(md|html)$/, '.json');
	fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
	fs.writeFileSync(jsonPath, JSON.stringify(data, null, 2), 'utf8');
}

export function loadJsonFile<T>(filePath: string): T | null {
	try {
		if (!fs.existsSync(filePath)) { return null; }
		return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
	} catch {
		return null;
	}
}

export function listJsonFiles(dir: string): string[] {
	if (!fs.existsSync(dir)) { return []; }
	return fs.readdirSync(dir)
		.filter(f => f.endsWith('.json'))
		.map(f => path.join(dir, f))
		.sort();
}
