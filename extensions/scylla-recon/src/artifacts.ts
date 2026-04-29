/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { CommandOutputOptions, OutputFormat } from './types';

export function resolveReadablePath(candidate: string): string {
	return path.isAbsolute(candidate)
		? candidate
		: path.resolve(getPathBaseDir(), candidate);
}

export function resolveWritablePath(candidate: string): string {
	const resolvedPath = resolveReadablePath(candidate);
	validateWritablePath(resolvedPath);
	return resolvedPath;
}

export function ensureWorkspaceRoot(): string {
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspaceRoot) {
		throw new Error('A workspace folder is required for Scylla Recon.');
	}
	return workspaceRoot;
}

export function buildTimestampPrefix(): string {
	return new Date().toISOString().replace(/[:.]/g, '-');
}

export function sanitizeFileName(value: string): string {
	return value
		.toLowerCase()
		.replace(/https?:\/\//g, '')
		.replace(/[^a-z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^-|-$/g, '')
		.slice(0, 80) || 'target';
}

export function writeResult(result: unknown, output: CommandOutputOptions, reportMarkdown?: string): void {
	const outputPath = resolveWritablePath(output.path);
	const format = normalizeOutputFormat(outputPath, output.format);
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });

	if (format === 'md' && reportMarkdown) {
		fs.writeFileSync(outputPath, reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
}

export function saveArtifact(subDir: string, name: string, data: unknown): string {
	const workspaceRoot = ensureWorkspaceRoot();
	const fileName = `${buildTimestampPrefix()}-${sanitizeFileName(name)}.json`;
	const filePath = path.join(workspaceRoot, '.scylla', 'recon', subDir, fileName);
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
	return filePath;
}

export function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
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

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}
