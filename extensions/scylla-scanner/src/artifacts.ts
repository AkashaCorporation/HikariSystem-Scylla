/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { CommandOutputOptions, CrawlResultFile, OutputFormat, ParameterTarget } from './types';

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
		throw new Error('A workspace folder is required for Scylla Scanner.');
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
		.slice(0, 80) || 'scan';
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
	const filePath = path.join(workspaceRoot, '.scylla', 'scanner', subDir, fileName);
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

/**
 * Load parameters from a crawl result file for pipeline integration.
 */
export function loadParametersFromCrawl(crawlResultFile: string): ParameterTarget[] {
	const resolved = resolveReadablePath(crawlResultFile);
	if (!fs.existsSync(resolved)) {
		throw new Error(`Crawl result file not found: ${resolved}`);
	}

	const raw = JSON.parse(fs.readFileSync(resolved, 'utf8')) as CrawlResultFile;
	const params: ParameterTarget[] = [];
	const seen = new Set<string>();

	// Extract from parameters array
	if (Array.isArray(raw.parameters)) {
		for (const p of raw.parameters) {
			const key = `${p.location}:${p.name}:${p.url}`;
			if (!seen.has(key)) {
				seen.add(key);
				params.push({
					name: p.name,
					value: 'test',
					location: p.location as ParameterTarget['location'],
				});
			}
		}
	}

	// Extract from forms
	if (Array.isArray(raw.forms)) {
		for (const form of raw.forms) {
			for (const input of form.inputs) {
				if (input.name) {
					const loc = form.method.toUpperCase() === 'GET' ? 'query' : 'body';
					const key = `${loc}:${input.name}:${form.action}`;
					if (!seen.has(key)) {
						seen.add(key);
						params.push({
							name: input.name,
							value: input.value ?? 'test',
							location: loc as ParameterTarget['location'],
						});
					}
				}
			}
		}
	}

	return params;
}

/**
 * Get target URLs from crawl result file.
 */
export function loadTargetsFromCrawl(crawlResultFile: string): string[] {
	const resolved = resolveReadablePath(crawlResultFile);
	if (!fs.existsSync(resolved)) {
		throw new Error(`Crawl result file not found: ${resolved}`);
	}

	const raw = JSON.parse(fs.readFileSync(resolved, 'utf8')) as CrawlResultFile;
	const urls = new Set<string>();

	if (Array.isArray(raw.parameters)) {
		for (const p of raw.parameters) {
			urls.add(p.url);
		}
	}

	if (Array.isArray(raw.forms)) {
		for (const form of raw.forms) {
			urls.add(form.action);
		}
	}

	if (Array.isArray(raw.discovered)) {
		for (const ep of raw.discovered) {
			if (ep.url) { urls.add(ep.url); }
		}
	}

	return Array.from(urls);
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
