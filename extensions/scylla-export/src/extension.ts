/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ExportOptions } from './types';
import { loadFindings } from './findingsLoader';
import { exportJson, exportCsv, exportSarif } from './exporters';

export function activate(context: vscode.ExtensionContext): void {

	// -----------------------------------------------------------------------
	// Interactive: Export Findings (format picker)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.export.findings', async () => {
			const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			if (!workspaceRoot) {
				vscode.window.showErrorMessage('A workspace folder is required.');
				return;
			}

			const findingsDir = path.join(workspaceRoot, '.scylla', 'findings');
			if (!fs.existsSync(findingsDir)) {
				vscode.window.showWarningMessage('No findings directory found. Run a scan first or create findings with Scylla Findings.');
				return;
			}

			const format = await vscode.window.showQuickPick(
				[
					{ label: 'JSON', description: 'Structured JSON export', id: 'json' },
					{ label: 'CSV', description: 'Comma-separated values (Excel/Sheets)', id: 'csv' },
					{ label: 'SARIF 2.1', description: 'GitHub Security / Azure DevOps format', id: 'sarif' },
				],
				{ placeHolder: 'Select export format' },
			);

			if (!format) { return; }

			const findings = loadFindings(findingsDir);
			if (findings.length === 0) {
				vscode.window.showWarningMessage('No findings to export.');
				return;
			}

			const ext = format.id === 'sarif' ? '.sarif.json' : `.${format.id}`;
			const outputPath = path.join(workspaceRoot, '.scylla', `findings-export${ext}`);

			let result;
			switch (format.id) {
				case 'json':
					result = exportJson(findings, outputPath);
					break;
				case 'csv':
					result = exportCsv(findings, outputPath);
					break;
				case 'sarif':
					result = exportSarif(findings, outputPath);
					break;
			}

			if (result) {
				vscode.window.showInformationMessage(
					`Exported ${result.findingsCount} findings to ${format.label}: ${result.outputPath}`
				);
				const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(result.outputPath));
				await vscode.window.showTextDocument(doc, { preview: true });
			}
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Export JSON
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.export.jsonHeadless', (options?: ExportOptions) => {
			const findings = loadFindings(options?.findingsDir, {
				severity: options?.severity,
				status: options?.status,
			});
			const outputPath = resolveOutputPath(options?.outputPath, 'json');
			return exportJson(findings, outputPath);
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Export CSV
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.export.csvHeadless', (options?: ExportOptions) => {
			const findings = loadFindings(options?.findingsDir, {
				severity: options?.severity,
				status: options?.status,
			});
			const outputPath = resolveOutputPath(options?.outputPath, 'csv');
			return exportCsv(findings, outputPath);
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Export SARIF
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.export.sarifHeadless', (options?: ExportOptions) => {
			const findings = loadFindings(options?.findingsDir, {
				severity: options?.severity,
				status: options?.status,
			});
			const outputPath = resolveOutputPath(options?.outputPath, 'sarif.json');
			return exportSarif(findings, outputPath);
		}),
	);
}

function resolveOutputPath(explicitPath: string | undefined, ext: string): string {
	if (explicitPath) {
		return path.isAbsolute(explicitPath) ? explicitPath : path.join(getWorkspaceRoot(), explicitPath);
	}
	return path.join(getWorkspaceRoot(), '.scylla', `findings-export.${ext}`);
}

function getWorkspaceRoot(): string {
	return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
}

export function deactivate(): void {}
