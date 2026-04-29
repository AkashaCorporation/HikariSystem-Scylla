/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { ReportGenerateCommandOptions } from './types';
import { generateReport } from './reportGenerator';
import { renderHtmlReport } from './htmlRenderer';
import { resolveOutputPath, writeReport } from './artifacts';

export function activate(context: vscode.ExtensionContext): void {

	// -----------------------------------------------------------------------
	// Interactive: Generate Report
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.reporting.generate', async () => {
			const format = await vscode.window.showQuickPick(
				[
					{ label: 'Markdown', description: 'Generate a .md report', value: 'md' as const },
					{ label: 'HTML', description: 'Generate a standalone .html report', value: 'html' as const },
				],
				{ placeHolder: 'Select report format' },
			);
			if (!format) { return; }

			const title = await vscode.window.showInputBox({
				prompt: 'Report title',
				value: 'Scylla Penetration Test Report',
			});
			if (title === undefined) { return; }

			await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Generating report...', cancellable: false },
				async () => {
					try {
						const options: ReportGenerateCommandOptions = {
							format: format.value,
							title: title || undefined,
						};

						const result = generateReport(options);

						if (format.value === 'html') {
							const htmlContent = renderHtmlReport(result.data);
							const htmlPath = result.reportPath.replace(/\.md$/, '.html');
							writeReport(htmlContent, htmlPath);
							const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(htmlPath));
							await vscode.window.showTextDocument(doc, { preview: true });
							vscode.window.showInformationMessage(`Report generated: ${htmlPath}`);
						} else {
							const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(result.reportPath));
							await vscode.window.showTextDocument(doc, { preview: true });
							vscode.window.showInformationMessage(`Report generated: ${result.reportPath}`);
						}
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						vscode.window.showErrorMessage(`Report generation failed: ${msg}`);
					}
				},
			);
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Generate Report (for pipeline automation)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.reporting.generateHeadless', async (options?: ReportGenerateCommandOptions) => {
			const opts: ReportGenerateCommandOptions = options ?? {};
			const result = generateReport(opts);

			// If HTML format requested, also produce HTML
			if (opts.format === 'html') {
				const htmlContent = renderHtmlReport(result.data);
				const htmlPath = result.reportPath.replace(/\.md$/, '.html');
				writeReport(htmlContent, htmlPath);
				return {
					reportPath: htmlPath,
					markdownPath: result.reportPath,
					dataPath: result.dataPath,
					data: result.data,
				};
			}

			// Also always generate HTML as a secondary output
			const htmlContent = renderHtmlReport(result.data);
			const htmlPath = result.reportPath.replace(/\.md$/, '.html');
			writeReport(htmlContent, htmlPath);

			return {
				reportPath: result.reportPath,
				htmlPath,
				dataPath: result.dataPath,
				data: result.data,
			};
		}),
	);
}

export function deactivate(): void {}
