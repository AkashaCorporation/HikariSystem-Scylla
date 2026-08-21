/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { ReportGenerateCommandOptions } from './types';
import { generateReport } from './reportGenerator';

export function activate(context: vscode.ExtensionContext): void {
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.reporting.generate', async () => {
			const format = await vscode.window.showQuickPick(
				[
					{ label: 'Markdown', description: 'Generate Markdown and HTML companions', value: 'md' as const },
					{ label: 'HTML', description: 'Generate HTML and Markdown companions', value: 'html' as const },
				],
				{ placeHolder: 'Select the primary report format' },
			);
			if (!format) { return; }

			const title = await vscode.window.showInputBox({
				prompt: 'Report title',
				value: 'Scylla Security Assessment Report',
			});
			if (title === undefined) { return; }

			await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Generating Scylla report...', cancellable: false },
				async () => {
					try {
						const result = generateReport({ format: format.value, title: title || undefined });
						const selectedPath = format.value === 'html' ? result.htmlPath : result.markdownPath;
						const document = await vscode.workspace.openTextDocument(vscode.Uri.file(selectedPath));
						await vscode.window.showTextDocument(document, { preview: true });
						vscode.window.showInformationMessage(
							`Scylla report generated: ${result.data.executiveSummary.validatedFindings} validated, ` +
							`${result.data.executiveSummary.candidates} candidate(s), ${result.data.executiveSummary.observations} observation(s).`
						);
					} catch (error: unknown) {
						const message = error instanceof Error ? error.message : String(error);
						vscode.window.showErrorMessage(`Report generation failed: ${message}`);
					}
				},
			);
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.reporting.generateHeadless', async (options?: ReportGenerateCommandOptions) => {
			const result = generateReport(options ?? {});
			return {
				generatedAt: result.data.generatedAt,
				target: result.data.target,
				reportPath: result.reportPath,
				markdownPath: result.markdownPath,
				htmlPath: result.htmlPath,
				dataPath: result.dataPath,
				executiveSummary: result.data.executiveSummary,
				reconSummary: result.data.reconSummary,
				engagementSummary: result.data.engagementSummary,
				authorizationSummary: result.data.authorizationSummary,
				...(options?.includeData ? { data: result.data } : {}),
			};
		}),
	);
}

export function deactivate(): void { }
