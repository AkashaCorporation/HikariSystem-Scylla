/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import {
	appendEvidence,
	createFinding,
	createFindingFromHttp,
	normalizeSeverity,
	type CreateFindingCommandOptions,
	type FindingSeverity
} from './findingsStore';

export function activate(context: vscode.ExtensionContext): void {
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.findings.create', async () => {
			const result = await createFindingInteractively();
			const document = await vscode.workspace.openTextDocument(result.findingFile);
			await vscode.window.showTextDocument(document, { preview: false });
		}),
		vscode.commands.registerCommand('scylla.findings.createHeadless', async (arg?: CreateFindingCommandOptions) => {
			const result = createFinding(arg);
			if (!arg?.quiet) {
				vscode.window.showInformationMessage(vscode.l10n.t('Scylla finding created at {0}', result.findingFile));
			}
			return result;
		}),
		vscode.commands.registerCommand('scylla.findings.appendEvidenceHeadless', async (arg?: import('./findingsStore').AppendEvidenceCommandOptions) => {
			const result = appendEvidence(arg);
			if (!arg?.quiet) {
				vscode.window.showInformationMessage(vscode.l10n.t('Evidence appended to {0}', result.findingFile));
			}
			return result;
		}),
		vscode.commands.registerCommand('scylla.findings.createFromHttpHeadless', async (arg?: import('./findingsStore').CreateFromHttpCommandOptions) => {
			const result = createFindingFromHttp(arg);
			if (!arg?.quiet) {
				vscode.window.showInformationMessage(vscode.l10n.t('HTTP finding created at {0}', result.findingFile));
			}
			return result;
		})
	);
}

async function createFindingInteractively() {
	const title = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Finding title'),
		placeHolder: vscode.l10n.t('Reflected XSS in search parameter'),
		validateInput: (value: string) => value.trim().length === 0 ? vscode.l10n.t('Finding title is required.') : null
	});
	if (!title) {
		throw new Error('Finding creation cancelled.');
	}

	const severityPick = await vscode.window.showQuickPick(['critical', 'high', 'medium', 'low', 'info'], {
		title: vscode.l10n.t('Severity'),
		placeHolder: vscode.l10n.t('Select a severity')
	});
	if (!severityPick) {
		throw new Error('Finding creation cancelled.');
	}

	const target = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Target'),
		placeHolder: 'https://target.tld'
	});
	if (!target) {
		throw new Error('Finding creation cancelled.');
	}

	const summary = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Summary'),
		placeHolder: vscode.l10n.t('Short description of the issue and why it matters')
	});

	return createFinding({
		title,
		severity: normalizeSeverity(severityPick as FindingSeverity),
		target,
		summary
	});
}

export function deactivate(): void { }
