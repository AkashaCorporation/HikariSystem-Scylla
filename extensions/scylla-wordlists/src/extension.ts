/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { WordlistProvider } from './wordlistProvider';

export function activate(context: vscode.ExtensionContext): void {
	const provider = new WordlistProvider();

	// -----------------------------------------------------------------------
	// Interactive: Browse Wordlists
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.wordlists.list', async () => {
			const wordlists = provider.listWordlists();
			const items = wordlists.map(wl => ({
				label: wl.name,
				description: `${wl.category} · ${wl.lineCount ?? '?'} entries`,
				detail: wl.description,
				id: wl.id,
			}));

			const picked = await vscode.window.showQuickPick(items, {
				placeHolder: 'Select a wordlist to preview or copy path',
			});

			if (!picked) { return; }

			const actions = ['Copy Path', 'Preview', 'Open File'];
			const action = await vscode.window.showQuickPick(actions, {
				placeHolder: `${picked.label} — What do you want to do?`,
			});

			if (!action) { return; }

			const filePath = provider.getPath(picked.id);
			if (!filePath) {
				vscode.window.showWarningMessage(`Wordlist file not found: ${picked.id}`);
				return;
			}

			switch (action) {
				case 'Copy Path':
					await vscode.env.clipboard.writeText(filePath);
					vscode.window.showInformationMessage(`Copied: ${filePath}`);
					break;
				case 'Preview': {
					const lines = provider.preview(picked.id, 100);
					const doc = await vscode.workspace.openTextDocument({
						content: `# ${picked.label}\n# ${lines.length} lines shown (preview)\n\n${lines.join('\n')}`,
						language: 'plaintext',
					});
					await vscode.window.showTextDocument(doc, { preview: true });
					break;
				}
				case 'Open File': {
					const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
					await vscode.window.showTextDocument(doc);
					break;
				}
			}
		}),
	);

	// -----------------------------------------------------------------------
	// Interactive: Preview Wordlist
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.wordlists.preview', async () => {
			const wordlists = provider.listWordlists();
			const items = wordlists.map(wl => ({
				label: wl.name,
				description: `${wl.lineCount ?? '?'} entries`,
				id: wl.id,
			}));

			const picked = await vscode.window.showQuickPick(items, {
				placeHolder: 'Select a wordlist to preview',
			});

			if (!picked) { return; }

			const lines = provider.preview(picked.id, 200);
			const doc = await vscode.workspace.openTextDocument({
				content: lines.join('\n'),
				language: 'plaintext',
			});
			await vscode.window.showTextDocument(doc, { preview: true });
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Get wordlist path by ID
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.wordlists.getPathHeadless', (options?: { id?: string }) => {
			if (!options?.id) {
				throw new Error('scylla.wordlists.getPathHeadless requires an "id" argument.');
			}
			const filePath = provider.getPath(options.id);
			if (!filePath) {
				throw new Error(`Wordlist not found: "${options.id}". Use scylla.wordlists.listHeadless to see available IDs.`);
			}
			return { id: options.id, path: filePath };
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: List available wordlists
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.wordlists.listHeadless', (options?: { category?: string }) => {
			const wordlists = options?.category
				? provider.listByCategory(options.category)
				: provider.listWordlists();

			return {
				generatedAt: new Date().toISOString(),
				count: wordlists.length,
				wordlists: wordlists.map(wl => ({
					id: wl.id,
					name: wl.name,
					category: wl.category,
					description: wl.description,
					lineCount: wl.lineCount,
				})),
			};
		}),
	);
}

export function deactivate(): void {}
