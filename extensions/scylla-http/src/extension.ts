/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import {
	generateSendReport,
	loadRequestDefinition,
	normalizeMaxBodyBytes,
	normalizeRequestDefinition,
	normalizeSendOptions,
	normalizeTimeout,
	parseRequestDocument,
	saveRequestDefinition,
	saveResponseArtifact,
	validateHttpUrl,
	writeSendOutput
} from './artifacts';
import { performRequest } from './httpClient';
import { hostResolver } from './hostResolver';
import type { HttpRequestDefinition, HttpSaveRequestCommandOptions, HttpSendCommandOptions, HttpSendResult, SavedRequestResult } from './types';

export function activate(context: vscode.ExtensionContext): void {
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.http.createRequest', async () => {
			const saved = await createRequestInteractively();
			const document = await vscode.workspace.openTextDocument(saved.requestFile);
			await vscode.window.showTextDocument(document, { preview: false });
		}),
		vscode.commands.registerCommand('scylla.http.send', async (arg?: vscode.Uri | HttpSendCommandOptions) => {
			const options = normalizeSendOptions(arg);
			const requestDefinition = await resolveInteractiveRequestDefinition(arg, options);
			if (!requestDefinition) {
				return undefined;
			}

			const result = await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: vscode.l10n.t('Scylla HTTP: Sending {0}', requestDefinition.name ?? requestDefinition.url),
					cancellable: false
				},
				async () => executeSend(requestDefinition, options, options.file)
			);

			const document = await vscode.workspace.openTextDocument({ content: result.reportMarkdown, language: 'markdown' });
			await vscode.window.showTextDocument(document, { preview: false });
			return result;
		}),
		vscode.commands.registerCommand('scylla.http.sendHeadless', async (arg?: HttpSendCommandOptions) => {
			const options = normalizeSendOptions(arg);
			const requestDefinition = resolveHeadlessRequestDefinition(options);
			const result = await executeSend(requestDefinition, options, options.file);
			if (options.output) {
				writeSendOutput(result, options.output);
			}
			return stripMarkdown(result);
		}),
		vscode.commands.registerCommand('scylla.http.saveRequestHeadless', async (arg?: HttpSaveRequestCommandOptions) => {
			const saved = saveRequestDefinition(normalizeRequestDefinition(arg), arg?.output?.path);
			if (!arg?.quiet) {
				vscode.window.showInformationMessage(vscode.l10n.t('Scylla HTTP request saved to {0}', saved.requestFile));
			}
			return saved;
		}),
		vscode.commands.registerCommand('scylla.http.replayHeadless', async (arg?: HttpSendCommandOptions) => {
			const options = normalizeSendOptions(arg);
			if (!options.file) {
				throw new Error('scylla.http.replayHeadless requires a "file" argument.');
			}
			const result = await executeSend(loadRequestDefinition(options.file), options, options.file);
			if (options.output) {
				writeSendOutput(result, options.output);
			}
			return stripMarkdown(result);
		}),

		// -----------------------------------------------------------------
		// Host resolver commands  (internal DNS for CTF/HTB vhosts)
		// -----------------------------------------------------------------

		vscode.commands.registerCommand('scylla.http.setHostsHeadless', (arg?: { hosts?: Record<string, string> }) => {
			if (!arg?.hosts || typeof arg.hosts !== 'object') {
				throw new Error('scylla.http.setHostsHeadless requires a "hosts" object (hostname → IP).');
			}
			hostResolver.setAll(arg.hosts);
			return { registered: Object.keys(arg.hosts).length, total: hostResolver.size };
		}),

		vscode.commands.registerCommand('scylla.http.clearHostsHeadless', () => {
			const count = hostResolver.size;
			hostResolver.clear();
			return { cleared: count };
		}),

		vscode.commands.registerCommand('scylla.http.getHostsHeadless', () => {
			return { hosts: hostResolver.getAll(), count: hostResolver.size };
		})
	);
}

async function createRequestInteractively(): Promise<SavedRequestResult> {
	const name = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Request name'),
		placeHolder: vscode.l10n.t('login-check'),
		validateInput: (value: string) => value.trim().length === 0 ? vscode.l10n.t('Request name is required.') : null
	});
	if (!name) {
		throw new Error('Request creation cancelled.');
	}

	const method = await vscode.window.showQuickPick(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], {
		title: vscode.l10n.t('HTTP method'),
		placeHolder: vscode.l10n.t('Select an HTTP method')
	});
	const url = method ? await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Target URL'),
		placeHolder: 'https://target.tld/api',
		validateInput: (value: string) => validateHttpUrl(value)
	}) : undefined;
	if (!method || !url) {
		throw new Error('Request creation cancelled.');
	}

	const body = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Request body (optional)'),
		placeHolder: '{"ping":"pong"}'
	});
	return saveRequestDefinition(normalizeRequestDefinition({ name, method, url, body }));
}

async function resolveInteractiveRequestDefinition(
	arg: vscode.Uri | HttpSendCommandOptions | undefined,
	options: HttpSendCommandOptions
): Promise<HttpRequestDefinition | undefined> {
	if (arg instanceof vscode.Uri) {
		return loadRequestDefinition(arg.fsPath);
	}
	if (options.file) {
		return loadRequestDefinition(options.file);
	}
	if (options.url) {
		return normalizeRequestDefinition(options);
	}
	const activeRequest = parseActiveEditorRequest();
	if (activeRequest) {
		return activeRequest;
	}
	return promptForInlineRequest();
}

function resolveHeadlessRequestDefinition(options: HttpSendCommandOptions): HttpRequestDefinition {
	if (options.file) {
		return loadRequestDefinition(options.file);
	}
	if (options.url) {
		return normalizeRequestDefinition(options);
	}
	throw new Error('scylla.http.sendHeadless requires either a "file" or a "url" argument.');
}

function parseActiveEditorRequest(): HttpRequestDefinition | undefined {
	const editor = vscode.window.activeTextEditor;
	if (!editor || editor.document.uri.scheme !== 'file') {
		return undefined;
	}

	try {
		return parseRequestDocument(editor.document.getText(), editor.document.uri.fsPath);
	} catch {
		return undefined;
	}
}

async function promptForInlineRequest(): Promise<HttpRequestDefinition | undefined> {
	const method = await vscode.window.showQuickPick(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], {
		title: vscode.l10n.t('HTTP method'),
		placeHolder: vscode.l10n.t('Select an HTTP method')
	});
	if (!method) {
		return undefined;
	}

	const url = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Target URL'),
		placeHolder: 'https://target.tld/api',
		validateInput: (value: string) => validateHttpUrl(value)
	});
	if (!url) {
		return undefined;
	}

	const body = await vscode.window.showInputBox({
		prompt: vscode.l10n.t('Request body (optional)'),
		placeHolder: '{"ping":"pong"}'
	});
	return normalizeRequestDefinition({ method, url, body });
}

async function executeSend(
	requestDefinition: HttpRequestDefinition,
	options: HttpSendCommandOptions,
	requestFile?: string
): Promise<HttpSendResult> {
	const normalizedRequest = normalizeRequestDefinition({
		...requestDefinition,
		timeoutMs: requestDefinition.timeoutMs ?? options.timeoutMs,
		followRedirects: options.followRedirects ?? requestDefinition.followRedirects
	});
	const response = await performRequest(normalizedRequest, normalizeMaxBodyBytes(options.maxBodyBytes));
	const generatedAt = new Date().toISOString();
	const result: HttpSendResult = {
		generatedAt,
		request: {
			name: normalizedRequest.name,
			method: normalizedRequest.method.toUpperCase(),
			url: normalizedRequest.url,
			headers: normalizedRequest.headers ?? {},
			body: normalizedRequest.body,
			timeoutMs: normalizeTimeout(normalizedRequest.timeoutMs),
			followRedirects: normalizedRequest.followRedirects !== false
		},
		response,
		requestFile,
		responseFile: options.saveResponse === true || !options.quiet ? saveResponseArtifact(normalizedRequest, response, generatedAt) : undefined,
		reportMarkdown: ''
	};
	result.reportMarkdown = generateSendReport(result);
	return result;
}

function stripMarkdown(result: HttpSendResult): Omit<HttpSendResult, 'reportMarkdown'> {
	const { reportMarkdown: _reportMarkdown, ...rest } = result;
	return rest;
}

export function deactivate(): void { }
