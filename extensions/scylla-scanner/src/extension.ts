/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { loadParametersFromCrawl, loadTargetsFromCrawl, saveArtifact, toErrorMessage, writeResult } from './artifacts';
import { autoScan, generateAutoScanReport } from './autoScanner';
import { scanCors, generateCorsReport } from './corsScanner';
import { scanDomxss, generateDomxssReport } from './domxssScanner';
import { scanGraphql, generateGraphqlReport } from './graphqlScanner';
import { scanHeaders, generateHeadersReport } from './headersScanner';
import { scanIdor, generateIdorReport } from './idorScanner';
import { scanJwt, generateJwtReport } from './jwtScanner';
import { generateLfiReport, scanLfi } from './lfiScanner';
import { scanMassAssign, generateMassAssignReport } from './massAssignScanner';
import { scanParams, generateParamsReport } from './paramsScanner';
import { scanPrivesc, generatePrivescReport } from './privescScanner';
import { scanRedirect, generateRedirectReport } from './redirectScanner';
import { generateSecretsReport, scanSecrets } from './secretsScanner';
import { generateSqliReport, scanSqli } from './sqliScanner';
import { scanSsrf, generateSsrfReport } from './ssrfScanner';
import { generateSstiReport, scanSsti } from './sstiScanner';
import { generateXssReport, scanXss } from './xssScanner';
import { extractSqli, generateSqliExtractReport } from './sqliExtractor';
import { generateXssExploits, generateXssExploitReport } from './xssExploiter';
import { exploitLfi, generateLfiExploitReport } from './lfiExploiter';
import type {
	AutoScanCommandOptions,
	CorsScanCommandOptions,
	DomxssScanCommandOptions,
	GraphqlScanCommandOptions,
	HeadersScanCommandOptions,
	IdorScanCommandOptions,
	JwtScanCommandOptions,
	LfiExploitCommandOptions,
	LfiScanCommandOptions,
	MassAssignScanCommandOptions,
	ParameterTarget,
	ParamsScanCommandOptions,
	PrivescScanCommandOptions,
	RedirectScanCommandOptions,
	SecretsScanCommandOptions,
	SqliExtractCommandOptions,
	SqliScanCommandOptions,
	SsrfScanCommandOptions,
	SstiScanCommandOptions,
	VulnFinding,
	XssExploitCommandOptions,
	XssScanCommandOptions,
} from './types';

// ---------------------------------------------------------------------------
// Reactive Tree Data Provider
// ---------------------------------------------------------------------------

class ScannerTreeProvider implements vscode.TreeDataProvider<string> {
	private _onDidChange = new vscode.EventEmitter<string | undefined>();
	readonly onDidChangeTreeData = this._onDidChange.event;

	private items: string[] = [];
	private emptyMessage: string;

	constructor(emptyMessage: string) {
		this.emptyMessage = emptyMessage;
	}

	refresh(items: string[]): void {
		this.items = items;
		this._onDidChange.fire(undefined);
	}

	append(items: string[]): void {
		this.items.push(...items);
		this._onDidChange.fire(undefined);
	}

	getTreeItem(element: string): vscode.TreeItem {
		const item = new vscode.TreeItem(element);
		// Color-code by severity
		if (element.startsWith('[CRITICAL]')) {
			item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
		} else if (element.startsWith('[HIGH]')) {
			item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
		} else if (element.startsWith('[MEDIUM]')) {
			item.iconPath = new vscode.ThemeIcon('warning');
		} else if (element.startsWith('[LOW]')) {
			item.iconPath = new vscode.ThemeIcon('info');
		} else if (element.startsWith('[INFO]')) {
			item.iconPath = new vscode.ThemeIcon('info');
		} else if (element === this.emptyMessage) {
			item.iconPath = new vscode.ThemeIcon('shield');
		}
		return item;
	}

	getChildren(): string[] {
		return this.items.length > 0 ? this.items : [this.emptyMessage];
	}
}

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {

	// Reactive sidebar providers
	const findingsProvider = new ScannerTreeProvider('No findings yet — run a scan');
	const historyProvider = new ScannerTreeProvider('No scans run yet');

	const allFindings: string[] = [];
	const scanHistory: string[] = [];

	function addFindings(findings: VulnFinding[], scanType: string, target: string): void {
		const timestamp = new Date().toLocaleTimeString();

		for (const f of findings) {
			allFindings.push(`[${f.severity.toUpperCase()}] ${f.type}: ${f.title}`);
		}
		findingsProvider.refresh(allFindings);

		scanHistory.unshift(`${timestamp} — ${scanType}: ${findings.length} findings on ${truncate(target, 30)}`);
		historyProvider.refresh(scanHistory);
	}

	function addScanEntry(scanType: string, target: string, findingCount: number): void {
		const timestamp = new Date().toLocaleTimeString();
		scanHistory.unshift(`${timestamp} — ${scanType}: ${findingCount} findings on ${truncate(target, 30)}`);
		historyProvider.refresh(scanHistory);
	}

	// Helper: resolve parameters from options (direct or from crawl file)
	function resolveParameters(options: { url?: string; parameters?: ParameterTarget[]; crawlResultFile?: string }): { url: string; params: ParameterTarget[] } {
		const url = options.url;
		if (!url) { throw new Error('A "url" argument is required.'); }

		if (options.parameters && options.parameters.length > 0) {
			return { url, params: options.parameters };
		}

		if (options.crawlResultFile) {
			const params = loadParametersFromCrawl(options.crawlResultFile);
			return { url, params };
		}

		// If no params provided, extract from URL query string
		try {
			const parsed = new URL(url);
			const params: ParameterTarget[] = [];
			for (const [name, value] of parsed.searchParams) {
				params.push({ name, value, location: 'query' });
			}
			return { url, params };
		} catch {
			return { url, params: [] };
		}
	}

	// Helper: create findings from scan results while preserving the structured
	// evidence lifecycle and cross-profile provenance emitted by scanners.
	async function createFindingsFromResults(findings: VulnFinding[], quiet: boolean): Promise<void> {
		for (const f of findings) {
			try {
				await vscode.commands.executeCommand('scylla.findings.createHeadless', {
					title: f.title,
					severity: f.severity,
					status: 'open',
					classification: f.state ?? 'candidate',
					confidence: f.confidence,
					source: f.source,
					actors: f.actors,
					target: f.url,
					summary: f.details,
					evidence: [f.evidence, `Payload: ${f.payload}`],
					tags: [f.type, `state:${f.state ?? 'candidate'}`, `confidence:${Math.round(f.confidence * 100)}%`],
					quiet,
				});
			} catch {
				// Findings extension may not be available
			}
		}
	}

	const commonOpts = (arg: { delayMs?: number; timeoutMs?: number; headers?: Record<string, string>; cookie?: string }) => ({
		delayMs: arg.delayMs,
		timeoutMs: arg.timeoutMs,
		headers: arg.headers,
		cookie: arg.cookie,
	});

	// -----------------------------------------------------------------------
	// SQLi Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.sqli', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with parameters', placeHolder: 'http://target.com/page?id=1' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				if (params.length === 0) { vscode.window.showWarningMessage('No parameters found in URL.'); return; }
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for SQLi...', cancellable: false },
					() => scanSqli(resolvedUrl, params)
				);
				addFindings(result.findings, 'SQLi', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateSqliReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('sqli', url, result);
			} catch (e) { vscode.window.showErrorMessage(`SQLi scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.sqliHeadless', async (arg?: SqliScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await scanSqli(url, params, { ...commonOpts(opts), techniques: opts.techniques?.filter((t): t is 'error' | 'time-blind' => t !== 'boolean-blind'), dbms: opts.dbms });
			addFindings(result.findings, 'SQLi', url);
			if (opts.output) { writeResult(result, opts.output, generateSqliReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`SQLi scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// XSS Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.xss', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with parameters', placeHolder: 'http://target.com/search?q=test' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				if (params.length === 0) { vscode.window.showWarningMessage('No parameters found in URL.'); return; }
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for XSS...', cancellable: false },
					() => scanXss(resolvedUrl, params)
				);
				addFindings(result.findings, 'XSS', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateXssReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('xss', url, result);
			} catch (e) { vscode.window.showErrorMessage(`XSS scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.xssHeadless', async (arg?: XssScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await scanXss(url, params, { ...commonOpts(opts), contexts: opts.contexts });
			addFindings(result.findings, 'XSS', url);
			if (opts.output) { writeResult(result, opts.output, generateXssReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`XSS scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// LFI Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.lfi', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with parameters', placeHolder: 'http://target.com/page?file=test' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				if (params.length === 0) { vscode.window.showWarningMessage('No parameters found in URL.'); return; }
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for LFI...', cancellable: false },
					() => scanLfi(resolvedUrl, params)
				);
				addFindings(result.findings, 'LFI', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateLfiReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('lfi', url, result);
			} catch (e) { vscode.window.showErrorMessage(`LFI scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.lfiHeadless', async (arg?: LfiScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await scanLfi(url, params, { ...commonOpts(opts), osTargets: opts.osTargets, encodings: opts.encodings });
			addFindings(result.findings, 'LFI', url);
			if (opts.output) { writeResult(result, opts.output, generateLfiReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`LFI scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// SSTI Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.ssti', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with parameters', placeHolder: 'http://target.com/render?template=test' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				if (params.length === 0) { vscode.window.showWarningMessage('No parameters found in URL.'); return; }
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for SSTI...', cancellable: false },
					() => scanSsti(resolvedUrl, params)
				);
				addFindings(result.findings, 'SSTI', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateSstiReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('ssti', url, result);
			} catch (e) { vscode.window.showErrorMessage(`SSTI scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.sstiHeadless', async (arg?: SstiScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await scanSsti(url, params, { ...commonOpts(opts), engines: opts.engines });
			addFindings(result.findings, 'SSTI', url);
			if (opts.output) { writeResult(result, opts.output, generateSstiReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`SSTI scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Secrets Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.secrets', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'URL to scan for secrets', placeHolder: 'http://target.com/app.js' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for secrets...', cancellable: false },
					() => scanSecrets({ url })
				);
				addFindings(result.findings, 'Secrets', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateSecretsReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('secrets', url, result);
			} catch (e) { vscode.window.showErrorMessage(`Secrets scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.secretsHeadless', async (arg?: SecretsScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url && !opts.content) { throw new Error('Either "url" or "content" is required.'); }

			// If crawl result file provided, scan all discovered URLs
			if (opts.crawlResultFile && !opts.content) {
				const urls = loadTargetsFromCrawl(opts.crawlResultFile);
				const crawlFindings: VulnFinding[] = [];
				for (const targetUrl of urls.slice(0, 50)) {
					const result = await scanSecrets({ url: targetUrl, ...commonOpts(opts) });
					crawlFindings.push(...result.findings);
				}
				const aggregated = {
					generatedAt: new Date().toISOString(),
					target: opts.url ?? urls[0] ?? '(crawl)',
					sourcesScanned: urls.length,
					findings: crawlFindings,
					elapsedMs: 0,
				};
				addFindings(crawlFindings, 'Secrets', opts.url ?? '(crawl)');
				if (opts.output) { writeResult(aggregated, opts.output, generateSecretsReport(aggregated)); }
				if (opts.createFindings) { await createFindingsFromResults(crawlFindings, opts.quiet ?? true); }
				return aggregated;
			}

			const result = await scanSecrets({ url: opts.url, content: opts.content, ...commonOpts(opts) });
			addFindings(result.findings, 'Secrets', opts.url ?? '(content)');
			if (opts.output) { writeResult(result, opts.output, generateSecretsReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`Secrets scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// CORS Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.cors', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL to check CORS policy', placeHolder: 'http://target.com/api/endpoint' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for CORS misconfigurations...', cancellable: false },
					() => scanCors(url)
				);
				addFindings(result.findings, 'CORS', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateCorsReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('cors', url, result);
			} catch (e) { vscode.window.showErrorMessage(`CORS scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.corsHeadless', async (arg?: CorsScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanCors(opts.url, { ...commonOpts(opts) });
			addFindings(result.findings, 'CORS', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateCorsReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`CORS scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Security Headers Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.headers', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL to check security headers', placeHolder: 'http://target.com/' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning security headers...', cancellable: false },
					() => scanHeaders(url)
				);
				addFindings(result.findings, 'Headers', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateHeadersReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('headers', url, result);
			} catch (e) { vscode.window.showErrorMessage(`Headers scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.headersHeadless', async (arg?: HeadersScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanHeaders(opts.url, { ...commonOpts(opts) });
			addFindings(result.findings, 'Headers', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateHeadersReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`Headers scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// DOM XSS Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.domxss', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL to scan for DOM XSS sinks', placeHolder: 'http://target.com/app' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for DOM XSS...', cancellable: false },
					() => scanDomxss(url)
				);
				addFindings(result.findings, 'DOM XSS', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateDomxssReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('domxss', url, result);
			} catch (e) { vscode.window.showErrorMessage(`DOM XSS scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.domxssHeadless', async (arg?: DomxssScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanDomxss(opts.url, { ...commonOpts(opts) });
			addFindings(result.findings, 'DOM XSS', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateDomxssReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`DOM XSS scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Hidden Params Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.params', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL to discover hidden parameters', placeHolder: 'http://target.com/api/endpoint' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Discovering hidden parameters...', cancellable: false },
					() => scanParams(url)
				);
				addFindings(result.findings, 'Params', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateParamsReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('params', url, result);
			} catch (e) { vscode.window.showErrorMessage(`Params scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.paramsHeadless', async (arg?: ParamsScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanParams(opts.url, { ...commonOpts(opts), wordlist: opts.wordlist });
			addFindings(result.findings, 'Params', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateParamsReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`Params scan: ${result.findings.length} findings, ${result.discoveredParams.length} params discovered`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Open Redirect Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.redirect', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with parameters', placeHolder: 'http://target.com/login?redirect=/' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				if (params.length === 0) { vscode.window.showWarningMessage('No parameters found in URL.'); return; }
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for open redirects...', cancellable: false },
					() => scanRedirect(resolvedUrl, params)
				);
				addFindings(result.findings, 'Redirect', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateRedirectReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('redirect', url, result);
			} catch (e) { vscode.window.showErrorMessage(`Redirect scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.redirectHeadless', async (arg?: RedirectScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await scanRedirect(url, params, { ...commonOpts(opts) });
			addFindings(result.findings, 'Redirect', url);
			if (opts.output) { writeResult(result, opts.output, generateRedirectReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`Redirect scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// JWT Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.jwt', async () => {
			const token = await vscode.window.showInputBox({ prompt: 'JWT token to analyze', placeHolder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' });
			if (!token) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Analyzing JWT token...', cancellable: false },
					() => scanJwt(token)
				);
				addFindings(result.findings, 'JWT', token);
				const doc = await vscode.workspace.openTextDocument({ content: generateJwtReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('jwt', token, result);
			} catch (e) { vscode.window.showErrorMessage(`JWT scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.jwtHeadless', async (arg?: JwtScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.token) { throw new Error('A "token" argument is required.'); }
			const result = await scanJwt(opts.token, { ...commonOpts(opts), attacks: opts.attacks });
			addFindings(result.findings, 'JWT', opts.token);
			if (opts.output) { writeResult(result, opts.output, generateJwtReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`JWT scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// GraphQL Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.graphql', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'GraphQL endpoint URL', placeHolder: 'http://target.com/graphql' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning GraphQL endpoint...', cancellable: false },
					() => scanGraphql(url)
				);
				addFindings(result.findings, 'GraphQL', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateGraphqlReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('graphql', url, result);
			} catch (e) { vscode.window.showErrorMessage(`GraphQL scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.graphqlHeadless', async (arg?: GraphqlScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanGraphql(opts.url, { ...commonOpts(opts), attacks: opts.attacks });
			addFindings(result.findings, 'GraphQL', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateGraphqlReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`GraphQL scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// SSRF Scanner
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.ssrf', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with parameters', placeHolder: 'http://target.com/fetch?url=http://example.com' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				if (params.length === 0) { vscode.window.showWarningMessage('No parameters found in URL.'); return; }
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for SSRF...', cancellable: false },
					() => scanSsrf(resolvedUrl, params)
				);
				addFindings(result.findings, 'SSRF', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateSsrfReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('ssrf', url, result);
			} catch (e) { vscode.window.showErrorMessage(`SSRF scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.ssrfHeadless', async (arg?: SsrfScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await scanSsrf(url, params, { ...commonOpts(opts) });
			addFindings(result.findings, 'SSRF', url);
			if (opts.output) { writeResult(result, opts.output, generateSsrfReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`SSRF scan: ${result.findings.length} findings`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// SQLi Extractor (Exploitation)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.sqliExtract', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with vulnerable parameter', placeHolder: 'http://target.com/page?id=1' });
			if (!url) { return; }
			const paramName = await vscode.window.showInputBox({ prompt: 'Vulnerable parameter name', placeHolder: 'id' });
			if (!paramName) { return; }
			const location = await vscode.window.showQuickPick(['query', 'body'], { placeHolder: 'Parameter location' }) as 'query' | 'body' | undefined;
			if (!location) { return; }
			const dbms = await vscode.window.showQuickPick(['auto', 'mysql', 'postgresql', 'mssql', 'sqlite', 'oracle'], { placeHolder: 'Target DBMS (auto = fingerprint)' });
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Extracting data via SQLi...', cancellable: false },
					() => extractSqli(url, { name: paramName, location }, {
						dbms: dbms === 'auto' ? undefined : dbms,
					})
				);
				addScanEntry('SQLi Extract', url, result.extractedData.length);
				const doc = await vscode.workspace.openTextDocument({ content: generateSqliExtractReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('sqli-extract', url, result);
			} catch (e) { vscode.window.showErrorMessage(`SQLi extraction failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.sqliExtractHeadless', async (arg?: SqliExtractCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			if (!opts.parameter) { throw new Error('A "parameter" argument is required ({ name, location }).'); }
			const result = await extractSqli(opts.url, opts.parameter, {
				dbms: opts.dbms,
				technique: opts.technique,
				maxRows: opts.maxRows,
				delayMs: opts.delayMs,
				timeoutMs: opts.timeoutMs,
				headers: opts.headers,
				cookie: opts.cookie,
			});
			addScanEntry('SQLi Extract', opts.url, result.extractedData.length);
			if (opts.output) { writeResult(result, opts.output, generateSqliExtractReport(result)); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`SQLi extraction: ${result.databases.length} DBs, ${result.tables.length} tables, ${result.extractedData.length} datasets`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// XSS Exploiter (Exploitation)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.xssExploit', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with XSS-vulnerable parameter', placeHolder: 'http://target.com/search?q=test' });
			if (!url) { return; }
			const paramName = await vscode.window.showInputBox({ prompt: 'Vulnerable parameter name', placeHolder: 'q' });
			if (!paramName) { return; }
			const context = await vscode.window.showQuickPick(['html', 'attribute', 'javascript', 'url'], { placeHolder: 'XSS context' }) as 'html' | 'attribute' | 'javascript' | 'url' | undefined;
			if (!context) { return; }
			const callbackUrl = await vscode.window.showInputBox({ prompt: 'Callback URL for data exfiltration', placeHolder: 'http://attacker.com/collect' });
			if (!callbackUrl) { return; }
			try {
				const result = await generateXssExploits(url, paramName, context, callbackUrl);
				addScanEntry('XSS Exploit', url, result.payloads.length);
				const doc = await vscode.workspace.openTextDocument({ content: generateXssExploitReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('xss-exploit', url, result);
			} catch (e) { vscode.window.showErrorMessage(`XSS exploit generation failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.xssExploitHeadless', async (arg?: XssExploitCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			if (!opts.parameter) { throw new Error('A "parameter" argument is required.'); }
			if (!opts.callbackUrl) { throw new Error('A "callbackUrl" argument is required.'); }
			const result = await generateXssExploits(
				opts.url,
				opts.parameter,
				opts.context ?? 'html',
				opts.callbackUrl,
			);
			addScanEntry('XSS Exploit', opts.url, result.payloads.length);
			if (opts.output) { writeResult(result, opts.output, generateXssExploitReport(result)); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`XSS exploit: ${result.payloads.length} payloads generated for ${result.context} context`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// LFI Exploiter (Exploitation)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.lfiExploit', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with LFI-vulnerable parameter', placeHolder: 'http://target.com/page?file=test' });
			if (!url) { return; }
			const paramName = await vscode.window.showInputBox({ prompt: 'Vulnerable parameter name', placeHolder: 'file' });
			if (!paramName) { return; }
			const location = await vscode.window.showQuickPick(['query', 'body'], { placeHolder: 'Parameter location' }) as 'query' | 'body' | undefined;
			if (!location) { return; }
			const traversal = await vscode.window.showInputBox({ prompt: 'Traversal prefix (leave empty for auto)', placeHolder: '../../../../../../', value: '../../../../../../' });
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Exploiting LFI...', cancellable: false },
					() => exploitLfi(url, { name: paramName, location }, traversal ?? '')
				);
				addScanEntry('LFI Exploit', url, result.readableFiles.length);
				const doc = await vscode.workspace.openTextDocument({ content: generateLfiExploitReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('lfi-exploit', url, result);
			} catch (e) { vscode.window.showErrorMessage(`LFI exploitation failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.lfiExploitHeadless', async (arg?: LfiExploitCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			if (!opts.parameter) { throw new Error('A "parameter" argument is required ({ name, location }).'); }
			const result = await exploitLfi(opts.url, opts.parameter, opts.traversalPrefix ?? '', {
				delayMs: opts.delayMs,
				timeoutMs: opts.timeoutMs,
				headers: opts.headers,
				cookie: opts.cookie,
			});
			addScanEntry('LFI Exploit', opts.url, result.readableFiles.length);
			if (opts.output) { writeResult(result, opts.output, generateLfiExploitReport(result)); }
			if (!opts.quiet) {
				vscode.window.showInformationMessage(
					`LFI exploit: ${result.readableFiles.length} files read, ${result.rceVectors.length} RCE vectors${result.logPoisoningPossible ? ', log poisoning possible' : ''}`
				);
			}
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// IDOR Scanner (Scylla 2.0)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.idor', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL with ID parameter', placeHolder: 'http://target.com/api/users/123' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for IDOR...', cancellable: false },
					() => scanIdor(url),
				);
				addFindings(result.findings, 'IDOR', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateIdorReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('idor', url, result);
			} catch (e) { vscode.window.showErrorMessage(`IDOR scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.idorHeadless', async (arg?: IdorScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanIdor(opts.url, opts.crawlResultFile, {
				strategies: opts.strategies,
				sensitivePatterns: opts.sensitivePatterns,
				delayMs: opts.delayMs,
				timeoutMs: opts.timeoutMs,
				headers: opts.headers,
				cookie: opts.cookie,
				profiles: opts.profiles,
				knownIds: opts.knownIds,
			});
			addFindings(result.findings, 'IDOR', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateIdorReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`IDOR scan: ${result.findings.length} findings`); }
			return result;
		}),
	);

	// -----------------------------------------------------------------------
	// Privilege Escalation Scanner (Scylla 2.0)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.privesc', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL or crawl result to test', placeHolder: 'http://target.com/' });
			if (!url) { return; }
			const highPriv = await vscode.window.showInputBox({ prompt: 'High-privilege profile name', placeHolder: 'admin' });
			if (!highPriv) { return; }
			const lowPriv = await vscode.window.showInputBox({ prompt: 'Low-privilege profile name', placeHolder: 'user' });
			if (!lowPriv) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for privilege escalation...', cancellable: false },
					() => scanPrivesc(url, undefined, highPriv, lowPriv),
				);
				addFindings(result.findings, 'PrivEsc', url);
				const doc = await vscode.workspace.openTextDocument({ content: generatePrivescReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('privesc', url, result);
			} catch (e) { vscode.window.showErrorMessage(`PrivEsc scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.privescHeadless', async (arg?: PrivescScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			if (!opts.highPrivProfile || !opts.lowPrivProfile) { throw new Error('"highPrivProfile" and "lowPrivProfile" are required.'); }
			const result = await scanPrivesc(opts.url, opts.crawlResultFile, opts.highPrivProfile, opts.lowPrivProfile, {
				delayMs: opts.delayMs,
				timeoutMs: opts.timeoutMs,
				headers: opts.headers,
			});
			addFindings(result.findings, 'PrivEsc', opts.url);
			if (opts.output) { writeResult(result, opts.output, generatePrivescReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`PrivEsc scan: ${result.findings.length} findings`); }
			return result;
		}),
	);

	// -----------------------------------------------------------------------
	// Mass Assignment Scanner (Scylla 2.0)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.massAssign', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target endpoint (POST/PUT)', placeHolder: 'http://target.com/api/profile' });
			if (!url) { return; }
			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Scanning for mass assignment...', cancellable: false },
					() => scanMassAssign(url, undefined),
				);
				addFindings(result.findings, 'Mass Assignment', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateMassAssignReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('mass-assign', url, result);
			} catch (e) { vscode.window.showErrorMessage(`Mass Assignment scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.massAssignHeadless', async (arg?: MassAssignScanCommandOptions) => {
			const opts = arg ?? {};
			if (!opts.url) { throw new Error('A "url" argument is required.'); }
			const result = await scanMassAssign(opts.url, opts.crawlResultFile, {
				categories: opts.categories,
				customFields: opts.customFields,
				profileName: opts.profileName,
				delayMs: opts.delayMs,
				timeoutMs: opts.timeoutMs,
				headers: opts.headers,
				cookie: opts.cookie,
			});
			addFindings(result.findings, 'Mass Assignment', opts.url);
			if (opts.output) { writeResult(result, opts.output, generateMassAssignReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`Mass Assignment scan: ${result.findings.length} findings`); }
			return result;
		}),
	);

	// -----------------------------------------------------------------------
	// Auto Scanner (all scanners)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.scanner.auto', async () => {
			const url = await vscode.window.showInputBox({ prompt: 'Target URL', placeHolder: 'http://target.com/page?id=1' });
			if (!url) { return; }
			try {
				const { url: resolvedUrl, params } = resolveParameters({ url });
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla: Running all scanners...', cancellable: false },
					() => autoScan(resolvedUrl, params)
				);
				addFindings(result.findings, 'AutoScan', url);
				const doc = await vscode.workspace.openTextDocument({ content: generateAutoScanReport(result), language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('auto', url, result);
			} catch (e) { vscode.window.showErrorMessage(`Auto scan failed: ${toErrorMessage(e)}`); }
		}),
		vscode.commands.registerCommand('scylla.scanner.autoHeadless', async (arg?: AutoScanCommandOptions) => {
			const opts = arg ?? {};
			const { url, params } = resolveParameters(opts);
			const result = await autoScan(url, params, { ...commonOpts(opts), scanners: opts.scanners });
			addFindings(result.findings, 'AutoScan', url);
			if (opts.output) { writeResult(result, opts.output, generateAutoScanReport(result)); }
			if (opts.createFindings) { await createFindingsFromResults(result.findings, opts.quiet ?? true); }
			if (!opts.quiet) { vscode.window.showInformationMessage(`Auto scan: ${result.totalFindings} findings across ${result.scannersRun.length} scanners`); }
			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Register Sidebar Tree Views
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('scylla.scanner.findings', findingsProvider),
		vscode.window.registerTreeDataProvider('scylla.scanner.scanHistory', historyProvider),
	);
}

function truncate(s: string, max: number): string {
	return s.length > max ? s.slice(0, max - 3) + '...' : s;
}

export function deactivate(): void { }
