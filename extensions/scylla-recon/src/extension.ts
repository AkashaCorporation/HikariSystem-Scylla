/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { saveArtifact, toErrorMessage, writeResult } from './artifacts';
import { crawl, generateCrawlReport } from './crawler';
import { fuzzDirectories, generateDirFuzzReport } from './dirFuzzer';
import { generatePortScanReport, scanPorts } from './portScanner';
import { detectTechnologies, generateTechDetectReport } from './techDetector';
import { detectWaf, generateWafDetectReport } from './wafDetector';
import type {
	CrawlCommandOptions,
	CrawlResult,
	DirFuzzCommandOptions,
	DirFuzzResult,
	OpenPort,
	PortScanCommandOptions,
	PortScanResult,
	TechDetectCommandOptions,
	TechDetectResult,
	DetectedTechnology,
	WafDetectCommandOptions,
	WafDetectResult,
} from './types';

// ---------------------------------------------------------------------------
// Reactive Tree Data Provider
// ---------------------------------------------------------------------------

class ReconTreeProvider<T> implements vscode.TreeDataProvider<string> {
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

	clear(): void {
		this.items = [];
		this._onDidChange.fire(undefined);
	}

	getTreeItem(element: string): vscode.TreeItem {
		const item = new vscode.TreeItem(element);
		if (this.items.length === 0 || element === this.emptyMessage) {
			item.iconPath = new vscode.ThemeIcon('info');
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
	const targetsProvider = new ReconTreeProvider('No targets scanned yet');
	const portsProvider = new ReconTreeProvider('Run a port scan to see results');
	const endpointsProvider = new ReconTreeProvider('Run a crawl or dirfuzz to see results');
	const techProvider = new ReconTreeProvider('Run tech detect to see results');
	const wafProvider = new ReconTreeProvider('Run WAF detect to see results');

	// Track scanned targets
	const scannedTargets = new Set<string>();

	function addTarget(target: string): void {
		scannedTargets.add(target);
		targetsProvider.refresh([...scannedTargets]);
	}

	function updatePorts(result: PortScanResult): void {
		if (result.openPorts.length === 0) {
			portsProvider.refresh([`${result.target}: No open ports (${result.filteredCount} filtered)`]);
		} else {
			portsProvider.refresh(result.openPorts.map((p: OpenPort) =>
				`${p.port}/${p.protocol} — ${p.service}${p.banner ? ` [${p.banner.slice(0, 40)}]` : ''}`
			));
		}
	}

	function updateEndpointsFromCrawl(result: CrawlResult): void {
		const items: string[] = [];
		for (const ep of result.discovered) { items.push(`${ep.statusCode} ${ep.method} ${ep.url}`); }
		for (const form of result.forms) { items.push(`FORM ${form.action ?? '?'} (${form.method ?? 'GET'})`); }
		for (const param of result.parameters) { items.push(`PARAM ${param.name} [${param.location}]`); }
		endpointsProvider.refresh(items.length > 0 ? items : ['Crawl: No endpoints discovered']);
	}

	function updateEndpointsFromFuzz(result: DirFuzzResult): void {
		const items: string[] = [];
		for (const hit of result.discovered) { items.push(`${hit.statusCode} ${hit.path}`); }
		endpointsProvider.refresh(items.length > 0 ? items : ['DirFuzz: No paths discovered']);
	}

	function updateTech(result: TechDetectResult): void {
		if (result.technologies.length === 0) {
			techProvider.refresh(['No technologies detected']);
		} else {
			techProvider.refresh(result.technologies.map((t: DetectedTechnology) =>
				`${t.name}${t.version ? ' ' + t.version : ''} [${t.category}] (${t.confidence}%)`
			));
		}
	}

	// -----------------------------------------------------------------------
	// Port Scan
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.portscan', async () => {
			const target = await vscode.window.showInputBox({
				prompt: vscode.l10n.t('Target hostname or IP'),
				placeHolder: '10.10.10.1',
			});
			if (!target) { return; }

			const portsSpec = await vscode.window.showInputBox({
				prompt: vscode.l10n.t('Ports to scan'),
				placeHolder: 'top1000',
				value: 'top1000',
			});
			if (!portsSpec) { return; }

			const result = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Scylla: Scanning ports...'), cancellable: false },
				async (progress) => {
					return scanPorts(target, portsSpec, undefined, undefined, (p) => {
						progress.report({ message: `${p.scanned}/${p.total} (${p.found} open)` });
					});
				}
			);

			addTarget(target);
			updatePorts(result);

			const report = generatePortScanReport(result);
			const doc = await vscode.workspace.openTextDocument({ content: report, language: 'markdown' });
			await vscode.window.showTextDocument(doc, { preview: true });
			saveArtifact('portscan', target, result);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.portscanHeadless', async (arg?: PortScanCommandOptions) => {
			const options = arg ?? {};
			const target = options.target;
			if (!target) { throw new Error('scylla.recon.portscanHeadless requires a "target" argument.'); }

			const result = await scanPorts(
				target,
				options.ports ?? 'top1000',
				options.timeoutMs,
				options.concurrency,
			);

			addTarget(target);
			updatePorts(result);

			if (options.output) {
				writeResult(result, options.output, generatePortScanReport(result));
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					vscode.l10n.t('Scylla port scan complete: {0} open ports on {1}', result.openPorts.length, target)
				);
			}

			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Web Crawler
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.crawl', async () => {
			const url = await vscode.window.showInputBox({
				prompt: vscode.l10n.t('Seed URL to crawl'),
				placeHolder: 'http://target.com',
			});
			if (!url) { return; }

			const result = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Scylla: Crawling...'), cancellable: false },
				async (progress) => {
					return crawl(url, {}, (p) => {
						progress.report({ message: `${p.visited} pages, ${p.queued} queued` });
					});
				}
			);

			addTarget(url);
			updateEndpointsFromCrawl(result);

			const report = generateCrawlReport(result);
			const doc = await vscode.workspace.openTextDocument({ content: report, language: 'markdown' });
			await vscode.window.showTextDocument(doc, { preview: true });
			saveArtifact('crawl', url, result);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.crawlHeadless', async (arg?: CrawlCommandOptions) => {
			const options = arg ?? {};
			const url = options.url;
			if (!url) { throw new Error('scylla.recon.crawlHeadless requires a "url" argument.'); }

			const result = await crawl(url, {
				maxDepth: options.maxDepth,
				maxPages: options.maxPages,
				scope: options.scope,
				delayMs: options.delayMs,
				timeoutMs: options.timeoutMs,
				headers: options.headers,
				cookie: options.cookie,
			});

			addTarget(url);
			updateEndpointsFromCrawl(result);

			if (options.output) {
				writeResult(result, options.output, generateCrawlReport(result));
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					vscode.l10n.t('Scylla crawl complete: {0} pages, {1} forms, {2} parameters', result.pagesVisited, result.forms.length, result.parameters.length)
				);
			}

			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Directory Fuzzer
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.dirfuzz', async () => {
			const url = await vscode.window.showInputBox({
				prompt: vscode.l10n.t('Base URL to fuzz'),
				placeHolder: 'http://target.com',
			});
			if (!url) { return; }

			const result = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Scylla: Fuzzing directories...'), cancellable: false },
				async (progress) => {
					return fuzzDirectories(url, {}, (p) => {
						progress.report({ message: `${p.completed}/${p.total} (${p.found} found)` });
					});
				}
			);

			addTarget(url);
			updateEndpointsFromFuzz(result);

			const report = generateDirFuzzReport(result);
			const doc = await vscode.workspace.openTextDocument({ content: report, language: 'markdown' });
			await vscode.window.showTextDocument(doc, { preview: true });
			saveArtifact('dirfuzz', url, result);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.dirfuzzHeadless', async (arg?: DirFuzzCommandOptions) => {
			const options = arg ?? {};
			const url = options.url;
			if (!url) { throw new Error('scylla.recon.dirfuzzHeadless requires a "url" argument.'); }

			const result = await fuzzDirectories(url, {
				wordlist: options.wordlist,
				extensions: options.extensions,
				concurrency: options.concurrency,
				delayMs: options.delayMs,
				timeoutMs: options.timeoutMs,
				followRedirects: options.followRedirects,
				filterStatus: options.filterStatus,
				headers: options.headers,
				cookie: options.cookie,
			});

			addTarget(url);
			updateEndpointsFromFuzz(result);

			if (options.output) {
				writeResult(result, options.output, generateDirFuzzReport(result));
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					vscode.l10n.t('Scylla dirfuzz complete: {0} paths discovered', result.discovered.length)
				);
			}

			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Technology Detection
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.techdetect', async () => {
			const url = await vscode.window.showInputBox({
				prompt: vscode.l10n.t('URL to detect technologies'),
				placeHolder: 'http://target.com',
			});
			if (!url) { return; }

			try {
				const result = await detectTechnologies(url);
				addTarget(url);
				updateTech(result);

				const report = generateTechDetectReport(result);
				const doc = await vscode.workspace.openTextDocument({ content: report, language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('techdetect', url, result);
			} catch (error) {
				vscode.window.showErrorMessage(vscode.l10n.t('Tech detection failed: {0}', toErrorMessage(error)));
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.techdetectHeadless', async (arg?: TechDetectCommandOptions) => {
			const options = arg ?? {};
			const url = options.url;
			if (!url) { throw new Error('scylla.recon.techdetectHeadless requires a "url" argument.'); }

			const result = await detectTechnologies(url, options.timeoutMs);

			addTarget(url);
			updateTech(result);

			if (options.output) {
				writeResult(result, options.output, generateTechDetectReport(result));
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					vscode.l10n.t('Scylla tech detect: {0} technologies found', result.technologies.length)
				);
			}

			return result;
		})
	);

	// -----------------------------------------------------------------------
	// WAF Detection
	// -----------------------------------------------------------------------

	function updateWaf(result: WafDetectResult): void {
		if (!result.wafDetected) {
			wafProvider.refresh(['No WAF detected']);
		} else {
			const items: string[] = [
				`WAF: ${result.wafName} (${Math.round(result.confidence * 100)}% confidence)`,
				...result.evidence.map(e => `  ${e}`),
				'--- Bypass Suggestions ---',
				...result.bypassSuggestions.map(s => `  ${s}`),
			];
			wafProvider.refresh(items);
		}
	}

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.wafdetect', async () => {
			const url = await vscode.window.showInputBox({
				prompt: vscode.l10n.t('URL to detect WAF'),
				placeHolder: 'http://target.com',
			});
			if (!url) { return; }

			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Scylla: Detecting WAF...'), cancellable: false },
					async () => detectWaf(url)
				);

				addTarget(url);
				updateWaf(result);

				const report = generateWafDetectReport(result);
				const doc = await vscode.workspace.openTextDocument({ content: report, language: 'markdown' });
				await vscode.window.showTextDocument(doc, { preview: true });
				saveArtifact('wafdetect', url, result);
			} catch (error) {
				vscode.window.showErrorMessage(vscode.l10n.t('WAF detection failed: {0}', toErrorMessage(error)));
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.recon.wafdetectHeadless', async (arg?: WafDetectCommandOptions) => {
			const options = arg ?? {};
			const url = options.url;
			if (!url) { throw new Error('scylla.recon.wafdetectHeadless requires a "url" argument.'); }

			const result = await detectWaf(url, {
				headers: options.headers,
				cookie: options.cookie,
			});

			addTarget(url);
			updateWaf(result);

			if (options.output) {
				writeResult(result, options.output, generateWafDetectReport(result));
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					vscode.l10n.t('Scylla WAF detect: {0}', result.wafDetected ? `${result.wafName} detected` : 'No WAF detected')
				);
			}

			return result;
		})
	);

	// -----------------------------------------------------------------------
	// Register Sidebar Tree Views
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('scylla.recon.targets', targetsProvider),
		vscode.window.registerTreeDataProvider('scylla.recon.openPorts', portsProvider),
		vscode.window.registerTreeDataProvider('scylla.recon.endpoints', endpointsProvider),
		vscode.window.registerTreeDataProvider('scylla.recon.technologies', techProvider),
		vscode.window.registerTreeDataProvider('scylla.recon.waf', wafProvider),
	);
}

export function deactivate(): void { }
