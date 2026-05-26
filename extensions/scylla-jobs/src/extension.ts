/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { PipelineRunStatus } from './types';
import { PipelineRunner } from './pipelineRunner';
import { PRESETS, getPreset, materializePreset } from './pipelinePresets';
import { ScyllaDashboardPanel } from './dashboardPanel';

class ScyllaRunHistoryProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
	private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | null | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
		return element;
	}

	async getChildren(element?: vscode.TreeItem): Promise<vscode.TreeItem[]> {
		if (element) {
			// If it's a job node, parse the status and show its steps
			const statusPath = (element as any).statusPath;
			if (statusPath && fs.existsSync(statusPath)) {
				try {
					const content = fs.readFileSync(statusPath, 'utf8');
					const status = JSON.parse(content) as PipelineRunStatus;
					const children: vscode.TreeItem[] = [];
					
					const durationMs = status.finishedAt && status.startedAt 
						? new Date(status.finishedAt).getTime() - new Date(status.startedAt).getTime() 
						: 0;

					const summaryNode = new vscode.TreeItem(`Status: ${status.status.toUpperCase()} (${durationMs}ms)`);
					summaryNode.iconPath = new vscode.ThemeIcon(status.status === 'ok' ? 'check' : 'error');
					children.push(summaryNode);

					for (let i = 0; i < status.steps.length; i++) {
						const step = status.steps[i];
						const stepNode = new vscode.TreeItem(`Step ${i + 1}: ${step.cmd}`);
						stepNode.description = `${step.status.toUpperCase()} (${step.durationMs}ms)`;
						stepNode.iconPath = new vscode.ThemeIcon(step.status === 'ok' ? 'pass' : 'testing-failed-icon');
						if (step.error) {
							stepNode.tooltip = step.error;
						}
						children.push(stepNode);
					}
					return children;
				} catch {
					return [new vscode.TreeItem('Error reading status')];
				}
			}
			return [];
		}

		// Root elements: Show all output folders across workspaces
		const workspaceFolders = vscode.workspace.workspaceFolders;
		if (!workspaceFolders) return [new vscode.TreeItem('No workspace folders found')];

		const jobNodes: vscode.TreeItem[] = [];

		for (const folder of workspaceFolders) {
			const scyllaDir = path.join(folder.uri.fsPath, '.scylla');
			if (!fs.existsSync(scyllaDir)) continue;

			const entries = fs.readdirSync(scyllaDir, { withFileTypes: true });
			const outputDirs = entries
				.filter(e => e.isDirectory() && e.name.startsWith('pipeline-output'))
				.map(e => ({ name: e.name, path: path.join(scyllaDir, e.name) }))
				.sort((a, b) => {
					// Sort by birth time descending
					const statA = fs.statSync(a.path);
					const statB = fs.statSync(b.path);
					return statB.birthtimeMs - statA.birthtimeMs;
				});

			for (const dir of outputDirs) {
				const statusFile = path.join(dir.path, 'scylla-pipeline.status.json');
				if (fs.existsSync(statusFile)) {
					const logFile = path.join(dir.path, 'scylla-pipeline.log');
					const item = new vscode.TreeItem(`${folder.name} / ${dir.name}`, vscode.TreeItemCollapsibleState.Collapsed);
					(item as any).statusPath = statusFile;
					item.contextValue = 'scyllaJobRun';
					item.iconPath = new vscode.ThemeIcon('server-process');
					
					if (fs.existsSync(logFile)) {
						item.command = {
							command: 'vscode.open',
							title: 'Open Log',
							arguments: [vscode.Uri.file(logFile)]
						};
					}
					jobNodes.push(item);
				}
			}
		}

		if (jobNodes.length === 0) {
			return [new vscode.TreeItem('No pipeline history found')];
		}

		return jobNodes;
	}
}

export function activate(context: vscode.ExtensionContext): void {
	const runner = new PipelineRunner();
	const historyProvider = new ScyllaRunHistoryProvider();

	const pendingJobRuns = new Map<string, NodeJS.Timeout>();
	const activeJobRuns = new Set<string>();
	const queuedAutoRuns = new Set<string>();

	const executePipelineJob = async (
		jobFilePath: string,
		quiet: boolean,
		autoTriggered: boolean
	): Promise<PipelineRunStatus | undefined> => {
		const normalizedPath = path.resolve(jobFilePath);
		if (activeJobRuns.has(normalizedPath)) {
			if (autoTriggered) {
				queuedAutoRuns.add(normalizedPath);
				return undefined;
			}
			if (!quiet) {
				vscode.window.showWarningMessage(`A Scylla job is already running: ${normalizedPath}`);
			}
			return undefined;
		}

		activeJobRuns.add(normalizedPath);
		try {
			const status = await runner.runJobFile(normalizedPath, true);
			if (!quiet) {
				if (status.status === 'ok') {
					vscode.window.showInformationMessage(
						`Pipeline completed successfully: ${status.completedSteps}/${status.totalSteps} steps OK.`
					);
				} else {
					vscode.window.showWarningMessage(
						`Pipeline finished with errors: ${status.completedSteps}/${status.totalSteps} OK, ${status.failedSteps} failed.`
					);
				}
				
				const statusPath = path.join(status.outDir, 'scylla-pipeline.status.json');
				if (fs.existsSync(statusPath)) {
					const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(statusPath));
					await vscode.window.showTextDocument(doc, { preview: true });
				}
			}
			historyProvider.refresh();
			return status;
		} catch (error: unknown) {
			if (!quiet) {
				const msg = error instanceof Error ? error.message : String(error);
				vscode.window.showErrorMessage(`Pipeline execution failed: ${msg}`);
			}
			historyProvider.refresh();
			throw error;
		} finally {
			activeJobRuns.delete(normalizedPath);
			if (queuedAutoRuns.delete(normalizedPath)) {
				scheduleJobRun(normalizedPath);
			}
		}
	};

	const scheduleJobRun = (jobFilePath: string): void => {
		const normalizedPath = path.resolve(jobFilePath);
		const existing = pendingJobRuns.get(normalizedPath);
		if (existing) {
			clearTimeout(existing);
		}
		if (activeJobRuns.has(normalizedPath)) {
			queuedAutoRuns.add(normalizedPath);
			return;
		}

		const timeoutHandle = setTimeout(() => {
			pendingJobRuns.delete(normalizedPath);
			executePipelineJob(normalizedPath, true, true).catch(error => {
				console.error('Scylla pipeline auto-run failed:', error);
			});
		}, 350);
		pendingJobRuns.set(normalizedPath, timeoutHandle);
	};

	const autoRunExistingJobs = (): void => {
		const folders = vscode.workspace.workspaceFolders ?? [];
		for (const folder of folders) {
			const jobFilePath = path.join(folder.uri.fsPath, '.scylla_job.json');
			if (fs.existsSync(jobFilePath)) {
				scheduleJobRun(jobFilePath);
			}
		}
	};

	// -----------------------------------------------------------------------
	// Interactive: Run Pipeline
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.runJob', async () => {
			const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			if (!workspaceRoot) {
				vscode.window.showErrorMessage('A workspace folder is required.');
				return;
			}

			const defaultPath = path.join(workspaceRoot, '.scylla_job.json');
			let jobFilePath: string | undefined;

			if (fs.existsSync(defaultPath)) {
				jobFilePath = defaultPath;
			} else {
				const picked = await vscode.window.showOpenDialog({
					canSelectFiles: true,
					canSelectFolders: false,
					canSelectMany: false,
					filters: { 'Scylla Job Files': ['json'] },
					title: 'Select a .scylla_job.json file',
				});
				if (!picked || picked.length === 0) { return; }
				jobFilePath = picked[0].fsPath;
			}

			await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Running Scylla pipeline...', cancellable: false },
				async (progress) => {
					progress.report({ message: 'Validating job file...' });
					const validation = runner.validateJobFile(jobFilePath!);
					if (!validation.valid) {
						vscode.window.showErrorMessage(`Invalid job file: ${validation.errors.join('; ')}`);
						return;
					}

					progress.report({ message: 'Executing pipeline steps...' });
					await executePipelineJob(jobFilePath!, false, false);
				},
			);
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Run Pipeline
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.runJobHeadless', async (options?: { jobFile?: string; quiet?: boolean }) => {
			const jobFile = options?.jobFile ?? '.scylla_job.json';
			return runner.runJobFile(jobFile, options?.quiet);
		}),
	);

	// -----------------------------------------------------------------------
	// Interactive: Validate Job File
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.validateJob', async () => {
			const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			if (!workspaceRoot) {
				vscode.window.showErrorMessage('A workspace folder is required.');
				return;
			}

			const defaultPath = path.join(workspaceRoot, '.scylla_job.json');
			let jobFilePath: string;

			if (fs.existsSync(defaultPath)) {
				jobFilePath = defaultPath;
			} else {
				const picked = await vscode.window.showOpenDialog({
					canSelectFiles: true,
					canSelectFolders: false,
					canSelectMany: false,
					filters: { 'Scylla Job Files': ['json'] },
					title: 'Select a .scylla_job.json file to validate',
				});
				if (!picked || picked.length === 0) { return; }
				jobFilePath = picked[0].fsPath;
			}

			const result = runner.validateJobFile(jobFilePath);
			if (result.valid) {
				vscode.window.showInformationMessage('Job file is valid.');
			} else {
				vscode.window.showErrorMessage(`Validation errors:\n${result.errors.join('\n')}`);
			}
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: Validate Job File
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.validateJobHeadless', (options?: { jobFile?: string }) => {
			const jobFile = options?.jobFile ?? '.scylla_job.json';
			return runner.validateJobFile(jobFile);
		}),
	);

	// -----------------------------------------------------------------------
	// Interactive: List Capabilities
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.listCapabilities', async () => {
			const caps = runner.listCapabilities();
			const items = caps.map(c => ({
				label: c.command,
				description: `headless: ${c.headless} | timeout: ${c.defaultTimeoutMs}ms`,
			}));
			await vscode.window.showQuickPick(items, {
				placeHolder: `${caps.length} pipeline commands available`,
				canPickMany: false,
			});
		}),
	);

	// -----------------------------------------------------------------------
	// Headless: List Capabilities
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.listCapabilitiesHeadless', () => {
			return runner.listCapabilities();
		}),
	);

	// -----------------------------------------------------------------------
	// Interactive: Create from Preset
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.createPresetJob', async () => {
			const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
			if (!workspaceRoot) {
				vscode.window.showErrorMessage('A workspace folder is required.');
				return;
			}

			const items = PRESETS.map(p => ({
				label: p.name,
				description: p.description,
				id: p.id,
			}));

			const picked = await vscode.window.showQuickPick(items, {
				placeHolder: 'Select a pipeline preset',
			});
			if (!picked) { return; }

			const target = await vscode.window.showInputBox({
				prompt: 'Target URL or hostname',
				placeHolder: 'https://example.com',
				validateInput: (v) => v.trim().length === 0 ? 'Target is required' : null,
			});
			if (!target) { return; }

			const preset = getPreset(picked.id);
			if (!preset) { return; }

			const jobFile = materializePreset(preset, target);
			const jobPath = path.join(workspaceRoot, '.scylla_job.json');
			fs.writeFileSync(jobPath, JSON.stringify(jobFile, null, 2), 'utf8');

			const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(jobPath));
			await vscode.window.showTextDocument(doc);
			vscode.window.showInformationMessage(`Created ${picked.label} pipeline for ${target}`);
		}),
	);

	// -----------------------------------------------------------------------
	// Interactive: Pipeline Doctor
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.jobs.doctor', async () => {
			const caps = runner.listCapabilities();
			const headlessCount = caps.filter(c => c.headless).length;
			const totalCount = caps.length;

			const lines: string[] = [
				'# Scylla Pipeline Doctor',
				'',
				`Total registered commands: ${totalCount}`,
				`Headless-capable commands: ${headlessCount}`,
				'',
				'## Available Presets',
				'',
			];

			for (const preset of PRESETS) {
				lines.push(`- **${preset.name}** (${preset.id}): ${preset.description} [${preset.template.steps.length} steps]`);
			}

			lines.push('');
			lines.push('## Registered Commands');
			lines.push('');
			for (const cap of caps) {
				lines.push(`\`${cap.command}\` (timeout: ${cap.defaultTimeoutMs}ms)`);
			}

			const doc = await vscode.workspace.openTextDocument({
				content: lines.join('\n'),
				language: 'markdown',
			});
			await vscode.window.showTextDocument(doc, { preview: true });
		}),
	);

	// -----------------------------------------------------------------------
	// Sidebar Tree Views (placeholder providers)
	// -----------------------------------------------------------------------
	const emptyProvider: vscode.TreeDataProvider<string> = {
		getTreeItem: (el: string) => new vscode.TreeItem(el),
		getChildren: () => ['No pipelines running'],
	};
	const presetsProvider: vscode.TreeDataProvider<string> = {
		getTreeItem: (el: string) => {
			const item = new vscode.TreeItem(el);
			item.command = { command: 'scylla.jobs.createPresetJob', title: 'Create from Preset' };
			return item;
		},
		getChildren: () => PRESETS.map(p => `${p.name} — ${p.description}`),
	};
	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('scylla.jobs.pipelines', emptyProvider),
		vscode.window.registerTreeDataProvider('scylla.jobs.presets', presetsProvider),
		vscode.window.registerTreeDataProvider('scylla.jobs.runHistory', historyProvider),
	);

	// -----------------------------------------------------------------------
	// Welcome Dashboard
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.dashboard.open', () => {
			ScyllaDashboardPanel.createOrShow(context.extensionUri);
		}),
	);

	// -----------------------------------------------------------------------
	// File System Watchers for Auto-run
	// -----------------------------------------------------------------------
	const jobWatcher = vscode.workspace.createFileSystemWatcher('**/.scylla_job.json');
	context.subscriptions.push(jobWatcher);
	context.subscriptions.push(
		jobWatcher.onDidCreate(uri => scheduleJobRun(uri.fsPath)),
		jobWatcher.onDidChange(uri => scheduleJobRun(uri.fsPath))
	);
	context.subscriptions.push({
		dispose: () => {
			for (const timeoutHandle of pendingJobRuns.values()) {
				clearTimeout(timeoutHandle);
			}
			pendingJobRuns.clear();
		}
	});

	// Trigger execution for workspace jobs presently available
	autoRunExistingJobs();
}

export function deactivate(): void {}
