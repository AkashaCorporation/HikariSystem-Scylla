/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { PipelineRunStatus } from './types';
import { PRESETS } from './pipelinePresets';

// ---------------------------------------------------------------------------
// Scylla Welcome Dashboard — Webview Panel
// ---------------------------------------------------------------------------

export class ScyllaDashboardPanel {

	public static readonly viewType = 'scylla.dashboard';
	private static currentPanel: ScyllaDashboardPanel | undefined;

	private readonly _panel: vscode.WebviewPanel;
	private readonly _extensionUri: vscode.Uri;
	private _disposables: vscode.Disposable[] = [];

	public static createOrShow(extensionUri: vscode.Uri): void {
		const column = vscode.window.activeTextEditor
			? vscode.window.activeTextEditor.viewColumn
			: undefined;

		if (ScyllaDashboardPanel.currentPanel) {
			ScyllaDashboardPanel.currentPanel._panel.reveal(column);
			ScyllaDashboardPanel.currentPanel._update();
			return;
		}

		const panel = vscode.window.createWebviewPanel(
			ScyllaDashboardPanel.viewType,
			'Scylla Dashboard',
			column || vscode.ViewColumn.One,
			{
				enableScripts: true,
				retainContextWhenHidden: true,
				localResourceRoots: [extensionUri],
			},
		);

		ScyllaDashboardPanel.currentPanel = new ScyllaDashboardPanel(panel, extensionUri);
	}

	private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
		this._panel = panel;
		this._extensionUri = extensionUri;

		this._update();

		this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

		this._panel.webview.onDidReceiveMessage(
			async (message: { command: string; preset?: string; target?: string }) => {
				switch (message.command) {
					case 'runPreset':
						if (message.preset && message.target) {
							await vscode.commands.executeCommand('scylla.jobs.runJobHeadless', {
								jobFile: '.scylla_job.json',
							});
						}
						break;
					case 'createPreset':
						await vscode.commands.executeCommand('scylla.jobs.createPresetJob');
						break;
					case 'openDocs':
						await vscode.commands.executeCommand('vscode.open',
							vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', 'docs', 'SCYLLA_AUTOMATION.md'))
						);
						break;
					case 'runPipeline':
						await vscode.commands.executeCommand('scylla.jobs.runJob');
						break;
					case 'openSettings':
						await vscode.commands.executeCommand('workbench.action.openSettings', 'scylla');
						break;
					case 'doctor':
						await vscode.commands.executeCommand('scylla.jobs.doctor');
						break;
					case 'refresh':
						this._update();
						break;
				}
			},
			null,
			this._disposables,
		);
	}

	public dispose(): void {
		ScyllaDashboardPanel.currentPanel = undefined;
		this._panel.dispose();
		while (this._disposables.length) {
			const x = this._disposables.pop();
			if (x) { x.dispose(); }
		}
	}

	private _update(): void {
		this._panel.title = 'Scylla Dashboard';
		this._panel.iconPath = new vscode.ThemeIcon('shield');
		this._panel.webview.html = this._getHtml();
	}

	// -----------------------------------------------------------------------
	// Data Collection
	// -----------------------------------------------------------------------

	private _getRecentRuns(): Array<{ name: string; status: string; target: string; date: string; steps: number; completed: number; failed: number }> {
		const runs: Array<{ name: string; status: string; target: string; date: string; steps: number; completed: number; failed: number }> = [];
		const folders = vscode.workspace.workspaceFolders ?? [];

		for (const folder of folders) {
			const scyllaDir = path.join(folder.uri.fsPath, '.scylla');
			if (!fs.existsSync(scyllaDir)) { continue; }

			try {
				const entries = fs.readdirSync(scyllaDir, { withFileTypes: true });
				const outputDirs = entries
					.filter(e => e.isDirectory() && e.name.startsWith('pipeline-output'))
					.map(e => path.join(scyllaDir, e.name))
					.sort((a, b) => {
						try {
							return fs.statSync(b).birthtimeMs - fs.statSync(a).birthtimeMs;
						} catch { return 0; }
					})
					.slice(0, 5);

				for (const dir of outputDirs) {
					const statusFile = path.join(dir, 'scylla-pipeline.status.json');
					if (!fs.existsSync(statusFile)) { continue; }

					try {
						const status = JSON.parse(fs.readFileSync(statusFile, 'utf8')) as PipelineRunStatus;
						runs.push({
							name: path.basename(dir),
							status: status.status,
							target: status.target,
							date: status.startedAt,
							steps: status.totalSteps,
							completed: status.completedSteps,
							failed: status.failedSteps,
						});
					} catch { /* skip corrupt files */ }
				}
			} catch { /* skip inaccessible dirs */ }
		}

		return runs.slice(0, 5);
	}

	// -----------------------------------------------------------------------
	// HTML Generation
	// -----------------------------------------------------------------------

	private _getHtml(): string {
		const recentRuns = this._getRecentRuns();
		const presets = PRESETS;
		const hasWorkspace = (vscode.workspace.workspaceFolders?.length ?? 0) > 0;

		const recentRunsHtml = recentRuns.length > 0
			? recentRuns.map(r => {
				const statusIcon = r.status === 'ok' ? '✅' : r.status === 'error' ? '❌' : '⏳';
				const statusClass = r.status === 'ok' ? 'status-ok' : r.status === 'error' ? 'status-error' : 'status-running';
				const dateStr = new Date(r.date).toLocaleString();
				return `
					<div class="run-card">
						<div class="run-header">
							<span class="run-status ${statusClass}">${statusIcon}</span>
							<span class="run-name">${this._escapeHtml(r.name)}</span>
						</div>
						<div class="run-meta">
							<span class="run-target">🎯 ${this._escapeHtml(r.target)}</span>
							<span class="run-date">📅 ${dateStr}</span>
						</div>
						<div class="run-progress">
							<div class="progress-bar">
								<div class="progress-fill ${statusClass}" style="width: ${r.steps > 0 ? (r.completed / r.steps * 100) : 0}%"></div>
							</div>
							<span class="progress-text">${r.completed}/${r.steps} steps${r.failed > 0 ? ` (${r.failed} failed)` : ''}</span>
						</div>
					</div>`;
			}).join('')
			: '<div class="empty-state"><span class="empty-icon">📭</span><p>No pipeline runs yet.<br>Create a <code>.scylla_job.json</code> to get started.</p></div>';

		const presetsHtml = presets.map(p => `
			<button class="preset-btn" onclick="sendMessage('createPreset')" title="${this._escapeHtml(p.description)}">
				<span class="preset-icon">⚡</span>
				<span class="preset-name">${this._escapeHtml(p.name)}</span>
				<span class="preset-steps">${p.template.steps.length} steps</span>
			</button>
		`).join('');

		return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scylla Dashboard</title>
<style>
	:root {
		--bg-primary: #0a0a0f;
		--bg-secondary: #12121a;
		--bg-card: #181825;
		--bg-card-hover: #1e1e2e;
		--border: #2a2a3c;
		--text-primary: #e4e4ef;
		--text-secondary: #8888a0;
		--text-muted: #5a5a72;
		--accent-primary: #7c3aed;
		--accent-secondary: #a855f7;
		--accent-glow: rgba(124, 58, 237, 0.3);
		--success: #22c55e;
		--error: #ef4444;
		--warning: #f59e0b;
		--info: #3b82f6;
		--radius: 12px;
		--radius-sm: 8px;
	}

	* { margin: 0; padding: 0; box-sizing: border-box; }

	body {
		background: var(--bg-primary);
		color: var(--text-primary);
		font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
		line-height: 1.6;
		overflow-x: hidden;
	}

	.dashboard {
		max-width: 960px;
		margin: 0 auto;
		padding: 32px 24px;
	}

	/* ---- Hero Section ---- */
	.hero {
		position: relative;
		padding: 48px 40px;
		border-radius: 20px;
		background: linear-gradient(135deg, #1a0a2e 0%, #16213e 50%, #0a1628 100%);
		border: 1px solid var(--border);
		overflow: hidden;
		margin-bottom: 32px;
	}

	.hero::before {
		content: '';
		position: absolute;
		top: -50%;
		left: -50%;
		width: 200%;
		height: 200%;
		background: radial-gradient(circle at 30% 30%, rgba(124, 58, 237, 0.08) 0%, transparent 50%),
					radial-gradient(circle at 70% 70%, rgba(168, 85, 247, 0.06) 0%, transparent 50%);
		animation: heroGlow 8s ease-in-out infinite alternate;
	}

	@keyframes heroGlow {
		0% { transform: translate(0, 0) rotate(0deg); }
		100% { transform: translate(-5%, -5%) rotate(3deg); }
	}

	.hero-content { position: relative; z-index: 1; }

	.hero-badge {
		display: inline-block;
		padding: 4px 14px;
		background: rgba(124, 58, 237, 0.2);
		border: 1px solid rgba(124, 58, 237, 0.4);
		border-radius: 20px;
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 1.5px;
		text-transform: uppercase;
		color: var(--accent-secondary);
		margin-bottom: 16px;
	}

	.hero h1 {
		font-size: 32px;
		font-weight: 700;
		letter-spacing: -0.5px;
		margin-bottom: 8px;
		background: linear-gradient(135deg, #e4e4ef 0%, #a855f7 100%);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.hero p {
		color: var(--text-secondary);
		font-size: 15px;
		max-width: 520px;
	}

	.hero-version {
		display: inline-block;
		margin-top: 12px;
		padding: 3px 10px;
		background: rgba(255,255,255,0.05);
		border-radius: 6px;
		font-size: 12px;
		color: var(--text-muted);
		font-family: 'Cascadia Code', 'Fira Code', monospace;
	}

	/* ---- Section ---- */
	.section {
		margin-bottom: 28px;
	}

	.section-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 14px;
	}

	.section-title {
		font-size: 16px;
		font-weight: 600;
		color: var(--text-primary);
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.section-title .icon { font-size: 18px; }

	/* ---- Quick Actions ---- */
	.actions-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 12px;
	}

	.action-btn {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 16px 18px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		color: var(--text-primary);
		cursor: pointer;
		font-size: 13px;
		font-weight: 500;
		transition: all 0.2s ease;
		font-family: inherit;
	}

	.action-btn:hover {
		background: var(--bg-card-hover);
		border-color: var(--accent-primary);
		box-shadow: 0 0 20px var(--accent-glow);
		transform: translateY(-1px);
	}

	.action-btn .btn-icon {
		width: 36px;
		height: 36px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		font-size: 18px;
		flex-shrink: 0;
	}

	.action-btn .btn-icon.play { background: rgba(34, 197, 94, 0.15); }
	.action-btn .btn-icon.preset { background: rgba(124, 58, 237, 0.15); }
	.action-btn .btn-icon.doc { background: rgba(59, 130, 246, 0.15); }
	.action-btn .btn-icon.health { background: rgba(245, 158, 11, 0.15); }

	.action-btn .btn-label {
		display: flex;
		flex-direction: column;
	}

	.action-btn .btn-sub {
		font-size: 11px;
		color: var(--text-muted);
		font-weight: 400;
	}

	/* ---- Pipeline Presets ---- */
	.presets-row {
		display: flex;
		flex-wrap: wrap;
		gap: 10px;
	}

	.preset-btn {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 10px 16px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		color: var(--text-primary);
		cursor: pointer;
		font-size: 12px;
		font-weight: 500;
		transition: all 0.2s ease;
		font-family: inherit;
	}

	.preset-btn:hover {
		background: var(--bg-card-hover);
		border-color: var(--accent-primary);
	}

	.preset-icon { font-size: 14px; }

	.preset-steps {
		color: var(--text-muted);
		font-size: 11px;
		margin-left: 4px;
	}

	/* ---- Recent Runs ---- */
	.run-card {
		padding: 16px 18px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		margin-bottom: 10px;
		transition: all 0.2s ease;
	}

	.run-card:hover {
		border-color: rgba(124, 58, 237, 0.3);
		background: var(--bg-card-hover);
	}

	.run-header {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 8px;
	}

	.run-status { font-size: 16px; }
	.run-name {
		font-weight: 600;
		font-size: 13px;
		font-family: 'Cascadia Code', 'Fira Code', monospace;
	}

	.run-meta {
		display: flex;
		gap: 16px;
		font-size: 12px;
		color: var(--text-secondary);
		margin-bottom: 10px;
	}

	.run-progress { display: flex; align-items: center; gap: 10px; }

	.progress-bar {
		flex: 1;
		height: 6px;
		background: rgba(255,255,255,0.06);
		border-radius: 3px;
		overflow: hidden;
	}

	.progress-fill {
		height: 100%;
		border-radius: 3px;
		transition: width 0.5s ease;
	}

	.progress-fill.status-ok { background: linear-gradient(90deg, var(--success), #4ade80); }
	.progress-fill.status-error { background: linear-gradient(90deg, var(--error), #f87171); }
	.progress-fill.status-running { background: linear-gradient(90deg, var(--warning), #fbbf24); }

	.progress-text {
		font-size: 11px;
		color: var(--text-muted);
		white-space: nowrap;
	}

	/* ---- Capabilities ---- */
	.caps-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 10px;
	}

	.cap-card {
		padding: 18px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		text-align: center;
	}

	.cap-number {
		font-size: 28px;
		font-weight: 700;
		background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.cap-label {
		font-size: 11px;
		color: var(--text-muted);
		text-transform: uppercase;
		letter-spacing: 1px;
		margin-top: 4px;
	}

	/* ---- Empty State ---- */
	.empty-state {
		text-align: center;
		padding: 40px 20px;
		color: var(--text-muted);
	}

	.empty-icon { font-size: 40px; display: block; margin-bottom: 12px; }

	.empty-state code {
		background: rgba(124, 58, 237, 0.15);
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 12px;
		color: var(--accent-secondary);
	}

	/* ---- Footer ---- */
	.footer {
		margin-top: 40px;
		padding-top: 20px;
		border-top: 1px solid var(--border);
		text-align: center;
		font-size: 11px;
		color: var(--text-muted);
	}

	.footer a {
		color: var(--accent-secondary);
		text-decoration: none;
	}

	.footer a:hover { text-decoration: underline; }

	/* ---- Refresh button ---- */
	.refresh-btn {
		background: none;
		border: 1px solid var(--border);
		color: var(--text-secondary);
		padding: 4px 12px;
		border-radius: 6px;
		font-size: 11px;
		cursor: pointer;
		font-family: inherit;
		transition: all 0.15s ease;
	}

	.refresh-btn:hover {
		border-color: var(--accent-primary);
		color: var(--text-primary);
	}
</style>
</head>
<body>
<div class="dashboard">

	<!-- Hero -->
	<div class="hero">
		<div class="hero-content">
			<div class="hero-badge">HikariSystem</div>
			<h1>Scylla 2.0 — Hydra</h1>
			<p>Pentesting IDE for access control and business logic vulnerabilities. Authenticated scanning, multi-role sessions, headless pipelines.</p>
			<span class="hero-version">v2.0.0-hydra</span>
		</div>
	</div>

	<!-- Quick Actions -->
	<div class="section">
		<div class="section-header">
			<span class="section-title"><span class="icon">⚡</span> Quick Actions</span>
		</div>
		<div class="actions-grid">
			<button class="action-btn" onclick="sendMessage('runPipeline')" ${!hasWorkspace ? 'disabled' : ''}>
				<span class="btn-icon play">▶️</span>
				<span class="btn-label">
					<span>Run Pipeline</span>
					<span class="btn-sub">Execute .scylla_job.json</span>
				</span>
			</button>
			<button class="action-btn" onclick="sendMessage('createPreset')">
				<span class="btn-icon preset">🧩</span>
				<span class="btn-label">
					<span>Create from Preset</span>
					<span class="btn-sub">Quick-start templates</span>
				</span>
			</button>
			<button class="action-btn" onclick="sendMessage('doctor')">
				<span class="btn-icon health">🩺</span>
				<span class="btn-label">
					<span>Pipeline Doctor</span>
					<span class="btn-sub">Check capabilities</span>
				</span>
			</button>
			<button class="action-btn" onclick="sendMessage('openDocs')">
				<span class="btn-icon doc">📖</span>
				<span class="btn-label">
					<span>Documentation</span>
					<span class="btn-sub">Automation guide</span>
				</span>
			</button>
		</div>
	</div>

	<!-- Pipeline Presets -->
	<div class="section">
		<div class="section-header">
			<span class="section-title"><span class="icon">🧩</span> Pipeline Presets</span>
		</div>
		<div class="presets-row">
			${presetsHtml}
		</div>
	</div>

	<!-- Capabilities -->
	<div class="section">
		<div class="section-header">
			<span class="section-title"><span class="icon">🛡️</span> Scanner Capabilities</span>
		</div>
		<div class="caps-grid">
			<div class="cap-card">
				<div class="cap-number">15</div>
				<div class="cap-label">Scanners</div>
			</div>
			<div class="cap-card">
				<div class="cap-number">3</div>
				<div class="cap-label">Exploiters</div>
			</div>
			<div class="cap-card">
				<div class="cap-number">5</div>
				<div class="cap-label">Recon Tools</div>
			</div>
		</div>
	</div>

	<!-- Recent Runs -->
	<div class="section">
		<div class="section-header">
			<span class="section-title"><span class="icon">📊</span> Recent Pipeline Runs</span>
			<button class="refresh-btn" onclick="sendMessage('refresh')">↻ Refresh</button>
		</div>
		${recentRunsHtml}
	</div>

	<!-- Footer -->
	<div class="footer">
		Scylla 2.0 "Hydra" — Built on Code-OSS · HikariSystem<br>
		<a href="#" onclick="sendMessage('openDocs')">Documentation</a> ·
		<a href="#" onclick="sendMessage('doctor')">Pipeline Doctor</a>
	</div>

</div>

<script>
	const vscode = acquireVsCodeApi();
	function sendMessage(command, data) {
		vscode.postMessage({ command, ...data });
	}
</script>
</body>
</html>`;
	}

	private _escapeHtml(str: string): string {
		return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
	}
}
