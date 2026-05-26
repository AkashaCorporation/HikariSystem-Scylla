/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { $ } from '../../../../base/browser/dom.js';
import { Dimension } from '../../../../base/browser/dom.js';
import { IEditorSerializer } from '../../../common/editor.js';
import { EditorPane } from '../../../browser/parts/editor/editorPane.js';
import { ITelemetryService } from '../../../../platform/telemetry/common/telemetry.js';
import { IWorkbenchThemeService } from '../../../services/themes/common/workbenchThemeService.js';
import { IStorageService } from '../../../../platform/storage/common/storage.js';
import { IWebviewService, IWebviewElement } from '../../webview/browser/webview.js';
import { IEditorGroup, IEditorGroupsService } from '../../../services/editor/common/editorGroupsService.js';
import { ICommandService } from '../../../../platform/commands/common/commands.js';
import { IConfigurationService } from '../../../../platform/configuration/common/configuration.js';
import { IInstantiationService } from '../../../../platform/instantiation/common/instantiation.js';
import { GettingStartedInput, GettingStartedEditorOptions } from './gettingStartedInput.js';
import { RawContextKey, IContextKeyService } from '../../../../platform/contextkey/common/contextkey.js';
import { mainWindow } from '../../../../base/browser/window.js';
import { CancellationToken } from '../../../../base/common/cancellation.js';
import { IEditorOpenContext } from '../../../common/editor.js';

import { IProductService } from '../../../../platform/product/common/productService.js';
import { IKeybindingService } from '../../../../platform/keybinding/common/keybinding.js';
import { IWalkthroughsService } from './gettingStartedService.js';
import { ILanguageService } from '../../../../editor/common/languages/language.js';
import { IFileService } from '../../../../platform/files/common/files.js';
import { IOpenerService } from '../../../../platform/opener/common/opener.js';
import { IExtensionService } from '../../../services/extensions/common/extensions.js';
import { INotificationService } from '../../../../platform/notification/common/notification.js';
import { IQuickInputService } from '../../../../platform/quickinput/common/quickInput.js';
import { IWorkspacesService } from '../../../../platform/workspaces/common/workspaces.js';
import { ILabelService } from '../../../../platform/label/common/label.js';
import { IHostService } from '../../../services/host/browser/host.js';
import { IWorkspaceContextService } from '../../../../platform/workspace/common/workspace.js';
import { IAccessibilityService } from '../../../../platform/accessibility/common/accessibility.js';
import { IMarkdownRendererService } from '../../../../platform/markdown/browser/markdownRenderer.js';

const configurationKey = 'workbench.startupEditor';

export const allWalkthroughsHiddenContext = new RawContextKey<boolean>('allWalkthroughsHidden', false);
export const inWelcomeContext = new RawContextKey<boolean>('inWelcome', false);

export interface IWelcomePageStartEntry {
	id: string;
	title: string;
	description: string;
	command: string;
	order: number;
	icon: { type: 'icon'; icon: any };
	when: any;
}

export class GettingStartedPage extends EditorPane {

	public static readonly ID = 'gettingStartedPage';

	private container!: HTMLElement;
	private webview: IWebviewElement | undefined;

	constructor(
		group: IEditorGroup,
		@ICommandService private readonly commandService: ICommandService,
		@IProductService private readonly productService: IProductService,
		@IKeybindingService private readonly keybindingService: IKeybindingService,
		@IWalkthroughsService private readonly gettingStartedService: IWalkthroughsService,
		@IConfigurationService private readonly configurationService: IConfigurationService,
		@ITelemetryService telemetryService: ITelemetryService,
		@ILanguageService private readonly languageService: ILanguageService,
		@IFileService private readonly fileService: IFileService,
		@IOpenerService private readonly openerService: IOpenerService,
		@IWorkbenchThemeService protected override readonly themeService: IWorkbenchThemeService,
		@IStorageService private storageService: IStorageService,
		@IExtensionService private readonly extensionService: IExtensionService,
		@IInstantiationService private readonly instantiationService: IInstantiationService,
		@INotificationService private readonly notificationService: INotificationService,
		@IEditorGroupsService private readonly groupsService: IEditorGroupsService,
		@IContextKeyService private readonly contextKeyService: IContextKeyService,
		@IQuickInputService private quickInputService: IQuickInputService,
		@IWorkspacesService private readonly workspacesService: IWorkspacesService,
		@ILabelService private readonly labelService: ILabelService,
		@IHostService private readonly hostService: IHostService,
		@IWebviewService private readonly webviewService: IWebviewService,
		@IWorkspaceContextService private readonly workspaceContextService: IWorkspaceContextService,
		@IAccessibilityService private readonly accessibilityService: IAccessibilityService,
		@IMarkdownRendererService private readonly markdownRendererService: IMarkdownRendererService,
	) {
		super(GettingStartedPage.ID, group, telemetryService, themeService, storageService);
		inWelcomeContext.bindTo(this.contextKeyService).set(true);

		// Evita erros de compilação por variáveis declaradas mas nunca usadas (noUnusedLocals)
		this._stubUnusedVariables();
	}

	private _stubUnusedVariables() {
		this.productService.toString();
		this.keybindingService.toString();
		this.gettingStartedService.toString();
		this.languageService.toString();
		this.fileService.toString();
		this.openerService.toString();
		this.storageService.toString();
		this.extensionService.toString();
		this.instantiationService.toString();
		this.notificationService.toString();
		this.groupsService.toString();
		this.quickInputService.toString();
		this.workspacesService.toString();
		this.labelService.toString();
		this.hostService.toString();
		this.workspaceContextService.toString();
		this.accessibilityService.toString();
		this.markdownRendererService.toString();
	}

	protected createEditor(parent: HTMLElement) {
		this.container = $('.gettingStartedContainer', {
			style: 'width: 100%; height: 100%; overflow: hidden; background: #060609; position: relative; border: none; outline: none; padding: 0; margin: 0;'
		});

		this.webview = this._register(this.webviewService.createWebviewElement({
			title: 'Scylla Welcome',
			options: {},
			contentOptions: {
				allowScripts: true
			},
			extension: undefined
		}));

		this.webview.mountTo(this.container, mainWindow);

		const startupEditorSetting = this.configurationService.getValue<string>(configurationKey);
		const autoOpenChecked = startupEditorSetting === 'welcomePage';

		this.webview.setHtml(this._getScyllaHtml(autoOpenChecked));

		this._register(this.webview.onMessage(async e => {
			const message = e.message;
			if (typeof message === 'object' && message !== null) {
				switch (message.command) {
					case 'closeDashboard':
						this.group.closeEditor(this.input);
						break;
					case 'runCommand':
						if (message.args) {
							await this.commandService.executeCommand(message.id, message.args);
						} else {
							await this.commandService.executeCommand(message.id);
						}
						break;
					case 'setAutoOpen':
						await this.configurationService.updateValue(configurationKey, message.value ? 'welcomePage' : 'none');
						break;
				}
			}
		}));

		parent.appendChild(this.container);
	}

	override async setInput(newInput: GettingStartedInput, options: GettingStartedEditorOptions | undefined, context: IEditorOpenContext, token: CancellationToken) {
		await super.setInput(newInput, options, context, token);
	}

	override focus() {
		super.focus();
		this.container.focus();
	}

	layout(size: Dimension) {
		// O Webview se ajusta automaticamente ao contêiner em que foi montado no Code-OSS,
		// portanto não há necessidade de chamar layouts internos explícitos.
	}

	escape() {
		// no-op para satisfazer referências em gettingStarted.contribution.ts
	}

	selectStepLoose(id: string) {
		// no-op para satisfazer referências em gettingStarted.contribution.ts
	}

	async makeCategoryVisibleWhenAvailable(categoryID: string, stepId?: string) {
		// no-op para satisfazer referências em gettingStartedAccessibleView.ts
	}

	private _getScyllaHtml(autoOpenChecked: boolean): string {
		return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scylla Operator Portal</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Fira+Code:wght@400;500;700&display=swap" rel="stylesheet">
<style>
	:root {
		--bg-primary: #060609;
		--bg-card: #0c0c12;
		--bg-input: #08080a;
		--border-crimson: #1a1a26;
		--border-crimson-focus: #e11d48;
		--text-primary: #f3f4f6;
		--text-secondary: #9ca3af;
		--text-muted: #6b7280;
		--accent-crimson: #e11d48;
		--accent-crimson-dark: #be123c;
		--accent-crimson-light: #fda4af;
		--success: #10b981;
		--error: #ef4444;
		--radius-lg: 8px;
		--radius-md: 6px;
		--radius-sm: 4px;
	}

	* {
		margin: 0;
		padding: 0;
		box-sizing: border-box;
		user-select: none;
		border: none;
		outline: none;
	}

	html, body {
		background: var(--bg-primary);
		color: var(--text-primary);
		font-family: 'Outfit', sans-serif;
		height: 100vh;
		width: 100%;
		overflow: hidden;
		display: flex;
		justify-content: center;
		align-items: center;
		position: relative;
		border: none;
		outline: none;
	}

	/* ---- App Wrapper ---- */
	.app-container {
		width: 100%;
		height: 100%;
		display: grid;
		grid-template-columns: 360px 1fr;
		gap: 16px;
		padding: 16px;
		z-index: 1;
		position: relative;
	}

	/* ---- Flat Professional Card Style ---- */
	.deck-card {
		background: var(--bg-card);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-lg);
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	/* =========================================================================
	   LEFT PANEL: TACTICAL LOGIN HUB
	   ========================================================================= */
	
	.login-panel {
		padding: 20px;
		justify-content: space-between;
	}

	.login-header {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.system-badge {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 3px 8px;
		background: rgba(225, 29, 72, 0.08);
		border: 1px solid rgba(225, 29, 72, 0.2);
		border-radius: 12px;
		width: max-content;
		font-size: 10px;
		font-weight: 600;
		letter-spacing: 0.5px;
		text-transform: uppercase;
		color: var(--accent-crimson-light);
	}

	.status-dot {
		width: 5px;
		height: 5px;
		background-color: var(--success);
		border-radius: 50%;
	}

	.title-brand {
		font-size: 22px;
		font-weight: 700;
		color: var(--text-primary);
		letter-spacing: -0.5px;
	}

	.subtitle-brand {
		font-size: 11px;
		color: var(--text-secondary);
	}

	/* ---- Credentials Form ---- */
	.auth-form {
		display: flex;
		flex-direction: column;
		gap: 12px;
		margin-top: 16px;
		margin-bottom: 16px;
	}

	.input-group {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.input-label {
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.8px;
		color: var(--text-secondary);
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.input-field {
		background: var(--bg-input);
		border: 1px solid var(--border-crimson);
		color: var(--text-primary);
		padding: 9px 12px;
		border-radius: var(--radius-md);
		font-size: 12px;
		font-family: inherit;
		width: 100%;
		transition: border-color 0.2s ease;
	}

	.input-field:focus {
		border-color: var(--border-crimson-focus);
	}

	select.input-field {
		cursor: pointer;
		appearance: none;
		background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23e11d48'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/%3E%3C/svg%3E");
		background-repeat: no-repeat;
		background-position: right 12px center;
		background-size: 14px;
		padding-right: 32px;
	}

	/* ---- Flat Solid Button ---- */
	.btn-auth {
		background: var(--accent-crimson);
		color: var(--text-primary);
		padding: 11px 20px;
		border-radius: var(--radius-md);
		font-family: inherit;
		font-size: 12px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.8px;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		transition: background-color 0.15s ease;
	}

	.btn-auth:hover {
		background: var(--accent-crimson-dark);
	}

	.bypass-login {
		margin-top: 8px;
		font-size: 11px;
		color: var(--text-muted);
		text-decoration: underline;
		cursor: pointer;
		text-align: center;
		transition: color 0.15s ease;
	}

	.bypass-login:hover {
		color: var(--accent-crimson-light);
	}

	/* ---- Cyber Boot Terminal ---- */
	.terminal-wrapper {
		flex: 1;
		background: rgba(0, 0, 0, 0.4);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-md);
		padding: 10px;
		display: flex;
		flex-direction: column;
		gap: 6px;
		min-height: 120px;
		max-height: 180px;
		overflow: hidden;
	}

	.terminal-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		font-size: 9px;
		font-weight: 700;
		text-transform: uppercase;
		color: var(--accent-crimson-light);
		font-family: 'Fira Code', monospace;
		border-bottom: 1px solid rgba(225, 29, 72, 0.15);
		padding-bottom: 4px;
	}

	.terminal-logs {
		font-family: 'Fira Code', monospace;
		font-size: 10px;
		line-height: 1.4;
		color: var(--text-secondary);
		overflow-y: auto;
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 4px;
		scrollbar-width: none;
	}

	.terminal-logs::-webkit-scrollbar {
		display: none;
	}

	.log-line.ok { color: var(--success); }
	.log-line.info { color: var(--accent-crimson-light); }
	.log-line.warn { color: var(--accent-crimson); }

	/* ---- Startup controller ---- */
	.startup-checkbox-container {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 12px;
	}

	.cyber-checkbox {
		appearance: none;
		width: 13px;
		height: 13px;
		border: 1px solid var(--border-crimson);
		border-radius: 3px;
		background: var(--bg-input);
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		outline: none;
		transition: background-color 0.15s ease;
	}

	.cyber-checkbox:checked {
		background: var(--accent-crimson);
		border-color: var(--accent-crimson);
	}

	.cyber-checkbox:checked::after {
		content: '';
		display: block;
		width: 7px;
		height: 4px;
		border-left: 2px solid white;
		border-bottom: 2px solid white;
		transform: rotate(-45deg) translate(1px, -1px);
	}

	.checkbox-label {
		font-size: 11px;
		color: var(--text-secondary);
		cursor: pointer;
	}

	/* =========================================================================
	   RIGHT PANEL: MULTI-TAB COMMAND DECK
	   ========================================================================= */

	.dashboard-panel {
		padding: 20px;
	}

	.deck-navigation {
		display: flex;
		align-items: center;
		gap: 4px;
		border-bottom: 1px solid var(--border-crimson);
		padding-bottom: 10px;
		margin-bottom: 16px;
	}

	.nav-tab {
		background: none;
		color: var(--text-secondary);
		padding: 6px 12px;
		border-radius: var(--radius-md);
		cursor: pointer;
		font-family: inherit;
		font-size: 12px;
		font-weight: 500;
		transition: all 0.15s ease;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.nav-tab:hover {
		color: var(--text-primary);
		background: rgba(225, 29, 72, 0.04);
	}

	.nav-tab.active {
		color: var(--text-primary);
		background: rgba(225, 29, 72, 0.08);
		border: 1px solid var(--border-crimson);
	}

	.icon {
		color: var(--text-secondary);
		transition: color 0.15s ease;
	}

	.nav-tab.active .icon {
		color: var(--accent-crimson);
	}

	/* ---- Tabs Content ---- */
	.tab-content {
		display: none;
		flex: 1;
		flex-direction: column;
		height: calc(100% - 46px);
		overflow: hidden;
	}

	.tab-content.active {
		display: flex;
	}

	/* ---- TAB 1: OVERVIEW PANELS ---- */
	.overview-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 12px;
		margin-bottom: 20px;
	}

	.stat-card {
		background: rgba(0, 0, 0, 0.15);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-lg);
		padding: 14px;
		text-align: center;
		position: relative;
	}

	.stat-card::before {
		content: '';
		position: absolute;
		top: 0;
		left: 0;
		width: 100%;
		height: 2px;
		background: var(--accent-crimson);
	}

	.stat-value {
		font-size: 28px;
		font-weight: 700;
		font-family: 'Fira Code', monospace;
		color: var(--accent-crimson-light);
		margin-bottom: 2px;
	}

	.stat-label {
		font-size: 10px;
		font-weight: 600;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.actions-header {
		font-size: 12px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.8px;
		color: var(--text-primary);
		margin-bottom: 10px;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.actions-header .icon {
		color: var(--accent-crimson);
	}

	.quick-actions-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 10px;
	}

	.btn-quick {
		background: var(--bg-input);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-md);
		padding: 12px;
		color: var(--text-primary);
		font-family: inherit;
		cursor: pointer;
		display: flex;
		align-items: center;
		gap: 12px;
		transition: all 0.15s ease;
		text-align: left;
	}

	.btn-quick:hover {
		border-color: var(--accent-crimson);
		background: rgba(225, 29, 72, 0.03);
	}

	.btn-quick-icon {
		width: 32px;
		height: 32px;
		background: rgba(225, 29, 72, 0.05);
		border: 1px solid rgba(225, 29, 72, 0.15);
		border-radius: var(--radius-sm);
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--accent-crimson);
		flex-shrink: 0;
	}

	.btn-quick-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.btn-quick-title {
		font-size: 12px;
		font-weight: 600;
	}

	.btn-quick-desc {
		font-size: 10px;
		color: var(--text-secondary);
	}

	/* ---- TAB 2: PIPELINE PRESETS ---- */
	.presets-container {
		display: flex;
		flex-direction: column;
		gap: 10px;
		overflow-y: auto;
		flex: 1;
		padding-right: 6px;
	}

	.preset-card {
		background: rgba(0, 0, 0, 0.15);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-md);
		padding: 14px;
		display: grid;
		grid-template-columns: 1fr 120px;
		gap: 16px;
		align-items: center;
		transition: all 0.15s ease;
	}

	.preset-card:hover {
		border-color: var(--accent-crimson);
	}

	.preset-info {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.preset-title-row {
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.preset-title {
		font-size: 14px;
		font-weight: 600;
		color: var(--text-primary);
	}

	.preset-badge {
		font-size: 9px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--accent-crimson-light);
		background: rgba(225, 29, 72, 0.08);
		border: 1px solid rgba(225, 29, 72, 0.15);
		padding: 1px 6px;
		border-radius: 10px;
	}

	.preset-desc {
		font-size: 11px;
		color: var(--text-secondary);
		line-height: 1.4;
	}

	.btn-preset-run {
		background: rgba(225, 29, 72, 0.05);
		border: 1px solid var(--border-crimson);
		color: var(--text-primary);
		padding: 6px 12px;
		border-radius: var(--radius-sm);
		font-family: inherit;
		font-size: 11px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s ease;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 4px;
	}

	.btn-preset-run:hover {
		background: var(--accent-crimson);
		border-color: var(--accent-crimson);
	}

	/* ---- TAB 3: WORDLISTS PANEL ---- */
	.wordlists-list {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 10px;
		overflow-y: auto;
		flex: 1;
		padding-right: 6px;
	}

	.wordlist-card {
		background: rgba(0, 0, 0, 0.15);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-md);
		padding: 12px;
		display: flex;
		flex-direction: column;
		justify-content: space-between;
		gap: 6px;
		transition: all 0.15s ease;
	}

	.wordlist-card:hover {
		border-color: var(--accent-crimson);
	}

	.wordlist-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}

	.wordlist-name {
		font-size: 12px;
		font-weight: 600;
		color: var(--text-primary);
	}

	.wordlist-tag {
		font-size: 8px;
		font-weight: 700;
		text-transform: uppercase;
		padding: 1px 5px;
		border-radius: 3px;
	}

	.wordlist-tag.directories { background: rgba(225, 29, 72, 0.08); border: 1px solid rgba(225, 29, 72, 0.15); color: var(--accent-crimson-light); }
	.wordlist-tag.parameters { background: rgba(217, 70, 239, 0.08); border: 1px solid rgba(217, 70, 239, 0.15); color: #d946ef; }
	.wordlist-tag.payloads { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.15); color: var(--error); }
	.wordlist-tag.credentials { background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.15); color: var(--success); }
	.wordlist-tag.subdomains { background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.15); color: #06b6d4; }
	.wordlist-tag.general { background: rgba(107, 114, 128, 0.08); border: 1px solid rgba(107, 114, 128, 0.15); color: var(--text-secondary); }

	.wordlist-description {
		font-size: 11px;
		color: var(--text-secondary);
		line-height: 1.3;
	}

	.wordlist-foot {
		display: flex;
		align-items: center;
		justify-content: space-between;
		font-size: 9px;
		color: var(--text-muted);
		border-top: 1px solid rgba(255, 255, 255, 0.03);
		padding-top: 4px;
	}

	.wordlist-lines {
		font-family: 'Fira Code', monospace;
	}

	/* ---- TAB 4: DOCUMENTATION ---- */
	.docs-list {
		display: flex;
		flex-direction: column;
		gap: 10px;
		overflow-y: auto;
		flex: 1;
		padding-right: 6px;
	}

	.doc-item {
		background: rgba(0, 0, 0, 0.15);
		border: 1px solid var(--border-crimson);
		border-radius: var(--radius-md);
		padding: 14px;
		display: flex;
		align-items: center;
		justify-content: space-between;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.doc-item:hover {
		border-color: var(--accent-crimson);
		background: rgba(225, 29, 72, 0.02);
	}

	.doc-left {
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.doc-icon {
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--accent-crimson);
	}

	.doc-meta {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.doc-title {
		font-size: 12px;
		font-weight: 600;
	}

	.doc-desc {
		font-size: 11px;
		color: var(--text-secondary);
	}

	.doc-chevron {
		color: var(--text-muted);
		display: flex;
		align-items: center;
		justify-content: center;
	}

	/* =========================================================================
	   AUTHENTICATION INTERACTIVE MODAL & LOADING OVERLAYS
	   ========================================================================= */

	.auth-overlay {
		position: absolute;
		top: 0;
		left: 0;
		width: 100%;
		height: 100%;
		background: var(--bg-primary);
		z-index: 10;
		display: flex;
		flex-direction: column;
		justify-content: center;
		align-items: center;
		gap: 20px;
		opacity: 0;
		pointer-events: none;
		transition: opacity 0.3s ease;
	}

	.auth-overlay.active {
		opacity: 1;
		pointer-events: all;
	}

	.decrypt-logo {
		width: 60px;
		height: 60px;
		background: rgba(225, 29, 72, 0.05);
		border: 1px solid var(--accent-crimson);
		border-radius: 50%;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--accent-crimson);
		animation: rotateLogo 4s linear infinite;
	}

	@keyframes rotateLogo {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}

	.decrypt-status {
		font-size: 15px;
		font-weight: 600;
		letter-spacing: 0.8px;
		text-transform: uppercase;
		color: var(--text-primary);
		text-align: center;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.decrypt-substatus {
		font-size: 11px;
		color: var(--accent-crimson-light);
		font-family: 'Fira Code', monospace;
	}

	.progress-bar-wrapper {
		width: 240px;
		height: 4px;
		background: rgba(255, 255, 255, 0.04);
		border-radius: 2px;
		overflow: hidden;
	}

	.progress-bar-fill {
		width: 0%;
		height: 100%;
		background: var(--accent-crimson);
		border-radius: 2px;
		transition: width 0.1s linear;
	}

	.bypass-login {
		margin-top: 10px;
		font-size: 11px;
		color: var(--text-muted);
		text-decoration: underline;
		cursor: pointer;
		transition: color 0.15s ease;
	}

	.bypass-login:hover {
		color: var(--accent-crimson-light);
	}

	/* Scrollbars styling */
	::-webkit-scrollbar {
		width: 4px;
	}

	::-webkit-scrollbar-track {
		background: transparent;
	}

	::-webkit-scrollbar-thumb {
		background: rgba(225, 29, 72, 0.15);
		border-radius: 2px;
	}

	::-webkit-scrollbar-thumb:hover {
		background: rgba(225, 29, 72, 0.3);
	}
</style>
</head>
<body>

	<!-- Loading/Auth Overlay -->
	<div class="auth-overlay" id="authOverlay">
		<div class="decrypt-logo">
			<svg viewBox="0 0 24 24" width="28" height="28" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
		</div>
		<div class="decrypt-status">
			<span id="decryptTitle">Initializing Scylla Core</span>
			<span class="decrypt-substatus" id="decryptSub">Decrypting Operator Dashboard...</span>
		</div>
		<div class="progress-bar-wrapper">
			<div class="progress-bar-fill" id="progressBar"></div>
		</div>
	</div>

	<!-- App Wrapper -->
	<div class="app-container">

		<!-- LEFT PANEL: TACTICAL CONTROL -->
		<div class="deck-card login-panel">
			<div class="login-header">
				<div class="system-badge">
					<div class="status-dot"></div>
					<span>Scylla Core · Active</span>
				</div>
				<h1 class="title-brand">Scylla 2.0</h1>
				<p class="subtitle-brand">Pentesting & Automation Core Deck</p>
			</div>

			<!-- Mock Authentication Form -->
			<div class="auth-form">
				<div class="input-group">
					<label class="input-label">Operator Handle</label>
					<input type="text" class="input-field" id="operatorName" value="OP_SCYLLA_ADMIN">
				</div>

				<div class="input-group">
					<label class="input-label">Session Profile</label>
					<select class="input-field" id="roleProfile">
						<option value="redteam">Red Team Lead (All tools)</option>
						<option value="auditor">Vulnerability Auditor (Scanners)</option>
						<option value="recon">Recon Specialist (Crawler + Fuzzer)</option>
						<option value="guest">Passive Guest (No modifications)</option>
					</select>
				</div>

				<div class="input-group">
					<label class="input-label">Decryption Passkey</label>
					<input type="password" class="input-field" value="••••••••••••••••">
				</div>

				<button class="btn-auth" onclick="startAuthentication()">
					<span>Initialize Deck</span>
				</button>
				<span class="bypass-login" onclick="skipToIDE()">Bypass Directly to Workspace</span>
			</div>

			<!-- Cybernetic Terminal Logs -->
			<div class="terminal-wrapper">
				<div class="terminal-header">
					<span>Console Output</span>
					<span style="color: var(--accent-crimson-light);">v2.0.0-hydra</span>
				</div>
				<div class="terminal-logs" id="terminalLogs">
					<!-- Dynamically injected logs -->
				</div>
			</div>

			<!-- Startup controller -->
			<div class="startup-checkbox-container">
				<input type="checkbox" class="cyber-checkbox" id="autoOpenCheck" ${autoOpenChecked ? 'checked' : ''} onchange="toggleAutoOpen(this.checked)">
				<label class="checkbox-label" for="autoOpenCheck">Auto-open console on boot</label>
			</div>
		</div>

		<!-- RIGHT PANEL: COMMAND DECK -->
		<div class="deck-card dashboard-panel">
			
			<!-- Nav Tabs -->
			<div class="deck-navigation">
				<button class="nav-tab active" onclick="switchTab('tab-overview', this)">
					<svg class="icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
					Command Deck
				</button>
				<button class="nav-tab" onclick="switchTab('tab-presets', this)">
					<svg class="icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
					Pipeline Presets
				</button>
				<button class="nav-tab" onclick="switchTab('tab-wordlists', this)">
					<svg class="icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg>
					Tactical Intel
				</button>
				<button class="nav-tab" onclick="switchTab('tab-docs', this)">
					<svg class="icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg>
					Documentation
				</button>
			</div>

			<!-- Tab 1: Overview -->
			<div class="tab-content active" id="tab-overview">
				<div class="overview-grid">
					<div class="stat-card">
						<div class="stat-value">15</div>
						<div class="stat-label">Scanners</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">3</div>
						<div class="stat-label">Exploiters</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">5</div>
						<div class="stat-label">Recon Tools</div>
					</div>
				</div>

				<h2 class="actions-header">
					<svg class="icon" viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
					Quick Deploy Operations
				</h2>
				<div class="quick-actions-grid">
					<button class="btn-quick" onclick="runCommand('scylla.jobs.runJob')">
						<div class="btn-quick-icon">
							<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
						</div>
						<div class="btn-quick-text">
							<span class="btn-quick-title">Run Pipeline</span>
							<span class="btn-quick-desc">Execute job configuration</span>
						</div>
					</button>

					<button class="btn-quick" onclick="runCommand('scylla.jobs.createPresetJob')">
						<div class="btn-quick-icon">
							<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
						</div>
						<div class="btn-quick-text">
							<span class="btn-quick-title">Create from Preset</span>
							<span class="btn-quick-desc">Load preset automation</span>
						</div>
					</button>

					<button class="btn-quick" onclick="runCommand('scylla.jobs.doctor')">
						<div class="btn-quick-icon">
							<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
						</div>
						<div class="btn-quick-text">
							<span class="btn-quick-title">Pipeline Doctor</span>
							<span class="btn-quick-desc">Verify local N-API capabilities</span>
						</div>
					</button>

					<button class="btn-quick" onclick="runCommand('workbench.action.openSettings', 'scylla')">
						<div class="btn-quick-icon">
							<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
						</div>
						<div class="btn-quick-text">
							<span class="btn-quick-title">Core Config</span>
							<span class="btn-quick-desc">Adjust Scylla configurations</span>
						</div>
					</button>
				</div>
			</div>

			<!-- Tab 2: Presets -->
			<div class="tab-content" id="tab-presets">
				<div class="presets-container">
					<div class="preset-card">
						<div class="preset-info">
							<div class="preset-title-row">
								<span class="preset-title">Web Reconnaissance</span>
								<span class="preset-badge">Active Recon</span>
							</div>
							<p class="preset-desc">Executes full target surface discovery: port scan, technology stack detect, crawler and directory fuzzing steps.</p>
						</div>
						<button class="btn-preset-run" onclick="runCommand('scylla.jobs.createPresetJob')">
							<svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
							Deploy Preset
						</button>
					</div>

					<div class="preset-card">
						<div class="preset-info">
							<div class="preset-title-row">
								<span class="preset-title">Vulnerability Scanner</span>
								<span class="preset-badge">Auto Scan</span>
							</div>
							<p class="preset-desc">Runs the integrated automated scanning suite covering OWASP Top 10 vulnerabilities (SQLi, XSS, LFI, Secrets) and creates findings in the database.</p>
						</div>
						<button class="btn-preset-run" onclick="runCommand('scylla.jobs.createPresetJob')">
							<svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
							Deploy Preset
						</button>
					</div>

					<div class="preset-card">
						<div class="preset-info">
							<div class="preset-title-row">
								<span class="preset-title">HTB Easy Assessment</span>
								<span class="preset-badge">Exploit Pipeline</span>
							</div>
							<p class="preset-desc">Pre-configured testing flow for HackTheBox/easy targets: scanning, directory discovery, common vulnerability exploits and automatic report generation.</p>
						</div>
						<button class="btn-preset-run" onclick="runCommand('scylla.jobs.createPresetJob')">
							<svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
							Deploy Preset
						</button>
					</div>

					<div class="preset-card">
						<div class="preset-info">
							<div class="preset-title-row">
								<span class="preset-title">Exposed Secrets Hunt</span>
								<span class="preset-badge">Passive Analysis</span>
							</div>
							<p class="preset-desc">Scans crawled files and endpoints for api keys, database passwords, configuration links, tokens and private credentials.</p>
						</div>
						<button class="btn-preset-run" onclick="runCommand('scylla.jobs.createPresetJob')">
							<svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
							Deploy Preset
						</button>
					</div>
				</div>
			</div>

			<!-- Tab 3: Wordlists -->
			<div class="tab-content" id="tab-wordlists">
				<div class="wordlists-list">
					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">Common Directories</span>
							<span class="wordlist-tag directories">Directories</span>
						</div>
						<p class="wordlist-description">Common web directory names, admin panels, config targets, backups, files.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">4,612 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">API Endpoints</span>
							<span class="wordlist-tag directories">Directories</span>
						</div>
						<p class="wordlist-description">Common patterns and routes for REST APIs, GraphQL, JSON endpoints.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">2,871 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">Common Parameters</span>
							<span class="wordlist-tag parameters">Parameters</span>
						</div>
						<p class="wordlist-description">Most frequent HTTP query and body parameter names for fuzzer injection.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">1,540 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">SQL Injection Payloads</span>
							<span class="wordlist-tag payloads">Payloads</span>
						</div>
						<p class="wordlist-description">Test strings, polyglots and bypasses for active SQL injection vulnerability detection.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">125 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">XSS Payloads</span>
							<span class="wordlist-tag payloads">Payloads</span>
						</div>
						<p class="wordlist-description">Cross-site scripting vectors, browser filters bypasses, execution payloads.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">280 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">Default Credentials</span>
							<span class="wordlist-tag credentials">Credentials</span>
						</div>
						<p class="wordlist-description">Standard database, web panel, service and device credentials (username:password pairs).</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">940 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">Common Subdomains</span>
							<span class="wordlist-tag subdomains">Subdomains</span>
						</div>
						<p class="wordlist-description">Popular subdomain prefixes for active DNS enumeration and host discovery.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">12,410 entries</span>
						</div>
					</div>

					<div class="wordlist-card">
						<div class="wordlist-head">
							<span class="wordlist-name">LFI Traversals</span>
							<span class="wordlist-tag payloads">Payloads</span>
						</div>
						<p class="wordlist-description">Local File Inclusion path patterns, encoding bypasses, file paths lists.</p>
						<div class="wordlist-foot">
							<span>Status: Ready</span>
							<span class="wordlist-lines">150 entries</span>
						</div>
					</div>
				</div>
			</div>

			<!-- Tab 4: Docs -->
			<div class="tab-content" id="tab-docs">
				<div class="docs-list">
					<div class="doc-item" onclick="runCommand('scylla.jobs.runJob')">
						<div class="doc-left">
							<div class="doc-icon">
								<svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg>
							</div>
							<div class="doc-meta">
								<span class="doc-title">Automation & Pipeline Guide</span>
								<span class="doc-desc">Learn how to customize your pentest workflows using job JSON files.</span>
							</div>
						</div>
						<div class="doc-chevron">
							<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
						</div>
					</div>

					<div class="doc-item" onclick="runCommand('scylla.jobs.doctor')">
						<div class="doc-left">
							<div class="doc-icon">
								<svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
							</div>
							<div class="doc-meta">
								<span class="doc-title">Capabilities Diagnostics</span>
								<span class="doc-desc">Run self-tests to verify scanner nodes availability.</span>
							</div>
						</div>
						<div class="doc-chevron">
							<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
						</div>
					</div>
				</div>
			</div>

		</div>
	</div>

	<script>
		// Native postMessage abstraction
		const vscode = typeof acquireVsCodeApi !== 'undefined' ? acquireVsCodeApi() : {
			postMessage: (msg) => console.log("PostMessage bypass:", msg)
		};

		// Tabs logic
		function switchTab(tabId, el) {
			document.querySelectorAll('.tab-content').forEach(tab => {
				tab.classList.remove('active');
			});
			document.querySelectorAll('.nav-tab').forEach(btn => {
				btn.classList.remove('active');
			});
			document.getElementById(tabId).classList.add('active');
			el.classList.add('active');

			writeTerminalLog(\`[SYSTEM] Navigated to \${el.innerText.trim()} view.\`, 'info');
		}

		// Terminal Log Simulation
		const logs = [
			{ text: "[INIT] Starting Scylla Cybernetic Core Engine...", type: "info", delay: 200 },
			{ text: "[BOOT] Kernel: v2.0.0-hydra on Electron TS", type: "info", delay: 400 },
			{ text: "[OK] 15 vulnerability scanner scripts registered.", type: "ok", delay: 700 },
			{ text: "[OK] 3 exploitation payload modules active.", type: "ok", delay: 900 },
			{ text: "[OK] 11 embedded wordlists linked successfully.", type: "ok", delay: 1100 },
			{ text: "[OK] Local database cryptographic key loaded.", type: "ok", delay: 1300 },
			{ text: "[INFO] Cryptographic channel ready for Operator OP_SCYLLA_ADMIN.", type: "info", delay: 1550 },
			{ text: "[STATUS] Awaiting terminal clearance authorization...", type: "warn", delay: 1800 }
		];

		const terminal = document.getElementById('terminalLogs');

		function writeTerminalLog(text, type = 'info') {
			const line = document.createElement('div');
			line.className = 'log-line ' + type;
			line.innerText = text;
			terminal.appendChild(line);
			terminal.scrollTop = terminal.scrollHeight;
		}

		// Initial boot logs sequence
		logs.forEach(log => {
			setTimeout(() => {
				writeTerminalLog(log.text, log.type);
			}, log.delay);
		});

		// Interactive Login Auth Simulation
		function startAuthentication() {
			const name = document.getElementById('operatorName').value;
			const profileSelect = document.getElementById('roleProfile');
			const profileName = profileSelect.options[profileSelect.selectedIndex].text;

			writeTerminalLog(\`[AUTH] Initiating handshake challenge for Operator: \${name}...\`, 'info');
			
			const authOverlay = document.getElementById('authOverlay');
			const progressBar = document.getElementById('progressBar');
			const decryptSub = document.getElementById('decryptSub');

			authOverlay.classList.add('active');

			let width = 0;
			const interval = setInterval(() => {
				if (width >= 100) {
					clearInterval(interval);
					progressBar.style.width = '100%';
					document.getElementById('decryptTitle').innerText = 'Access Authorized';
					decryptSub.innerText = 'Initializing Tactical Dashboard Node...';
					
					setTimeout(() => {
						// Close the welcome editor natively!
						vscode.postMessage({ command: 'closeDashboard' });
					}, 800);
				} else {
					width += 4;
					progressBar.style.width = width + '%';
					if (width === 24) {
						decryptSub.innerText = 'Validating ECDSA digital signature...';
					} else if (width === 48) {
						decryptSub.innerText = 'Synchronizing N-API modules...';
					} else if (width === 72) {
						decryptSub.innerText = \`Authorizing Operator role: \${profileName.split(' ')[1]}...\`;
					} else if (width === 96) {
						decryptSub.innerText = 'Loading Workspace environment...';
					}
				}
			}, 50);
		}

		function skipToIDE() {
			writeTerminalLog("[BYPASS] Operator selected direct workspace bypass.", "warn");
			setTimeout(() => {
				vscode.postMessage({ command: 'closeDashboard' });
			}, 200);
		}

		// Commands triggers
		function runCommand(id, args = null) {
			vscode.postMessage({ command: 'runCommand', id, args });
		}

		// Configuration changes
		function toggleAutoOpen(checked) {
			vscode.postMessage({ command: 'setAutoOpen', value: checked });
			writeTerminalLog(\`[CONFIG] Auto-open on boot set to: \${checked}\`, 'warn');
		}
	</script>
</body>
</html>`;
	}
}

export class GettingStartedInputSerializer implements IEditorSerializer {
	public canSerialize(editorInput: GettingStartedInput): boolean {
		return true;
	}

	public serialize(editorInput: GettingStartedInput): string {
		return JSON.stringify({ selectedCategory: editorInput.selectedCategory, selectedStep: editorInput.selectedStep });
	}

	public deserialize(instantiationService: IInstantiationService, serializedEditorInput: string): GettingStartedInput {
		return instantiationService.invokeFunction(accessor => {
			try {
				const { selectedCategory, selectedStep } = JSON.parse(serializedEditorInput);
				return new GettingStartedInput({ selectedCategory, selectedStep });
			} catch { }
			return new GettingStartedInput({});
		});
	}
}
