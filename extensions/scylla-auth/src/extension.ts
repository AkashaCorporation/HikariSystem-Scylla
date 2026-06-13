/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { sessionManager } from './sessionManager';
import { governor } from './governor';
import type {
	GetHeadersCommandOptions,
	LoginCommandOptions,
	OAuthCommandOptions,
	SessionCheckCommandOptions,
	SessionRefreshCommandOptions,
} from './types';

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {

	// -------------------------------------------------------------------
	// Login
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.login', async () => {
			const loginUrl = await vscode.window.showInputBox({ prompt: 'Login URL', placeHolder: 'https://target.com/login' });
			if (!loginUrl) { return; }
			const username = await vscode.window.showInputBox({ prompt: 'Username' });
			if (!username) { return; }
			const password = await vscode.window.showInputBox({ prompt: 'Password', password: true });
			if (!password) { return; }

			const profileName = 'default';
			sessionManager.registerProfile(profileName, {
				name: profileName,
				type: 'form',
				loginUrl,
				fields: { username, password },
			});

			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla Auth: Logging in...', cancellable: false },
					() => sessionManager.login(profileName),
				);
				if (result.success) {
					vscode.window.showInformationMessage(`✅ Login successful. ${result.cookiesObtained} cookies obtained.`);
				} else {
					vscode.window.showWarningMessage(`⚠️ Login failed: ${result.error ?? 'Unknown error'}`);
				}
			} catch (e) {
				vscode.window.showErrorMessage(`Login failed: ${e instanceof Error ? e.message : String(e)}`);
			}
		}),

		vscode.commands.registerCommand('scylla.auth.loginHeadless', async (arg?: LoginCommandOptions) => {
			const opts = arg ?? {};

			// Register profiles
			if (opts.profiles) {
				sessionManager.registerProfiles(opts.profiles);
			}
			if (opts.profile) {
				const name = opts.profileName ?? opts.profile.name ?? 'default';
				sessionManager.registerProfile(name, opts.profile);
			}

			// Login
			if (opts.loginAll) {
				const result = await sessionManager.loginAll();
				if (!opts.quiet) {
					vscode.window.showInformationMessage(
						`Auth: ${result.successfulLogins}/${result.totalProfiles} profiles logged in successfully.`
					);
				}
				return result;
			}

			const name = opts.profileName ?? 'default';
			const result = await sessionManager.login(name);
			if (!opts.quiet) {
				if (result.success) {
					vscode.window.showInformationMessage(`Auth: "${name}" logged in. ${result.cookiesObtained} cookies.`);
				} else {
					vscode.window.showWarningMessage(`Auth: "${name}" login failed: ${result.error}`);
				}
			}
			return result;
		}),
	);

	// -------------------------------------------------------------------
	// OAuth2
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.oauth', async () => {
			const tokenUrl = await vscode.window.showInputBox({ prompt: 'OAuth2 Token URL', placeHolder: 'https://auth.example.com/oauth/token' });
			if (!tokenUrl) { return; }
			const clientId = await vscode.window.showInputBox({ prompt: 'Client ID' });
			if (!clientId) { return; }
			const clientSecret = await vscode.window.showInputBox({ prompt: 'Client Secret', password: true });
			if (!clientSecret) { return; }

			const profileName = 'oauth-default';
			sessionManager.registerProfile(profileName, {
				name: profileName,
				type: 'oauth2-client-credentials',
				oauth: { tokenUrl, clientId, clientSecret },
			});

			try {
				const result = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Scylla Auth: OAuth2 login...', cancellable: false },
					() => sessionManager.login(profileName),
				);
				if (result.success) {
					vscode.window.showInformationMessage('✅ OAuth2 login successful. Bearer token obtained.');
				} else {
					vscode.window.showWarningMessage(`⚠️ OAuth2 failed: ${result.error ?? 'Unknown error'}`);
				}
			} catch (e) {
				vscode.window.showErrorMessage(`OAuth2 failed: ${e instanceof Error ? e.message : String(e)}`);
			}
		}),

		vscode.commands.registerCommand('scylla.auth.oauthHeadless', async (arg?: OAuthCommandOptions) => {
			const opts = arg ?? {};
			const name = opts.profileName ?? 'oauth-default';

			if (opts.oauth) {
				sessionManager.registerProfile(name, {
					name,
					type: 'oauth2-client-credentials',
					oauth: opts.oauth,
				});
			}

			const result = await sessionManager.login(name);
			if (!opts.quiet) {
				if (result.success) {
					vscode.window.showInformationMessage(`Auth: "${name}" OAuth2 login successful.`);
				} else {
					vscode.window.showWarningMessage(`Auth: "${name}" OAuth2 failed: ${result.error}`);
				}
			}
			return result;
		}),
	);

	// -------------------------------------------------------------------
	// Session Check
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.sessionCheck', async () => {
			const profiles = sessionManager.listProfiles();
			if (profiles.length === 0) {
				vscode.window.showWarningMessage('No auth profiles registered. Login first.');
				return;
			}
			const pick = await vscode.window.showQuickPick(
				profiles.map(p => ({ label: p.name, description: `${p.type} | ${p.sessionValid ? '✅ valid' : '❌ invalid'}` })),
				{ placeHolder: 'Select a profile to check' },
			);
			if (!pick) { return; }

			const result = await sessionManager.checkSession(pick.label);
			if (result.valid) {
				vscode.window.showInformationMessage(`✅ Session "${pick.label}" is valid (status ${result.statusCode}).`);
			} else {
				vscode.window.showWarningMessage(`⚠️ Session "${pick.label}" is invalid: ${result.error ?? `status ${result.statusCode}`}`);
			}
		}),

		vscode.commands.registerCommand('scylla.auth.sessionCheckHeadless', async (arg?: SessionCheckCommandOptions) => {
			const opts = arg ?? {};
			if (opts.checkAll) {
				const profiles = sessionManager.listProfiles();
				const results = [];
				for (const p of profiles) {
					results.push(await sessionManager.checkSession(p.name));
				}
				return results;
			}
			const name = opts.profileName ?? 'default';
			return await sessionManager.checkSession(name);
		}),
	);

	// -------------------------------------------------------------------
	// Session Refresh
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.sessionRefresh', async () => {
			const profiles = sessionManager.listProfiles();
			if (profiles.length === 0) {
				vscode.window.showWarningMessage('No auth profiles registered. Login first.');
				return;
			}
			const pick = await vscode.window.showQuickPick(
				profiles.map(p => ({ label: p.name, description: p.type })),
				{ placeHolder: 'Select a profile to refresh' },
			);
			if (!pick) { return; }

			const result = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: `Scylla Auth: Refreshing "${pick.label}"...`, cancellable: false },
				() => sessionManager.refreshSession(pick.label),
			);
			if (result.success) {
				vscode.window.showInformationMessage(`✅ Session refreshed (attempt #${result.refreshCount}).`);
			} else {
				vscode.window.showWarningMessage(`⚠️ Refresh failed: ${result.error}`);
			}
		}),

		vscode.commands.registerCommand('scylla.auth.sessionRefreshHeadless', async (arg?: SessionRefreshCommandOptions) => {
			const opts = arg ?? {};
			if (opts.refreshAll) {
				const profiles = sessionManager.listProfiles();
				const results = [];
				for (const p of profiles) {
					results.push(await sessionManager.refreshSession(p.name));
				}
				return results;
			}
			const name = opts.profileName ?? 'default';
			return await sessionManager.refreshSession(name);
		}),
	);

	// -------------------------------------------------------------------
	// Get Auth Headers (used by pipeline runner and scanners)
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.getHeadersHeadless', (arg?: GetHeadersCommandOptions) => {
			const name = arg?.profileName ?? 'default';
			// Pass targetUrl so cookies are domain-scoped to the request host.
			// Without it, buildAuthHeaders falls back to sending EVERY cookie in
			// the jar to EVERY host (a cross-host session leak that also breaks
			// IDOR reliability). Omitting targetUrl keeps the legacy behavior.
			return sessionManager.getAuthHeaders(name, arg?.targetUrl);
		}),
	);

	// -------------------------------------------------------------------
	// Governor scope commands  (parity with scylla-http; lets a job run
	// constrain auth-side egress -- login, session-check, refresh -- to the
	// engagement scope, closing the auto-login SSRF on out-of-scope hosts).
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.setScopeHeadless', (arg?: { scope?: string[]; replace?: boolean }) => {
			if (!arg?.scope || !Array.isArray(arg.scope)) {
				throw new Error('scylla.auth.setScopeHeadless requires a "scope" array of host patterns.');
			}
			if (arg.replace) {
				governor.clearRuntimeScope();
			}
			governor.seedScope(arg.scope);
			return { scope: governor.getEffectiveScope() };
		}),

		vscode.commands.registerCommand('scylla.auth.clearScopeHeadless', () => {
			governor.clearRuntimeScope();
			return { scope: governor.getEffectiveScope() };
		}),

		vscode.commands.registerCommand('scylla.auth.getScopeHeadless', () => {
			return { scope: governor.getEffectiveScope(), config: governor.getConfig() };
		}),
	);

	// -------------------------------------------------------------------
	// List Profiles
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.listProfilesHeadless', () => {
			return sessionManager.listProfiles();
		}),
	);

	// -------------------------------------------------------------------
	// Clear Sessions
	// -------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.auth.clearSessionsHeadless', () => {
			sessionManager.clearSessions();
			return { success: true, generatedAt: new Date().toISOString() };
		}),
	);
}

export function deactivate(): void {
	sessionManager.clearAll();
}
