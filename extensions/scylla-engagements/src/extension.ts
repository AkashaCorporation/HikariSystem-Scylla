/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { engagementStore } from './store';
import type {
	AddIdentityOptions,
	CreateEngagementOptions,
	EngagementIdOptions,
	ProbeOptions,
	ProbeResponseData,
	ProbeResult,
	RecordTransactionOptions,
	RegisterResourceOptions,
	SetActiveEngagementOptions,
} from './types';

interface AuthHeadersResult {
	headers: Record<string, string>;
	sessionValid: boolean;
}

interface HttpSendResult {
	generatedAt: string;
	request: {
		method: string;
		url: string;
	};
	response: ProbeResponseData;
	requestFile?: string;
	responseFile?: string;
}

const SAFE_PROBE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function activate(context: vscode.ExtensionContext): void {
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.engagement.createHeadless', (arg?: CreateEngagementOptions) => {
			return engagementStore.createEngagement(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.getHeadless', (arg?: EngagementIdOptions) => {
			return engagementStore.getEngagement(arg?.engagementId);
		}),
		vscode.commands.registerCommand('scylla.engagement.listHeadless', () => {
			return engagementStore.listEngagements();
		}),
		vscode.commands.registerCommand('scylla.engagement.setActiveHeadless', (arg?: SetActiveEngagementOptions) => {
			if (!arg?.engagementId) {
				throw new Error('scylla.engagement.setActiveHeadless requires "engagementId".');
			}
			return engagementStore.setActiveEngagement(arg.engagementId);
		}),
		vscode.commands.registerCommand('scylla.engagement.addIdentityHeadless', (arg?: AddIdentityOptions) => {
			if (!arg) {
				throw new Error('scylla.engagement.addIdentityHeadless requires identity options.');
			}
			return engagementStore.addIdentity(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.registerResourceHeadless', (arg?: RegisterResourceOptions) => {
			if (!arg) {
				throw new Error('scylla.engagement.registerResourceHeadless requires resource options.');
			}
			return engagementStore.registerResource(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.recordTransactionHeadless', (arg?: RecordTransactionOptions) => {
			if (!arg) {
				throw new Error('scylla.engagement.recordTransactionHeadless requires transaction options.');
			}
			return engagementStore.recordTransaction(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.probeHeadless', async (arg?: ProbeOptions): Promise<ProbeResult> => {
			if (!arg?.identityId) {
				throw new Error('scylla.engagement.probeHeadless requires "identityId".');
			}

			const engagement = engagementStore.getEngagement(arg.engagementId);
			const identity = engagement.identities.find(item => item.id === arg.identityId);
			if (!identity) {
				throw new Error(`Unknown engagement identity: ${arg.identityId}`);
			}

			const resource = arg.resourceId
				? engagement.resources.find(item => item.id === arg.resourceId)
				: undefined;
			if (arg.resourceId && !resource) {
				throw new Error(`Unknown engagement resource: ${arg.resourceId}`);
			}

			const method = (arg.method ?? 'GET').trim().toUpperCase();
			if (!method) {
				throw new Error('Probe method cannot be empty.');
			}
			if (!SAFE_PROBE_METHODS.has(method) && arg.allowStateChange !== true) {
				throw new Error(
					`State-changing probe method ${method} is blocked by default. ` +
					`Set allowStateChange=true only when the engagement explicitly permits this operation.`
				);
			}

			const url = arg.url?.trim() || resource?.canonicalUrl?.trim();
			if (!url) {
				throw new Error('Probe requires "url" or a resource with canonicalUrl.');
			}

			let authHeaders: Record<string, string> = {};
			if (identity.authProfile) {
				const authResult = await vscode.commands.executeCommand<AuthHeadersResult>(
					'scylla.auth.getHeadersHeadless',
					{ profileName: identity.authProfile, targetUrl: url, quiet: true }
				);
				if (!authResult?.sessionValid) {
					throw new Error(
						`Auth profile "${identity.authProfile}" for identity "${identity.id}" has no valid session. ` +
						`Refusing to downgrade the probe to anonymous.`
					);
				}
				authHeaders = authResult.headers ?? {};
			}

			const httpResult = await vscode.commands.executeCommand<HttpSendResult>(
				'scylla.http.sendHeadless',
				{
					url,
					method,
					headers: { ...authHeaders, ...(arg.headers ?? {}) },
					body: arg.body,
					timeoutMs: arg.timeoutMs,
					followRedirects: arg.followRedirects,
					maxBodyBytes: arg.maxBodyBytes,
					saveResponse: true,
					quiet: true,
				}
			);
			if (!httpResult?.response) {
				throw new Error('scylla-http returned no response for the engagement probe.');
			}

			const bodyHash = crypto.createHash('sha256').update(httpResult.response.bodyText ?? '').digest('hex').slice(0, 16);
			const recorded = engagementStore.recordTransaction({
				engagementId: engagement.id,
				kind: arg.kind ?? 'probe',
				identityId: identity.id,
				resourceId: resource?.id,
				method,
				url,
				requestArtifact: httpResult.requestFile,
				responseArtifact: httpResult.responseFile,
				statusCode: httpResult.response.statusCode,
				bodyHash,
				contentLength: httpResult.response.bodyBytes,
				baselineTransactionId: arg.baselineTransactionId,
				parentTransactionId: arg.parentTransactionId,
				mutation: arg.mutation,
				expectedAccess: arg.expectedAccess ?? 'unknown',
				confidence: arg.confidence,
				notes: arg.notes,
				tags: arg.tags,
			});

			return {
				generatedAt: new Date().toISOString(),
				engagementId: engagement.id,
				identityId: identity.id,
				resourceId: resource?.id,
				transaction: recorded.transaction,
				response: httpResult.response,
				responseFile: httpResult.responseFile,
			};
		}),
		vscode.commands.registerCommand('scylla.engagement.authorizationMatrixHeadless', (arg?: EngagementIdOptions) => {
			return engagementStore.authorizationMatrix(arg?.engagementId);
		}),
	);
}

export function deactivate(): void { }
