/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as vscode from 'vscode';
import { importScannerResult, isScannerImportOptions, type ScannerImportOptions } from './scannerImport';
import { engagementStore } from './store';
import type {
	AddIdentityOptions,
	CreateEngagementOptions,
	EngagementIdOptions,
	ProbeOptions,
	ProbeResponseData,
	ProbeResponseSummary,
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
const SENSITIVE_RESPONSE_HEADERS = new Set([
	'set-cookie',
	'authorization',
	'proxy-authorization',
	'www-authenticate',
	'proxy-authenticate',
	'x-api-key',
	'x-auth-token',
]);

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
		vscode.commands.registerCommand(
			'scylla.engagement.recordTransactionHeadless',
			(arg?: RecordTransactionOptions | ScannerImportOptions) => {
				if (!arg) {
					throw new Error('scylla.engagement.recordTransactionHeadless requires transaction or scanner-import options.');
				}
				if (isScannerImportOptions(arg)) {
					return importScannerResult(arg);
				}
				return engagementStore.recordTransaction(arg);
			},
		),
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

			// Scylla Jobs injects the job target as a generic `url` when a step does
			// not provide one. When a resource is present, its canonical URL is the
			// authoritative operation target and must win over that injected fallback.
			const url = resource?.canonicalUrl?.trim() || arg.url?.trim();
			if (!url) {
				throw new Error('Probe requires a resource with canonicalUrl or an explicit "url".');
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
					// Custom test headers are allowed, but identity-derived auth wins so
					// the persisted transaction cannot claim one actor while using another
					// actor's Cookie/Authorization header.
					headers: { ...(arg.headers ?? {}), ...authHeaders },
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
				response: buildResponseSummary(httpResult.response, bodyHash, arg),
				responseFile: httpResult.responseFile,
			};
		}),
		vscode.commands.registerCommand('scylla.engagement.authorizationMatrixHeadless', (arg?: EngagementIdOptions) => {
			return engagementStore.authorizationMatrix(arg?.engagementId);
		}),
	);
}

function buildResponseSummary(
	response: ProbeResponseData,
	bodyHash: string,
	options: ProbeOptions,
): ProbeResponseSummary {
	const contentType = getHeader(response.headers, 'content-type');
	return {
		statusCode: response.statusCode,
		statusMessage: response.statusMessage,
		finalUrl: response.finalUrl,
		contentType,
		bodyBytes: response.bodyBytes,
		bodyHash,
		truncated: response.truncated,
		elapsedMs: response.elapsedMs,
		redirected: response.redirected,
		redirectCount: response.redirectCount,
		...(options.includeResponseHeaders ? { headers: sanitizeResponseHeaders(response.headers) } : {}),
		...(options.includeResponseBody ? { bodyText: response.bodyText } : {}),
	};
}

function getHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
	const target = name.toLowerCase();
	for (const [key, value] of Object.entries(headers)) {
		if (key.toLowerCase() === target) {
			return Array.isArray(value) ? value.join(', ') : value;
		}
	}
	return undefined;
}

function sanitizeResponseHeaders(
	headers: Record<string, string | string[]>,
): Record<string, string | string[]> {
	const sanitized: Record<string, string | string[]> = {};
	for (const [key, value] of Object.entries(headers)) {
		sanitized[key] = SENSITIVE_RESPONSE_HEADERS.has(key.toLowerCase()) ? '[REDACTED]' : value;
	}
	return sanitized;
}

export function deactivate(): void { }
