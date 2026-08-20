/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { engagementStore } from './store';
import type {
	AuthorizationMatrixResult,
	EngagementDocument,
	EngagementTransaction,
	RecordTransactionOptions,
} from './types';

export type ScannerImportType = 'idor' | 'privesc';

export interface ScannerImportOptions {
	engagementId?: string;
	scannerResultFile?: string;
	scannerType?: ScannerImportType;
}

export interface ScannerImportResult {
	generatedAt: string;
	engagementId: string;
	scannerType: ScannerImportType;
	findingsImported: number;
	resourcesRegistered: number;
	transactionsRecorded: number;
	matrix: AuthorizationMatrixResult;
}

interface BaseScannerFinding {
	type?: string;
	confidence?: number;
	payload?: string;
	details?: string;
}

interface IdorArtifactFinding extends BaseScannerFinding {
	type: 'idor';
	testedUrl: string;
	originalUrl?: string;
	strategy?: string;
	attackerProfile: string;
	baselineProfile: string;
	resourceOwnerProfile?: string;
	ownershipSource?: 'knownIds' | 'heuristic';
	originalResponse: { statusCode: number; bodyHash?: string; contentLength?: number };
	modifiedResponse: { statusCode: number; bodyHash?: string; contentLength?: number };
}

interface PrivescArtifactFinding extends BaseScannerFinding {
	type: 'privesc';
	adminEndpoint: string;
	method?: string;
	actors?: {
		attackerProfile?: string;
		baselineProfile?: string;
	};
	adminResponse: { statusCode: number; contentLength?: number };
	lowPrivResponse: { statusCode: number; contentLength?: number };
}

interface ScannerArtifact {
	findings?: BaseScannerFinding[];
}

export function isScannerImportOptions(value: unknown): value is ScannerImportOptions {
	return !!value && typeof value === 'object' && typeof (value as ScannerImportOptions).scannerResultFile === 'string';
}

export function importScannerResult(options: ScannerImportOptions): ScannerImportResult {
	if (!options.scannerResultFile?.trim()) {
		throw new Error('Scanner import requires "scannerResultFile".');
	}

	const engagement = engagementStore.getEngagement(options.engagementId);
	const artifactPath = resolveWorkspaceFile(options.scannerResultFile);
	const artifact = readArtifact(artifactPath);
	const scannerType = options.scannerType ?? inferScannerType(artifact);

	let findingsImported = 0;
	const resourceIds = new Set<string>();
	const transactionIds = new Set<string>();

	for (const rawFinding of artifact.findings ?? []) {
		if (scannerType === 'idor' && rawFinding.type === 'idor') {
			const result = importIdorFinding(engagement.id, rawFinding as IdorArtifactFinding);
			if (result.imported) { findingsImported++; }
			resourceIds.add(result.resourceId);
			for (const id of result.transactionIds) { transactionIds.add(id); }
		} else if (scannerType === 'privesc' && rawFinding.type === 'privesc') {
			const result = importPrivescFinding(engagement.id, rawFinding as PrivescArtifactFinding);
			if (result.imported) { findingsImported++; }
			resourceIds.add(result.resourceId);
			for (const id of result.transactionIds) { transactionIds.add(id); }
		}
	}

	return {
		generatedAt: new Date().toISOString(),
		engagementId: engagement.id,
		scannerType,
		findingsImported,
		resourcesRegistered: resourceIds.size,
		transactionsRecorded: transactionIds.size,
		matrix: engagementStore.authorizationMatrix(engagement.id),
	};
}

function importIdorFinding(
	engagementId: string,
	finding: IdorArtifactFinding,
): { imported: boolean; resourceId: string; transactionIds: string[] } {
	if (!finding.testedUrl || !finding.attackerProfile || !finding.baselineProfile) {
		throw new Error('Invalid IDOR artifact: testedUrl, attackerProfile, and baselineProfile are required.');
	}

	const attackerIdentityId = ensureIdentity(engagementId, finding.attackerProfile, 'attacker');
	const baselineIdentityId = ensureIdentity(engagementId, finding.baselineProfile, 'baseline');
	const ownerIdentityId = finding.resourceOwnerProfile
		? ensureIdentity(engagementId, finding.resourceOwnerProfile, 'resource-owner')
		: undefined;

	const resourceId = `idor-${shortHash(finding.testedUrl)}`;
	engagementStore.registerResource({
		engagementId,
		id: resourceId,
		type: 'object-reference',
		ownerIdentityId,
		canonicalUrl: finding.testedUrl,
		identifiers: normalizeIdentifier(finding.payload) ? [finding.payload!.trim()] : [],
		tags: ['scanner-import', 'idor', `ownership:${finding.ownershipSource ?? 'heuristic'}`],
		metadata: {
			scanner: 'scylla-idor',
			strategy: finding.strategy ?? 'unknown',
		},
	});

	const method = finding.strategy === 'method-swap' ? 'POST' : 'GET';
	const baselineTxId = `tx-idor-base-${shortHash(`${baselineIdentityId}|${finding.testedUrl}|${method}`)}`;
	const attackerTxId = `tx-idor-probe-${shortHash(`${attackerIdentityId}|${finding.testedUrl}|${method}`)}`;
	const before = engagementStore.getEngagement(engagementId).transactions.length;

	ensureTransaction(engagementId, baselineTxId, {
		kind: 'baseline',
		identityId: baselineIdentityId,
		resourceId,
		method,
		url: finding.testedUrl,
		statusCode: finding.originalResponse.statusCode,
		bodyHash: finding.originalResponse.bodyHash,
		contentLength: finding.originalResponse.contentLength,
		expectedAccess: 'allow',
		confidence: finding.confidence,
		notes: 'Imported from IDOR scanner victim/baseline response.',
		tags: ['scanner-import', 'idor', 'baseline'],
	});

	ensureTransaction(engagementId, attackerTxId, {
		kind: 'probe',
		identityId: attackerIdentityId,
		resourceId,
		method,
		url: finding.testedUrl,
		statusCode: finding.modifiedResponse.statusCode,
		bodyHash: finding.modifiedResponse.bodyHash,
		contentLength: finding.modifiedResponse.contentLength,
		baselineTransactionId: baselineTxId,
		mutation: {
			kind: finding.strategy ?? 'idor-candidate',
			to: normalizeIdentifier(finding.payload) ? finding.payload!.trim() : undefined,
		},
		// Ownership alone does not prove that non-owner access should be denied.
		// Policy remains explicit and can be supplied later by probeHeadless/jobs.
		expectedAccess: 'unknown',
		confidence: finding.confidence,
		notes: finding.details ?? 'Imported cross-profile IDOR candidate.',
		tags: ['scanner-import', 'idor', 'candidate'],
	});

	const after = engagementStore.getEngagement(engagementId).transactions.length;
	return {
		imported: after > before,
		resourceId,
		transactionIds: [baselineTxId, attackerTxId],
	};
}

function importPrivescFinding(
	engagementId: string,
	finding: PrivescArtifactFinding,
): { imported: boolean; resourceId: string; transactionIds: string[] } {
	const highProfile = finding.actors?.baselineProfile;
	const lowProfile = finding.actors?.attackerProfile;
	if (!finding.adminEndpoint || !highProfile || !lowProfile) {
		throw new Error('Invalid PrivEsc artifact: endpoint and structured actor profiles are required.');
	}

	const highIdentityId = ensureIdentity(engagementId, highProfile, 'high-privilege');
	const lowIdentityId = ensureIdentity(engagementId, lowProfile, 'low-privilege');
	const resourceId = `priv-${shortHash(finding.adminEndpoint)}`;
	const method = (finding.method ?? 'GET').toUpperCase();

	engagementStore.registerResource({
		engagementId,
		id: resourceId,
		type: 'privileged-endpoint',
		canonicalUrl: finding.adminEndpoint,
		tags: ['scanner-import', 'privesc'],
		metadata: {
			scanner: 'scylla-privesc',
		},
	});

	const baselineTxId = `tx-priv-base-${shortHash(`${highIdentityId}|${finding.adminEndpoint}|${method}`)}`;
	const probeTxId = `tx-priv-probe-${shortHash(`${lowIdentityId}|${finding.adminEndpoint}|${method}`)}`;
	const before = engagementStore.getEngagement(engagementId).transactions.length;

	ensureTransaction(engagementId, baselineTxId, {
		kind: 'baseline',
		identityId: highIdentityId,
		resourceId,
		method,
		url: finding.adminEndpoint,
		statusCode: finding.adminResponse.statusCode,
		contentLength: finding.adminResponse.contentLength,
		expectedAccess: 'allow',
		confidence: finding.confidence,
		notes: 'Imported from PrivEsc high-privilege baseline response.',
		tags: ['scanner-import', 'privesc', 'baseline'],
	});

	ensureTransaction(engagementId, probeTxId, {
		kind: 'probe',
		identityId: lowIdentityId,
		resourceId,
		method,
		url: finding.adminEndpoint,
		statusCode: finding.lowPrivResponse.statusCode,
		contentLength: finding.lowPrivResponse.contentLength,
		baselineTransactionId: baselineTxId,
		expectedAccess: 'unknown',
		confidence: finding.confidence,
		notes: finding.details ?? 'Imported read-only cross-role PrivEsc candidate.',
		tags: ['scanner-import', 'privesc', 'candidate'],
	});

	const after = engagementStore.getEngagement(engagementId).transactions.length;
	return {
		imported: after > before,
		resourceId,
		transactionIds: [baselineTxId, probeTxId],
	};
}

function ensureIdentity(engagementId: string, profileName: string, roleTag: string): string {
	const identityId = profileIdentityId(profileName);
	engagementStore.addIdentity({
		engagementId,
		id: identityId,
		displayName: profileName,
		authProfile: profileName,
		tags: ['scanner-import', roleTag],
		metadata: { sourceProfile: profileName },
	});
	return identityId;
}

function ensureTransaction(
	engagementId: string,
	transactionId: string,
	options: Omit<RecordTransactionOptions, 'engagementId' | 'transaction'>,
): EngagementTransaction {
	const engagement = engagementStore.getEngagement(engagementId);
	const existing = engagement.transactions.find(transaction => transaction.id === transactionId);
	if (existing) { return existing; }
	return engagementStore.recordTransaction({
		engagementId,
		transaction: {
			id: transactionId,
			...options,
		},
	}).transaction;
}

function inferScannerType(artifact: ScannerArtifact): ScannerImportType {
	const firstType = artifact.findings?.find(finding => finding?.type)?.type;
	if (firstType === 'idor' || firstType === 'privesc') { return firstType; }
	throw new Error('Could not infer scanner type. Pass scannerType as "idor" or "privesc".');
}

function readArtifact(filePath: string): ScannerArtifact {
	let parsed: unknown;
	try {
		parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
	} catch (error: unknown) {
		throw new Error(`Failed to parse scanner artifact ${filePath}: ${toErrorMessage(error)}`);
	}
	if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as ScannerArtifact).findings)) {
		throw new Error(`Scanner artifact has no findings array: ${filePath}`);
	}
	return parsed as ScannerArtifact;
}

function resolveWorkspaceFile(candidate: string): string {
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspaceRoot) {
		throw new Error('A workspace folder is required for scanner artifact import.');
	}
	const resolved = path.isAbsolute(candidate) ? path.normalize(candidate) : path.resolve(workspaceRoot, candidate);
	const relative = path.relative(workspaceRoot, resolved);
	if (relative.startsWith('..') || path.isAbsolute(relative)) {
		throw new Error(`scannerResultFile must be inside the workspace: ${resolved}`);
	}
	if (!fs.existsSync(resolved)) {
		throw new Error(`Scanner result file not found: ${resolved}`);
	}
	return resolved;
}

function profileIdentityId(profileName: string): string {
	const trimmed = profileName.trim();
	if (/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(trimmed)) {
		return trimmed;
	}
	return `profile-${shortHash(trimmed)}`;
}

function normalizeIdentifier(value: unknown): boolean {
	return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= 256;
}

function shortHash(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function toErrorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
