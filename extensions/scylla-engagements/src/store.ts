/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
	SCYLLA_ENGAGEMENT_SCHEMA_VERSION,
	type AccessExpectation,
	type AccessObservation,
	type AddIdentityOptions,
	type AuthorizationMatrixCell,
	type AuthorizationMatrixResult,
	type CreateEngagementOptions,
	type EngagementDocument,
	type EngagementIdentity,
	type EngagementResource,
	type EngagementSummary,
	type RecordTransactionOptions,
	type RegisterResourceOptions,
	type TransactionKind,
} from './types';

const ENGAGEMENTS_DIR = path.join('.scylla', 'engagements');
const ACTIVE_FILE = 'active.json';
const SAFE_ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

interface ActiveEngagementPointer {
	engagementId: string;
	updatedAt: string;
}

export class JsonEngagementStore {
	createEngagement(options?: CreateEngagementOptions): EngagementDocument {
		const name = normalizeRequiredString(options?.name, 'Engagement name is required.');
		const id = options?.id ? validateId(options.id, 'engagementId') : buildEntityId(name);
		const filePath = this.engagementPath(id);
		if (fs.existsSync(filePath)) {
			throw new Error(`Engagement already exists: ${id}`);
		}

		const now = new Date().toISOString();
		const engagement: EngagementDocument = {
			schemaVersion: SCYLLA_ENGAGEMENT_SCHEMA_VERSION,
			id,
			name,
			description: normalizeOptionalString(options?.description),
			createdAt: now,
			updatedAt: now,
			targets: normalizeStringArray(options?.targets),
			scope: normalizeStringArray(options?.scope),
			tags: normalizeStringArray(options?.tags),
			identities: [],
			resources: [],
			transactions: [],
		};

		this.writeEngagement(engagement);
		if (options?.setActive !== false) {
			this.setActiveEngagement(id);
		}
		return engagement;
	}

	getEngagement(engagementId?: string): EngagementDocument {
		const id = engagementId ? validateId(engagementId, 'engagementId') : this.requireActiveEngagementId();
		const filePath = this.engagementPath(id);
		if (!fs.existsSync(filePath)) {
			throw new Error(`Engagement not found: ${id}`);
		}

		let parsed: unknown;
		try {
			parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
		} catch (error: unknown) {
			throw new Error(`Failed to parse engagement ${id}: ${toErrorMessage(error)}`);
		}
		return validateEngagementDocument(parsed, filePath);
	}

	listEngagements(): EngagementSummary[] {
		const dir = this.ensureDirectory();
		const activeId = this.getActiveEngagementId();
		const summaries: EngagementSummary[] = [];
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
			if (!entry.isFile() || !entry.name.endsWith('.json') || entry.name === ACTIVE_FILE) {
				continue;
			}
			try {
				const engagement = this.getEngagement(entry.name.slice(0, -5));
				summaries.push({
					id: engagement.id,
					name: engagement.name,
					updatedAt: engagement.updatedAt,
					targets: [...engagement.targets],
					identityCount: engagement.identities.length,
					resourceCount: engagement.resources.length,
					transactionCount: engagement.transactions.length,
					active: engagement.id === activeId,
				});
			} catch {
				// Ignore malformed files in list mode; explicit get reports the parse error.
			}
		}
		return summaries.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
	}

	setActiveEngagement(engagementId: string): ActiveEngagementPointer {
		const id = validateId(engagementId, 'engagementId');
		// Ensure the target exists before changing the pointer.
		this.getEngagement(id);
		const pointer: ActiveEngagementPointer = {
			engagementId: id,
			updatedAt: new Date().toISOString(),
		};
		writeJsonAtomically(path.join(this.ensureDirectory(), ACTIVE_FILE), pointer);
		return pointer;
	}

	getActiveEngagementId(): string | undefined {
		const pointerPath = path.join(this.ensureDirectory(), ACTIVE_FILE);
		if (!fs.existsSync(pointerPath)) { return undefined; }
		try {
			const parsed = JSON.parse(fs.readFileSync(pointerPath, 'utf8')) as Partial<ActiveEngagementPointer>;
			if (typeof parsed.engagementId !== 'string') { return undefined; }
			const id = validateId(parsed.engagementId, 'engagementId');
			return fs.existsSync(this.engagementPath(id)) ? id : undefined;
		} catch {
			return undefined;
		}
	}

	addIdentity(options: AddIdentityOptions): { engagement: EngagementDocument; identity: EngagementIdentity } {
		const engagement = this.getEngagement(options.engagementId);
		const source = options.identity ?? {};
		const id = validateId(source.id ?? options.id ?? buildEntityId(source.displayName ?? options.displayName ?? source.authProfile ?? options.authProfile ?? 'identity'), 'identityId');
		const identity: EngagementIdentity = {
			id,
			displayName: normalizeOptionalString(source.displayName ?? options.displayName),
			role: normalizeOptionalString(source.role ?? options.role),
			authProfile: normalizeOptionalString(source.authProfile ?? options.authProfile),
			tags: normalizeStringArray(source.tags ?? options.tags),
			metadata: normalizeMetadata(source.metadata ?? options.metadata),
		};

		const existingIndex = engagement.identities.findIndex(item => item.id === id);
		if (existingIndex >= 0) {
			engagement.identities[existingIndex] = mergeIdentity(engagement.identities[existingIndex], identity);
		} else {
			engagement.identities.push(identity);
		}
		engagement.updatedAt = new Date().toISOString();
		this.writeEngagement(engagement);
		return { engagement, identity: engagement.identities.find(item => item.id === id)! };
	}

	registerResource(options: RegisterResourceOptions): { engagement: EngagementDocument; resource: EngagementResource } {
		const engagement = this.getEngagement(options.engagementId);
		const source = options.resource ?? {};
		const id = validateId(source.id ?? options.id ?? buildEntityId(source.type ?? options.type ?? 'resource'), 'resourceId');
		const ownerIdentityId = normalizeOptionalString(source.ownerIdentityId ?? options.ownerIdentityId);
		if (ownerIdentityId && !engagement.identities.some(identity => identity.id === ownerIdentityId)) {
			throw new Error(`Unknown owner identity: ${ownerIdentityId}`);
		}

		const resource: EngagementResource = {
			id,
			type: normalizeOptionalString(source.type ?? options.type),
			ownerIdentityId,
			canonicalUrl: normalizeOptionalString(source.canonicalUrl ?? options.canonicalUrl),
			identifiers: normalizeStringArray(source.identifiers ?? options.identifiers),
			tags: normalizeStringArray(source.tags ?? options.tags),
			metadata: normalizeMetadata(source.metadata ?? options.metadata),
		};

		const existingIndex = engagement.resources.findIndex(item => item.id === id);
		if (existingIndex >= 0) {
			engagement.resources[existingIndex] = mergeResource(engagement.resources[existingIndex], resource);
		} else {
			engagement.resources.push(resource);
		}
		engagement.updatedAt = new Date().toISOString();
		this.writeEngagement(engagement);
		return { engagement, resource: engagement.resources.find(item => item.id === id)! };
	}

	recordTransaction(options: RecordTransactionOptions): { engagement: EngagementDocument; transaction: EngagementDocument['transactions'][number] } {
		const engagement = this.getEngagement(options.engagementId);
		const source = options.transaction ?? {};
		const identityId = normalizeOptionalString(source.identityId ?? options.identityId);
		const resourceId = normalizeOptionalString(source.resourceId ?? options.resourceId);
		const baselineTransactionId = normalizeOptionalString(source.baselineTransactionId ?? options.baselineTransactionId);
		const parentTransactionId = normalizeOptionalString(source.parentTransactionId ?? options.parentTransactionId);

		if (identityId && !engagement.identities.some(identity => identity.id === identityId)) {
			throw new Error(`Unknown transaction identity: ${identityId}`);
		}
		if (resourceId && !engagement.resources.some(resource => resource.id === resourceId)) {
			throw new Error(`Unknown transaction resource: ${resourceId}`);
		}
		if (baselineTransactionId && !engagement.transactions.some(transaction => transaction.id === baselineTransactionId)) {
			throw new Error(`Unknown baseline transaction: ${baselineTransactionId}`);
		}
		if (parentTransactionId && !engagement.transactions.some(transaction => transaction.id === parentTransactionId)) {
			throw new Error(`Unknown parent transaction: ${parentTransactionId}`);
		}

		const method = normalizeRequiredString(source.method ?? options.method, 'Transaction method is required.').toUpperCase();
		const url = normalizeRequiredString(source.url ?? options.url, 'Transaction URL is required.');
		const statusCode = normalizeStatusCode(source.statusCode ?? options.statusCode);
		const observedAccess = normalizeAccessObservation(
			source.observedAccess ?? options.observedAccess ?? inferObservedAccess(statusCode)
		);
		const expectedAccess = normalizeAccessExpectation(source.expectedAccess ?? options.expectedAccess ?? 'unknown');
		const createdAt = normalizeOptionalString(source.createdAt) ?? new Date().toISOString();
		const transaction = {
			id: validateId(source.id ?? buildTransactionId(), 'transactionId'),
			createdAt,
			kind: normalizeTransactionKind(source.kind ?? options.kind),
			identityId,
			method,
			url,
			requestArtifact: normalizeOptionalString(source.requestArtifact ?? options.requestArtifact),
			responseArtifact: normalizeOptionalString(source.responseArtifact ?? options.responseArtifact),
			statusCode,
			bodyHash: normalizeOptionalString(source.bodyHash ?? options.bodyHash),
			contentLength: normalizeNonNegativeInteger(source.contentLength ?? options.contentLength, 'contentLength'),
			resourceId,
			baselineTransactionId,
			parentTransactionId,
			mutation: normalizeMutation(source.mutation ?? options.mutation),
			expectedAccess,
			observedAccess,
			confidence: normalizeConfidence(source.confidence ?? options.confidence),
			notes: normalizeOptionalString(source.notes ?? options.notes),
			tags: normalizeStringArray(source.tags ?? options.tags),
		};

		if (engagement.transactions.some(existing => existing.id === transaction.id)) {
			throw new Error(`Transaction already exists: ${transaction.id}`);
		}
		engagement.transactions.push(transaction);
		engagement.updatedAt = new Date().toISOString();
		this.writeEngagement(engagement);
		return { engagement, transaction };
	}

	authorizationMatrix(engagementId?: string): AuthorizationMatrixResult {
		const engagement = this.getEngagement(engagementId);
		const cells: AuthorizationMatrixCell[] = [];

		for (const identity of engagement.identities) {
			for (const resource of engagement.resources) {
				const relevant = engagement.transactions
					.filter(transaction => transaction.identityId === identity.id && transaction.resourceId === resource.id)
					.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
				const latest = relevant[0];
				const expectedAccess = latest?.expectedAccess ?? inferExpectedAccess(identity.id, resource);
				const observedAccess = latest?.observedAccess ?? 'unknown';
				const matchesExpectation = compareAccess(expectedAccess, observedAccess);
				cells.push({
					identityId: identity.id,
					resourceId: resource.id,
					expectedAccess,
					observedAccess,
					matchesExpectation,
					transactionId: latest?.id,
					statusCode: latest?.statusCode,
					confidence: latest?.confidence,
				});
			}
		}

		return {
			generatedAt: new Date().toISOString(),
			engagementId: engagement.id,
			identities: engagement.identities,
			resources: engagement.resources,
			cells,
			mismatches: cells.filter(cell => cell.matchesExpectation === false),
		};
	}

	private requireActiveEngagementId(): string {
		const active = this.getActiveEngagementId();
		if (!active) {
			throw new Error('No active Scylla engagement. Pass engagementId or create/set an active engagement.');
		}
		return active;
	}

	private ensureDirectory(): string {
		const dir = path.join(ensureWorkspaceRoot(), ENGAGEMENTS_DIR);
		fs.mkdirSync(dir, { recursive: true });
		return dir;
	}

	private engagementPath(engagementId: string): string {
		return path.join(this.ensureDirectory(), `${validateId(engagementId, 'engagementId')}.json`);
	}

	private writeEngagement(engagement: EngagementDocument): void {
		writeJsonAtomically(this.engagementPath(engagement.id), engagement);
	}
}

export const engagementStore = new JsonEngagementStore();

function validateEngagementDocument(value: unknown, filePath: string): EngagementDocument {
	if (!value || typeof value !== 'object') {
		throw new Error(`Invalid engagement document: ${filePath}`);
	}
	const document = value as Partial<EngagementDocument>;
	if (document.schemaVersion !== SCYLLA_ENGAGEMENT_SCHEMA_VERSION) {
		throw new Error(`Unsupported engagement schemaVersion in ${filePath}: ${String(document.schemaVersion)}`);
	}
	if (typeof document.id !== 'string' || !SAFE_ID.test(document.id)) {
		throw new Error(`Invalid engagement id in ${filePath}`);
	}
	if (typeof document.name !== 'string' || document.name.trim().length === 0) {
		throw new Error(`Invalid engagement name in ${filePath}`);
	}
	if (!Array.isArray(document.identities) || !Array.isArray(document.resources) || !Array.isArray(document.transactions)) {
		throw new Error(`Invalid engagement collections in ${filePath}`);
	}
	if (!Array.isArray(document.targets) || !Array.isArray(document.scope) || !Array.isArray(document.tags)) {
		throw new Error(`Invalid engagement metadata arrays in ${filePath}`);
	}
	return document as EngagementDocument;
}

function mergeIdentity(previous: EngagementIdentity, next: EngagementIdentity): EngagementIdentity {
	return {
		...previous,
		...next,
		displayName: next.displayName ?? previous.displayName,
		role: next.role ?? previous.role,
		authProfile: next.authProfile ?? previous.authProfile,
		tags: uniqueStrings([...previous.tags, ...next.tags]),
		metadata: { ...(previous.metadata ?? {}), ...(next.metadata ?? {}) },
	};
}

function mergeResource(previous: EngagementResource, next: EngagementResource): EngagementResource {
	return {
		...previous,
		...next,
		type: next.type ?? previous.type,
		ownerIdentityId: next.ownerIdentityId ?? previous.ownerIdentityId,
		canonicalUrl: next.canonicalUrl ?? previous.canonicalUrl,
		identifiers: uniqueStrings([...previous.identifiers, ...next.identifiers]),
		tags: uniqueStrings([...previous.tags, ...next.tags]),
		metadata: { ...(previous.metadata ?? {}), ...(next.metadata ?? {}) },
	};
}

function inferExpectedAccess(identityId: string, resource: EngagementResource): AccessExpectation {
	// Ownership is evidence that the owner should normally be able to access the
	// resource, but non-ownership alone does not prove denial (admins, sharing,
	// team membership, delegation, etc. may legitimately grant access). Explicit
	// deny expectations must come from the engagement policy or recorded probe.
	if (!resource.ownerIdentityId) { return 'unknown'; }
	return resource.ownerIdentityId === identityId ? 'allow' : 'unknown';
}

function inferObservedAccess(statusCode?: number): AccessObservation {
	if (statusCode === undefined) { return 'unknown'; }
	if (statusCode >= 200 && statusCode < 300) { return 'allowed'; }
	if (statusCode === 401 || statusCode === 403) { return 'denied'; }
	return 'unknown';
}

function compareAccess(expected: AccessExpectation, observed: AccessObservation): boolean | undefined {
	if (expected === 'unknown' || observed === 'unknown') { return undefined; }
	return (expected === 'allow' && observed === 'allowed') || (expected === 'deny' && observed === 'denied');
}

function normalizeAccessExpectation(value: unknown): AccessExpectation {
	return value === 'allow' || value === 'deny' || value === 'unknown' ? value : 'unknown';
}

function normalizeAccessObservation(value: unknown): AccessObservation {
	return value === 'allowed' || value === 'denied' || value === 'unknown' ? value : 'unknown';
}

function normalizeTransactionKind(value: unknown): TransactionKind {
	return value === 'baseline' || value === 'probe' || value === 'replay' || value === 'observation' ? value : 'observation';
}

function normalizeStatusCode(value: unknown): number | undefined {
	if (value === undefined || value === null) { return undefined; }
	if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 999) {
		throw new Error(`Invalid HTTP statusCode: ${String(value)}`);
	}
	return value as number;
}

function normalizeNonNegativeInteger(value: unknown, fieldName: string): number | undefined {
	if (value === undefined || value === null) { return undefined; }
	if (!Number.isInteger(value) || (value as number) < 0) {
		throw new Error(`${fieldName} must be a non-negative integer.`);
	}
	return value as number;
}

function normalizeConfidence(value: unknown): number | undefined {
	if (value === undefined || value === null) { return undefined; }
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new Error('confidence must be a finite number between 0 and 1.');
	}
	return Math.min(1, Math.max(0, value));
}

function normalizeMutation(value: unknown): EngagementDocument['transactions'][number]['mutation'] {
	if (!value || typeof value !== 'object') { return undefined; }
	const source = value as Record<string, unknown>;
	const kind = normalizeOptionalString(source.kind);
	if (!kind) { return undefined; }
	return {
		kind,
		field: normalizeOptionalString(source.field),
		from: normalizeOptionalString(source.from),
		to: normalizeOptionalString(source.to),
	};
}

function normalizeMetadata(value: unknown): Record<string, string> | undefined {
	if (!value || typeof value !== 'object' || Array.isArray(value)) { return undefined; }
	const output: Record<string, string> = {};
	for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
		if (typeof item === 'string' && key.trim().length > 0) {
			output[key.trim()] = item;
		}
	}
	return Object.keys(output).length > 0 ? output : undefined;
}

function normalizeStringArray(values: unknown): string[] {
	if (!Array.isArray(values)) { return []; }
	return uniqueStrings(values.filter((value): value is string => typeof value === 'string').map(value => value.trim()).filter(Boolean));
}

function uniqueStrings(values: string[]): string[] {
	return Array.from(new Set(values));
}

function normalizeRequiredString(value: unknown, message: string): string {
	const normalized = normalizeOptionalString(value);
	if (!normalized) { throw new Error(message); }
	return normalized;
}

function normalizeOptionalString(value: unknown): string | undefined {
	return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function validateId(value: string, fieldName: string): string {
	const normalized = value.trim();
	if (!SAFE_ID.test(normalized)) {
		throw new Error(`${fieldName} must match ${SAFE_ID.source}.`);
	}
	return normalized;
}

function buildEntityId(seed: string): string {
	const slug = seed
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^[._-]+|[._-]+$/g, '')
		.slice(0, 72) || 'entity';
	return `${slug}-${Date.now().toString(36)}`;
}

function buildTransactionId(): string {
	return `tx-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function ensureWorkspaceRoot(): string {
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspaceRoot) {
		throw new Error('A workspace folder is required for Scylla engagement persistence.');
	}
	return workspaceRoot;
}

function writeJsonAtomically(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
	fs.writeFileSync(tempPath, JSON.stringify(value, null, 2), 'utf8');
	try {
		fs.renameSync(tempPath, filePath);
	} catch (error: unknown) {
		// Windows can reject rename-over-existing. Fall back to a replace sequence.
		try {
			if (fs.existsSync(filePath)) { fs.unlinkSync(filePath); }
			fs.renameSync(tempPath, filePath);
		} catch {
			try { if (fs.existsSync(tempPath)) { fs.unlinkSync(tempPath); } } catch { /* ignore cleanup */ }
			throw error;
		}
	}
}

function toErrorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
