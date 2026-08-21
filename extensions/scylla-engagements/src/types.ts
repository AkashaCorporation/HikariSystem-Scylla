/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export const SCYLLA_ENGAGEMENT_SCHEMA_VERSION = 1 as const;

export type AccessExpectation = 'allow' | 'deny' | 'unknown';
export type AccessObservation = 'allowed' | 'denied' | 'unknown';
export type TransactionKind = 'baseline' | 'probe' | 'replay' | 'observation';

export interface EngagementIdentity {
	id: string;
	displayName?: string;
	role?: string;
	/** Name of the scylla-auth profile that materializes this identity. */
	authProfile?: string;
	tags: string[];
	metadata?: Record<string, string>;
}

export interface EngagementResource {
	id: string;
	type?: string;
	/** Engagement identity that is known to own this resource, when known. */
	ownerIdentityId?: string;
	canonicalUrl?: string;
	/** Stable values that identify this resource in URLs/bodies (IDs, UUIDs, slugs, etc.). */
	identifiers: string[];
	tags: string[];
	metadata?: Record<string, string>;
}

export interface TransactionMutation {
	kind: string;
	field?: string;
	from?: string;
	to?: string;
}

export interface EngagementTransaction {
	id: string;
	createdAt: string;
	kind: TransactionKind;
	identityId?: string;
	method: string;
	url: string;
	requestArtifact?: string;
	responseArtifact?: string;
	statusCode?: number;
	bodyHash?: string;
	contentLength?: number;
	resourceId?: string;
	baselineTransactionId?: string;
	parentTransactionId?: string;
	mutation?: TransactionMutation;
	expectedAccess: AccessExpectation;
	observedAccess: AccessObservation;
	confidence?: number;
	notes?: string;
	tags: string[];
}

export interface EngagementDocument {
	schemaVersion: typeof SCYLLA_ENGAGEMENT_SCHEMA_VERSION;
	id: string;
	name: string;
	description?: string;
	createdAt: string;
	updatedAt: string;
	targets: string[];
	scope: string[];
	tags: string[];
	identities: EngagementIdentity[];
	resources: EngagementResource[];
	transactions: EngagementTransaction[];
}

export interface EngagementSummary {
	id: string;
	name: string;
	updatedAt: string;
	targets: string[];
	identityCount: number;
	resourceCount: number;
	transactionCount: number;
	active: boolean;
}

export interface CreateEngagementOptions {
	id?: string;
	name?: string;
	description?: string;
	targets?: string[];
	scope?: string[];
	tags?: string[];
	setActive?: boolean;
}

export interface EngagementIdOptions {
	engagementId?: string;
}

export interface SetActiveEngagementOptions {
	engagementId?: string;
}

export interface AddIdentityOptions extends EngagementIdOptions {
	identity?: Partial<EngagementIdentity> & { id?: string };
	id?: string;
	displayName?: string;
	role?: string;
	authProfile?: string;
	tags?: string[];
	metadata?: Record<string, string>;
}

export interface RegisterResourceOptions extends EngagementIdOptions {
	resource?: Partial<EngagementResource> & { id?: string };
	id?: string;
	type?: string;
	ownerIdentityId?: string;
	canonicalUrl?: string;
	identifiers?: string[];
	tags?: string[];
	metadata?: Record<string, string>;
}

export interface RecordTransactionOptions extends EngagementIdOptions {
	transaction?: Partial<EngagementTransaction>;
	kind?: TransactionKind;
	identityId?: string;
	method?: string;
	url?: string;
	requestArtifact?: string;
	responseArtifact?: string;
	statusCode?: number;
	bodyHash?: string;
	contentLength?: number;
	resourceId?: string;
	baselineTransactionId?: string;
	parentTransactionId?: string;
	mutation?: TransactionMutation;
	expectedAccess?: AccessExpectation;
	observedAccess?: AccessObservation;
	confidence?: number;
	notes?: string;
	tags?: string[];
}

export interface ProbeOptions extends EngagementIdOptions {
	identityId?: string;
	resourceId?: string;
	method?: string;
	url?: string;
	headers?: Record<string, string>;
	body?: string;
	timeoutMs?: number;
	followRedirects?: boolean;
	maxBodyBytes?: number;
	kind?: TransactionKind;
	baselineTransactionId?: string;
	parentTransactionId?: string;
	mutation?: TransactionMutation;
	expectedAccess?: AccessExpectation;
	confidence?: number;
	notes?: string;
	tags?: string[];
	/** Include the response body in the command result. The full body is always kept in the response artifact. */
	includeResponseBody?: boolean;
	/** Include sanitized response headers in the command result. */
	includeResponseHeaders?: boolean;
	/**
	 * State-changing methods (POST/PUT/PATCH/DELETE and other non-safe verbs) are
	 * blocked unless this flag is explicitly true. Scope/rate-limit enforcement
	 * still occurs in scylla-http.
	 */
	allowStateChange?: boolean;
}

export interface ProbeResponseData {
	statusCode: number;
	statusMessage: string;
	headers: Record<string, string | string[]>;
	bodyText: string;
	bodyBytes: number;
	truncated: boolean;
	elapsedMs: number;
	redirected: boolean;
	redirectCount: number;
	finalUrl: string;
}

/** Compact-by-default command result; full evidence remains file-backed. */
export interface ProbeResponseSummary {
	statusCode: number;
	statusMessage: string;
	finalUrl: string;
	contentType?: string;
	bodyBytes: number;
	bodyHash: string;
	truncated: boolean;
	elapsedMs: number;
	redirected: boolean;
	redirectCount: number;
	headers?: Record<string, string | string[]>;
	bodyText?: string;
}

export interface ProbeResult {
	generatedAt: string;
	engagementId: string;
	identityId: string;
	resourceId?: string;
	transaction: EngagementTransaction;
	response: ProbeResponseSummary;
	responseFile?: string;
}

export interface AuthorizationMatrixCell {
	identityId: string;
	resourceId: string;
	expectedAccess: AccessExpectation;
	observedAccess: AccessObservation;
	matchesExpectation?: boolean;
	transactionId?: string;
	statusCode?: number;
	confidence?: number;
}

export interface AuthorizationMatrixResult {
	generatedAt: string;
	engagementId: string;
	identities: EngagementIdentity[];
	resources: EngagementResource[];
	cells: AuthorizationMatrixCell[];
	mismatches: AuthorizationMatrixCell[];
}
