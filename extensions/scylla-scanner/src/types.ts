/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export type OutputFormat = 'json' | 'md';
export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingState = 'observation' | 'candidate' | 'validated';

export interface FindingSource {
	scanner?: string;
	command?: string;
	strategy?: string;
}

export interface FindingActors {
	attackerProfile?: string;
	baselineProfile?: string;
	resourceOwnerProfile?: string;
}

export interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

export interface ParameterTarget {
	name: string;
	value: string;
	location: 'query' | 'body' | 'cookie' | 'header' | 'path';
}

export interface VulnFinding {
	type: string;
	severity: VulnSeverity;
	title: string;
	url: string;
	parameter?: string;
	payload: string;
	evidence: string;
	confidence: number;
	details: string;
	/** Evidence lifecycle. Scanner output should normally begin as a candidate. */
	state?: FindingState;
	/** Structured provenance for downstream agents/reporting. */
	source?: FindingSource;
	/** Identities involved in authorization/business-logic comparisons. */
	actors?: FindingActors;
}

// ---------------------------------------------------------------------------
// SQLi Scanner
// ---------------------------------------------------------------------------

export interface SqliScanCommandOptions {
	url?: string;
	parameters?: ParameterTarget[];
	crawlResultFile?: string;
	techniques?: Array<'error' | 'time-blind' | 'boolean-blind'>;
	dbms?: Array<'mysql' | 'postgresql' | 'mssql' | 'sqlite' | 'oracle'>;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface SqliScanResult {
	generatedAt: string;
	target: string;
	parametersScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// XSS Scanner
// ---------------------------------------------------------------------------

export interface XssScanCommandOptions {
	url?: string;
	parameters?: ParameterTarget[];
	crawlResultFile?: string;
	contexts?: Array<'html' | 'attribute' | 'javascript' | 'url'>;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface XssScanResult {
	generatedAt: string;
	target: string;
	parametersScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// LFI Scanner
// ---------------------------------------------------------------------------

export interface LfiScanCommandOptions {
	url?: string;
	parameters?: ParameterTarget[];
	crawlResultFile?: string;
	osTargets?: Array<'linux' | 'windows'>;
	encodings?: Array<'plain' | 'url-encoded' | 'double-encoded' | 'null-byte' | 'php-wrapper'>;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface LfiScanResult {
	generatedAt: string;
	target: string;
	parametersScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// SSTI Scanner
// ---------------------------------------------------------------------------

export interface SstiScanCommandOptions {
	url?: string;
	parameters?: ParameterTarget[];
	crawlResultFile?: string;
	engines?: Array<'jinja2' | 'twig' | 'freemarker' | 'velocity' | 'smarty' | 'mako' | 'spel' | 'ognl'>;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface SstiScanResult {
	generatedAt: string;
	target: string;
	parametersScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Secrets Scanner
// ---------------------------------------------------------------------------

export interface SecretsScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	content?: string;
	verify?: boolean;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface SecretsScanResult {
	generatedAt: string;
	target: string;
	sourcesScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// CORS Scanner
// ---------------------------------------------------------------------------

export interface CorsScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface CorsScanResult {
	generatedAt: string;
	target: string;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Security Headers Scanner
// ---------------------------------------------------------------------------

export interface HeadersScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface HeadersScanResult {
	generatedAt: string;
	target: string;
	findings: VulnFinding[];
	presentHeaders: string[];
	missingHeaders: string[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// DOM XSS Scanner
// ---------------------------------------------------------------------------

export interface DomxssScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface DomxssScanResult {
	generatedAt: string;
	target: string;
	jsFilesAnalyzed: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Hidden Params Discovery
// ---------------------------------------------------------------------------

export interface ParamsScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	wordlist?: string[];
	concurrency?: number;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface ParamsScanResult {
	generatedAt: string;
	target: string;
	paramsTested: number;
	findings: VulnFinding[];
	discoveredParams: string[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Open Redirect Scanner
// ---------------------------------------------------------------------------

export interface RedirectScanCommandOptions {
	url?: string;
	parameters?: ParameterTarget[];
	crawlResultFile?: string;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface RedirectScanResult {
	generatedAt: string;
	target: string;
	parametersScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// JWT Attack Scanner
// ---------------------------------------------------------------------------

export interface JwtScanCommandOptions {
	token?: string;
	url?: string;
	crawlResultFile?: string;
	attacks?: Array<'decode' | 'none-alg' | 'weak-secret' | 'claim-tamper'>;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface JwtScanResult {
	generatedAt: string;
	target: string;
	decoded?: { header: Record<string, unknown>; payload: Record<string, unknown> };
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// GraphQL Scanner
// ---------------------------------------------------------------------------

export interface GraphqlScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	attacks?: Array<'introspection' | 'injection' | 'batching' | 'field-enum'>;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface GraphqlScanResult {
	generatedAt: string;
	target: string;
	introspectionEnabled: boolean;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// SSRF Scanner
// ---------------------------------------------------------------------------

export interface SsrfScanCommandOptions {
	url?: string;
	parameters?: ParameterTarget[];
	crawlResultFile?: string;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface SsrfScanResult {
	generatedAt: string;
	target: string;
	parametersScanned: number;
	findings: VulnFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Auto Scanner
// ---------------------------------------------------------------------------

export interface AutoScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	scanners?: Array<'sqli' | 'xss' | 'lfi' | 'ssti' | 'secrets' | 'cors' | 'headers' | 'domxss' | 'params' | 'redirect' | 'jwt' | 'graphql' | 'ssrf'>;
	parameters?: ParameterTarget[];
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface AutoScanResult {
	generatedAt: string;
	target: string;
	scannersRun: string[];
	totalFindings: number;
	findings: VulnFinding[];
	scannerResults: Record<string, { findings: number; elapsedMs: number }>;
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// SQLi Extractor (exploitation)
// ---------------------------------------------------------------------------

export interface SqliExtractCommandOptions {
	url?: string;
	parameter?: { name: string; location: 'query' | 'body' };
	dbms?: string;
	technique?: 'union' | 'boolean-blind' | 'time-blind';
	maxRows?: number;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

// ---------------------------------------------------------------------------
// XSS Exploiter (exploitation)
// ---------------------------------------------------------------------------

export interface XssExploitCommandOptions {
	url?: string;
	parameter?: string;
	context?: 'html' | 'attribute' | 'javascript' | 'url';
	callbackUrl?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

// ---------------------------------------------------------------------------
// LFI Exploiter (exploitation)
// ---------------------------------------------------------------------------

export interface LfiExploitCommandOptions {
	url?: string;
	parameter?: { name: string; location: 'query' | 'body' };
	traversalPrefix?: string;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

// ---------------------------------------------------------------------------
// Crawl Result (for reading crawl output files)
// ---------------------------------------------------------------------------

export interface CrawlResultFile {
	discovered: Array<{ url: string; method: string }>;
	forms: Array<{
		action: string;
		method: string;
		inputs: Array<{ name: string; type: string; value?: string }>;
	}>;
	parameters: Array<{
		name: string;
		location: string;
		url: string;
		method: string;
	}>;
}

// ---------------------------------------------------------------------------
// IDOR Scanner (Scylla 2.0)
// ---------------------------------------------------------------------------

export type IdorStrategy = 'known-id-swap' | 'sequential' | 'uuid-swap' | 'zero-id' | 'remove-param' | 'method-swap';
export type IdorCompareField = 'body_hash' | 'status_code' | 'content_length';
export type IdorOwnershipSource = 'knownIds' | 'heuristic';

export interface IdorScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	/** Auth profile names. profiles[0] is attacker; profiles[1] is victim/baseline. */
	profiles?: string[];
	strategies?: IdorStrategy[];
	compareFields?: IdorCompareField[];
	/** Regex patterns to detect sensitive data in responses */
	sensitivePatterns?: string[];
	/**
	 * Resource identifiers known to belong to each auth profile. When a victim
	 * profile has known IDs, Scylla adds deterministic known-id-swap tests before
	 * heuristic mutations. IDs may be numeric, UUID, slug-like, etc.
	 */
	knownIds?: Record<string, string[]>;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface IdorFinding extends VulnFinding {
	/** Original URL that established the endpoint shape. */
	originalUrl: string;
	/** Exact victim-resource URL replayed under both profiles. */
	testedUrl: string;
	strategy: IdorStrategy;
	/** Victim/baseline response metadata for testedUrl. Kept under the legacy name for compatibility. */
	originalResponse: { statusCode: number; bodyHash: string; contentLength: number };
	/** Attacker response metadata for the same testedUrl. */
	modifiedResponse: { statusCode: number; bodyHash: string; contentLength: number };
	/** Optional attacker response metadata on originalUrl. */
	attackerBaselineResponse?: { statusCode: number; bodyHash: string; contentLength: number };
	sensitiveDataFound: string[];
	attackerProfile: string;
	baselineProfile: string;
	resourceOwnerProfile?: string;
	ownershipSource: IdorOwnershipSource;
}

export interface IdorScanResult {
	generatedAt: string;
	target: string;
	endpointsTested: number;
	strategiesUsed: IdorStrategy[];
	findings: IdorFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Privilege Escalation Scanner (Scylla 2.0)
// ---------------------------------------------------------------------------

export interface PrivescScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	/** High-privilege profile name (e.g., 'admin') */
	highPrivProfile?: string;
	/** Low-privilege profile name (e.g., 'user') */
	lowPrivProfile?: string;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface PrivescFinding extends VulnFinding {
	/** The high-privilege endpoint that was compared. */
	adminEndpoint: string;
	method: string;
	adminResponse: { statusCode: number; contentLength: number };
	lowPrivResponse: { statusCode: number; contentLength: number };
	/** Response-level equivalence only; not by itself proof of authorization impact. */
	fullAccess: boolean;
}

export interface PrivescScanResult {
	generatedAt: string;
	target: string;
	adminEndpointsTested: number;
	findings: PrivescFinding[];
	elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Mass Assignment Scanner (Scylla 2.0)
// ---------------------------------------------------------------------------

export type MassAssignCategory = 'role-escalation' | 'financial' | 'verification-bypass' | 'password-change';

export interface MassAssignScanCommandOptions {
	url?: string;
	crawlResultFile?: string;
	/** Categories of payloads to test */
	categories?: MassAssignCategory[];
	/** Custom extra fields to inject */
	customFields?: Record<string, unknown>;
	/** Auth profile to use */
	profileName?: string;
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	createFindings?: boolean;
}

export interface MassAssignFinding extends VulnFinding {
	/** Endpoint where mass assignment was detected */
	endpoint: string;
	/** HTTP method */
	method: string;
	/** The extra field(s) that were accepted */
	injectedFields: Record<string, unknown>;
	/** Category of the payload */
	category: MassAssignCategory;
	/** Original response (without extra fields) */
	originalResponse: { statusCode: number; bodySnippet: string };
	/** Modified response (with extra fields) */
	modifiedResponse: { statusCode: number; bodySnippet: string };
}

export interface MassAssignScanResult {
	generatedAt: string;
	target: string;
	endpointsTested: number;
	findings: MassAssignFinding[];
	elapsedMs: number;
}
