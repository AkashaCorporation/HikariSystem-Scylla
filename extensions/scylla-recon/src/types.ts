/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export type OutputFormat = 'json' | 'md';

export interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

// ---------------------------------------------------------------------------
// Port Scanner
// ---------------------------------------------------------------------------

export interface PortScanCommandOptions {
	target?: string;
	ports?: string;
	timeoutMs?: number;
	concurrency?: number;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export interface PortScanResult {
	generatedAt: string;
	target: string;
	portsScanned: number;
	openPorts: OpenPort[];
	closedCount: number;
	filteredCount: number;
	elapsedMs: number;
}

export interface OpenPort {
	port: number;
	state: 'open';
	service: string;
	banner?: string;
	protocol: 'tcp';
}

// ---------------------------------------------------------------------------
// Web Crawler
// ---------------------------------------------------------------------------

export interface CrawlCommandOptions {
	url?: string;
	maxDepth?: number;
	maxPages?: number;
	scope?: 'host' | 'domain' | 'path';
	delayMs?: number;
	timeoutMs?: number;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export interface CrawlResult {
	generatedAt: string;
	seedUrl: string;
	pagesVisited: number;
	discovered: DiscoveredEndpoint[];
	forms: DiscoveredForm[];
	parameters: DiscoveredParameter[];
	jsRoutes: string[];
	externalLinks: string[];
	redirects: CrawlRedirect[];
	elapsedMs: number;
}

export interface CrawlRedirect {
	from: string;
	to: string;
	statusCode: number;
	inScope: boolean;
}

export interface DiscoveredEndpoint {
	url: string;
	method: string;
	statusCode: number;
	contentType: string;
	depth: number;
}

export interface DiscoveredForm {
	action: string;
	method: string;
	inputs: FormInput[];
	pageUrl: string;
}

export interface FormInput {
	name: string;
	type: string;
	value?: string;
}

export interface DiscoveredParameter {
	name: string;
	location: 'query' | 'body' | 'path' | 'cookie';
	url: string;
	method: string;
}

// ---------------------------------------------------------------------------
// Directory Fuzzer
// ---------------------------------------------------------------------------

export interface DirFuzzCommandOptions {
	url?: string;
	wordlist?: 'common' | 'medium' | string;
	extensions?: string[];
	concurrency?: number;
	delayMs?: number;
	timeoutMs?: number;
	followRedirects?: boolean;
	filterStatus?: number[];
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export interface DirFuzzResult {
	generatedAt: string;
	baseUrl: string;
	wordlistUsed: string;
	totalRequests: number;
	discovered: DirFuzzHit[];
	elapsedMs: number;
}

export interface DirFuzzHit {
	path: string;
	url: string;
	statusCode: number;
	contentLength: number;
	contentType: string;
	redirectUrl?: string;
}

// ---------------------------------------------------------------------------
// Tech Detection
// ---------------------------------------------------------------------------

export interface TechDetectCommandOptions {
	url?: string;
	timeoutMs?: number;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export interface TechDetectResult {
	generatedAt: string;
	url: string;
	technologies: DetectedTechnology[];
	headers: Record<string, string>;
	elapsedMs: number;
}

export interface DetectedTechnology {
	name: string;
	category: string;
	version?: string;
	confidence: number;
	evidence: string;
}

// ---------------------------------------------------------------------------
// WAF Detection
// ---------------------------------------------------------------------------

export interface WafDetectCommandOptions {
	url?: string;
	headers?: Record<string, string>;
	cookie?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export interface WafDetectResult {
	generatedAt: string;
	target: string;
	wafDetected: boolean;
	wafName: string | null;
	confidence: number;
	evidence: string[];
	bypassSuggestions: string[];
	elapsedMs: number;
}
