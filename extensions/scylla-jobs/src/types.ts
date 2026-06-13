/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface PipelineOutputOptions {
	path?: string;
	format?: 'json' | 'md';
}

export interface PipelineStep {
	cmd: string;
	args?: Record<string, unknown>;
	output?: PipelineOutputOptions;
	continueOnError?: boolean;
	timeoutMs?: number;
	expectOutput?: boolean;
	retryCount?: number;
	retryDelayMs?: number;
}

export interface ScyllaJobFile {
	target: string;
	outDir: string;
	steps: PipelineStep[];
	quiet?: boolean;
	variables?: Record<string, string>;
	/**
	 * Custom hostname → IP mappings resolved internally by `scylla-http`
	 * without touching the system hosts file.  Supports wildcards:
	 *
	 * ```json
	 * { "hosts": { "facts.htb": "10.129.10.5", "*.htb": "10.129.10.5" } }
	 * ```
	 */
	hosts?: Record<string, string>;
	/**
	 * Additional in-scope host patterns for this engagement, beyond `target`.
	 * Published to the governor so the egress layer constrains all traffic to
	 * the authorized scope. Supports exact hosts and `*.wildcard` patterns:
	 *
	 * ```json
	 * { "scope": ["api.target.com", "*.target.com"] }
	 * ```
	 *
	 * When omitted, scope is derived from `target` (and any `hosts` keys).
	 */
	scope?: string[];
	/**
	 * Authentication profiles for authenticated scanning (Scylla 2.0).
	 * Supports multiple profiles for multi-role testing (e.g., IDOR, PrivEsc).
	 *
	 * ```json
	 * {
	 *   "auth": {
	 *     "profiles": {
	 *       "admin": { "type": "form", "loginUrl": "...", "fields": { ... } },
	 *       "user":  { "type": "form", "loginUrl": "...", "fields": { ... } }
	 *     },
	 *     "loginAll": true
	 *   }
	 * }
	 * ```
	 */
	auth?: JobAuthConfig;
}

export interface JobAuthConfig {
	/** Named auth profiles. Keys are profile names (e.g., "admin", "user"). */
	profiles: Record<string, JobAuthProfile>;
	/** If true, login all profiles at pipeline start. Default: true. */
	loginAll?: boolean;
	/** If true, automatically refresh sessions on 401/403. Default: true. */
	autoRefresh?: boolean;
}

export interface JobAuthProfile {
	type: 'form' | 'api' | 'oauth2-client-credentials' | 'bearer' | 'basic' | 'none';
	loginUrl?: string;
	fields?: Record<string, string>;
	csrfSelector?: string;
	csrfHeader?: string;
	successIndicator?: string;
	sessionCookie?: string;
	sessionCheckUrl?: string;
	cookie?: string;
	authorization?: string;
	headers?: Record<string, string>;
	oauth?: {
		tokenUrl: string;
		clientId: string;
		clientSecret: string;
		scopes?: string[];
	};
}

export interface PipelineStepStatus {
	index: number;
	cmd: string;
	resolvedCmd: string;
	status: 'ok' | 'error' | 'skipped' | 'timeout';
	startedAt: string;
	finishedAt: string;
	durationMs: number;
	attemptCount: number;
	outputPath?: string;
	error?: string;
}

export interface PipelineRunStatus {
	jobFile: string;
	target: string;
	outDir: string;
	status: 'running' | 'ok' | 'error';
	startedAt: string;
	finishedAt?: string;
	totalSteps: number;
	completedSteps: number;
	failedSteps: number;
	steps: PipelineStepStatus[];
}

export interface CommandCapability {
	headless: boolean;
	defaultTimeoutMs: number;
	validateOutput: boolean;
	reason?: string;
}
