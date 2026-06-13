/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';

/**
 * Scylla Scope + Rate-Limit Governor (shared safety layer).
 *
 * A web-pentest IDE hits LIVE targets. Without guardrails it can (a) send
 * traffic OUTSIDE the authorized engagement scope (a bounty-scope violation),
 * (b) hammer a target with no throttle (instant rate-limit ban / accidental
 * DoS), and (c) auto-fire scans the moment a `.scylla_job.json` appears. This
 * module is the single primitive that closes all three.
 *
 * Because Scylla's extensions run in SEPARATE extension hosts, they cannot
 * share a runtime object. The shared source of truth is therefore VS Code
 * settings (the `scylla.governor.*` namespace), which every host reads. This
 * file is intentionally SOURCE-DUPLICATED into each consumer extension
 * (scylla-http, scylla-jobs, scylla-auth); keep the copies identical.
 *
 * Scope matching mirrors `hostResolver`: an exact (case-insensitive) host
 * match plus `*.suffix` wildcards (so `*.htb` covers `facts.htb`,
 * `admin.facts.htb`, ...).
 */

export interface GovernorConfig {
	scope: string[];
	enforceScope: boolean;
	rateLimitPerSec: number;
	maxConcurrency: number;
	consent: boolean;
}

/** Thrown when a request targets a host outside the configured scope. */
export class ScopeViolationError extends Error {
	constructor(public readonly host: string) {
		super(
			`Scylla governor: host "${host}" is out of scope. ` +
			`Add it to the "scylla.governor.scope" setting (supports *.wildcards), ` +
			`or set "scylla.governor.enforceScope" to false to disable enforcement.`
		);
		this.name = 'ScopeViolationError';
	}
}

const CONFIG_NS = 'scylla.governor';

export class ScopeGovernor {

	/** Ephemeral, per-run scope seeded by a job run (NOT persisted to settings). */
	private readonly runtimeScope = new Set<string>();

	/** Per-host token buckets for rate limiting. */
	private readonly buckets = new Map<string, { tokens: number; last: number }>();
	private static readonly MAX_BUCKETS = 512;

	/** Global concurrency state. */
	private inFlight = 0;
	private readonly waiters: Array<() => void> = [];

	// -----------------------------------------------------------------------
	// Config (read live so settings changes take effect immediately)
	// -----------------------------------------------------------------------

	getConfig(): GovernorConfig {
		const c = vscode.workspace.getConfiguration(CONFIG_NS);
		return {
			scope: normalizePatterns(c.get<string[]>('scope', [])),
			enforceScope: c.get<boolean>('enforceScope', true),
			rateLimitPerSec: Math.max(0, Number(c.get<number>('rateLimitPerSec', 0)) || 0),
			maxConcurrency: Math.max(0, Number(c.get<number>('maxConcurrency', 0)) || 0),
			consent: c.get<boolean>('consent', false) === true
		};
	}

	// -----------------------------------------------------------------------
	// Scope
	// -----------------------------------------------------------------------

	/** Seed ephemeral scope patterns for the current run (e.g. from `job.target`). */
	seedScope(patterns: string[]): void {
		for (const p of normalizePatterns(patterns)) {
			this.runtimeScope.add(p);
		}
	}

	/** Drop all ephemeral (run-seeded) scope. Settings-based scope is untouched. */
	clearRuntimeScope(): void {
		this.runtimeScope.clear();
	}

	/** The union of settings scope and ephemeral run-seeded scope. */
	getEffectiveScope(): string[] {
		const cfg = this.getConfig();
		return Array.from(new Set([...cfg.scope, ...this.runtimeScope]));
	}

	/**
	 * Is the host in scope? Permissive (true) when enforcement is off OR no
	 * scope is configured at all (back-compat). Otherwise the host must match.
	 */
	isInScope(hostname: string): boolean {
		if (!this.getConfig().enforceScope) { return true; }
		const patterns = this.getEffectiveScope();
		if (patterns.length === 0) { return true; }
		return matchesAny(hostname, patterns);
	}

	/** Throws {@link ScopeViolationError} if the URL/host is out of scope. */
	assertInScope(rawUrlOrHost: string): void {
		const host = extractHost(rawUrlOrHost);
		if (!host) {
			// Unparseable host: fail-CLOSED while scope is actively enforced (an
			// allowlist that defaults to ALLOW on parser disagreement is a bypass).
			// When no scope is configured we stay permissive for back-compat.
			const cfg = this.getConfig();
			if (cfg.enforceScope && this.getEffectiveScope().length > 0) {
				throw new ScopeViolationError(String(rawUrlOrHost ?? ''));
			}
			return;
		}
		if (!this.isInScope(host)) {
			throw new ScopeViolationError(host);
		}
	}

	// -----------------------------------------------------------------------
	// Consent (gates AUTOMATIC job runs)
	// -----------------------------------------------------------------------

	isAutoRunAllowed(): boolean {
		return this.getConfig().consent === true;
	}

	// -----------------------------------------------------------------------
	// Rate limit + concurrency
	// -----------------------------------------------------------------------

	/**
	 * Wait for a per-host rate token, then take a global concurrency slot.
	 * Token-first so the concurrency cap bounds only requests actually in
	 * flight, not requests parked waiting for their rate turn.
	 */
	async acquire(hostname: string): Promise<void> {
		await this.awaitToken(hostname);
		await this.acquireSlot();
	}

	/** Release a previously-acquired concurrency slot. Always call in a finally. */
	release(_hostname?: string): void {
		this.releaseSlot();
	}

	/** Convenience: scope-check + acquire, run `fn`, always release. */
	async runGated<T>(rawUrl: string, fn: () => Promise<T>): Promise<T> {
		this.assertInScope(rawUrl);
		const host = extractHost(rawUrl) ?? '';
		await this.acquire(host);
		try {
			return await fn();
		} finally {
			this.release(host);
		}
	}

	// -----------------------------------------------------------------------
	// Internals
	// -----------------------------------------------------------------------

	private acquireSlot(): Promise<void> {
		const cap = this.getConfig().maxConcurrency;
		if (cap <= 0 || this.inFlight < cap) {
			this.inFlight++;
			return Promise.resolve();
		}
		return new Promise<void>(resolve => {
			this.waiters.push(() => {
				this.inFlight++;
				resolve();
			});
		});
	}

	private releaseSlot(): void {
		if (this.inFlight > 0) { this.inFlight--; }
		// Wake as many waiters as the CURRENT cap allows. Re-reading the cap each
		// pass means a live decrease of maxConcurrency holds waiters back (no
		// over-admission past the lowered cap), while a live increase admits the
		// backlog. Each woken waiter increments inFlight synchronously, so the
		// loop sees the updated count.
		for (; ;) {
			const cap = this.getConfig().maxConcurrency;
			if (cap > 0 && this.inFlight >= cap) { break; }
			const next = this.waiters.shift();
			if (!next) { break; }
			next();
		}
	}

	private async awaitToken(hostname: string): Promise<void> {
		const rate = this.getConfig().rateLimitPerSec;
		if (rate <= 0) { return; }
		// Burst capacity must be at least 1 token, INDEPENDENT of the refill rate.
		// Otherwise a fractional rate (0 < rate < 1) caps tokens below 1 forever,
		// so `tokens >= 1` never holds and this loop never terminates (the request
		// would hang). With capacity >= 1, a sub-1 rate still works: one token
		// accrues every 1/rate seconds (e.g. rate=0.5 -> one request every 2s).
		const capacity = Math.max(1, rate);
		// Loop until a token is available, refilling on each pass.
		for (; ;) {
			const now = Date.now();
			let bucket = this.buckets.get(hostname);
			if (!bucket) {
				this.evictIfNeeded();
				bucket = { tokens: capacity, last: now };
				this.buckets.set(hostname, bucket);
			}
			const elapsedSec = (now - bucket.last) / 1000;
			bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * rate);
			bucket.last = now;
			if (bucket.tokens >= 1) {
				bucket.tokens -= 1;
				return;
			}
			const waitMs = Math.max(1, Math.ceil(((1 - bucket.tokens) / rate) * 1000));
			await delay(waitMs);
		}
	}

	private evictIfNeeded(): void {
		if (this.buckets.size < ScopeGovernor.MAX_BUCKETS) { return; }
		let oldestKey: string | undefined;
		let oldest = Infinity;
		for (const [k, v] of this.buckets) {
			if (v.last < oldest) { oldest = v.last; oldestKey = k; }
		}
		if (oldestKey) { this.buckets.delete(oldestKey); }
	}
}

// ---------------------------------------------------------------------------
// Module-private helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
	return new Promise<void>(resolve => setTimeout(resolve, ms));
}

/**
 * Canonicalize a host for comparison: lowercase, strip a single trailing DNS
 * root dot ("target.com." === "target.com"), and unwrap an IPv6 literal's
 * brackets ("[::1]" === "::1"), so an extracted host and a scope pattern always
 * share one representation.
 */
function canonicalHost(value: string): string {
	let s = (value ?? '').trim().toLowerCase();
	if (!s) { return ''; }
	if (s.startsWith('[') && s.endsWith(']')) { s = s.slice(1, -1); }
	if (s.length > 1 && s.endsWith('.')) { s = s.slice(0, -1); }
	return s;
}

/** Does this look like a bracketless IPv6 literal (2 or more colons)? */
function isBareIpv6(s: string): boolean {
	return (s.match(/:/g) || []).length >= 2;
}

/** Reduce raw scope entries (host, host:port, IPv6 literal, or full URL) to canonical host patterns. */
function normalizePatterns(patterns: string[] | undefined): string[] {
	if (!Array.isArray(patterns)) { return []; }
	const out: string[] = [];
	for (const raw of patterns) {
		if (typeof raw !== 'string') { continue; }
		const p = raw.trim().toLowerCase();
		if (!p) { continue; }
		if (p.includes('://')) {
			const h = extractHost(p);
			if (h) { out.push(h); }
			continue;
		}
		// Wildcard pattern: keep it (canonicalized for the trailing-dot case).
		if (p.startsWith('*.')) { out.push(canonicalHost(p)); continue; }
		// Bracketed IPv6 literal, optionally with :port -> keep "[...]" then canonicalize.
		if (p.startsWith('[')) {
			const close = p.indexOf(']');
			if (close !== -1) { out.push(canonicalHost(p.slice(0, close + 1))); continue; }
		}
		// Bare IPv6 literal (no brackets, no port) -> keep the whole thing.
		if (isBareIpv6(p)) { out.push(canonicalHost(p)); continue; }
		// Plain host or host:port -> strip any path then any port.
		const host = p.split('/')[0].split(':')[0];
		if (host) { out.push(canonicalHost(host)); }
	}
	return out;
}

function matchesAny(hostname: string, patterns: string[]): boolean {
	const host = canonicalHost(hostname);
	for (const pattern of patterns) {
		if (pattern.startsWith('*.')) {
			const suffix = pattern.slice(1); // "*.htb" -> ".htb"
			if (host.endsWith(suffix) || host === suffix.slice(1)) { return true; }
		} else if (host === pattern) {
			return true;
		}
	}
	return false;
}

function extractHost(rawUrlOrHost: string): string | undefined {
	const v = (rawUrlOrHost ?? '').trim();
	if (!v) { return undefined; }
	try {
		const withScheme = v.includes('://') ? v : `http://${v}`;
		const host = new URL(withScheme).hostname;
		return host ? canonicalHost(host) : undefined;
	} catch {
		// Bare-host fallback (new URL rejects bracketless IPv6 and some authorities).
		let bare = v.toLowerCase();
		if (bare.startsWith('[')) {
			const close = bare.indexOf(']');
			if (close !== -1) { return canonicalHost(bare.slice(0, close + 1)); }
		}
		if (isBareIpv6(bare)) { return canonicalHost(bare); }
		bare = bare.split('/')[0].split(':')[0];
		return bare ? canonicalHost(bare) : undefined;
	}
}

/** Process-global singleton (one per extension host). */
export const governor = new ScopeGovernor();
