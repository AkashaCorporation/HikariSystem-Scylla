/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as dns from 'dns';

/**
 * Internal DNS resolver for Scylla.
 *
 * Resolves hostnames to IP addresses using an in-memory map, with support
 * for exact matches and wildcard patterns (e.g. `*.htb`).  This allows the
 * pipeline to work with CTF/HTB virtual-host names **without** touching the
 * system hosts file (`/etc/hosts` or `C:\Windows\System32\drivers\etc\hosts`),
 * which would require elevated privileges and does not support wildcards.
 *
 * All HTTP requests made via `scylla.http.sendHeadless` automatically go
 * through this resolver.
 */
export class HostResolver {

	private readonly exactHosts = new Map<string, string>();
	private readonly wildcardHosts = new Map<string, string>();

	// -----------------------------------------------------------------------
	// Public API
	// -----------------------------------------------------------------------

	/** Register a single hostname → ip mapping (supports `*.htb` wildcards). */
	set(hostname: string, ip: string): void {
		if (hostname.startsWith('*.')) {
			this.wildcardHosts.set(hostname.toLowerCase(), ip);
		} else {
			this.exactHosts.set(hostname.toLowerCase(), ip);
		}
	}

	/** Bulk-register from a `Record<hostname, ip>`. */
	setAll(hosts: Record<string, string>): void {
		for (const [hostname, ip] of Object.entries(hosts)) {
			this.set(hostname, ip);
		}
	}

	/** Remove a previously registered hostname. */
	delete(hostname: string): boolean {
		const lower = hostname.toLowerCase();
		return this.exactHosts.delete(lower) || this.wildcardHosts.delete(lower);
	}

	/** Resolve a hostname using the internal map.  Returns `undefined` if no match. */
	resolve(hostname: string): string | undefined {
		const lower = hostname.toLowerCase();

		// 1. Exact match
		const exact = this.exactHosts.get(lower);
		if (exact) { return exact; }

		// 2. Wildcard match  (*.htb  matches  facts.htb, admin.facts.htb, etc.)
		for (const [pattern, ip] of this.wildcardHosts) {
			const suffix = pattern.slice(1); // "*.htb" → ".htb"
			if (lower.endsWith(suffix) || lower === suffix.slice(1)) {
				// lower === suffix.slice(1) handles "htb" matching "*.htb" (unlikely but safe)
				return ip;
			}
		}

		return undefined;
	}

	/** Check whether we have any registrations at all. */
	get isEmpty(): boolean {
		return this.exactHosts.size === 0 && this.wildcardHosts.size === 0;
	}

	get size(): number {
		return this.exactHosts.size + this.wildcardHosts.size;
	}

	/** Return all entries as a plain object (for debugging / status). */
	getAll(): Record<string, string> {
		const result: Record<string, string> = {};
		for (const [k, v] of this.exactHosts) { result[k] = v; }
		for (const [k, v] of this.wildcardHosts) { result[k] = v; }
		return result;
	}

	/** Clear all registrations. */
	clear(): void {
		this.exactHosts.clear();
		this.wildcardHosts.clear();
	}

	// -----------------------------------------------------------------------
	// Node.js DNS lookup function  (drop-in for http.request `lookup` option)
	// -----------------------------------------------------------------------

	/**
	 * Custom `lookup` function compatible with `http.request({ lookup })`.
	 *
	 * If the hostname is in our internal map, resolves immediately without
	 * touching the OS DNS stack.  Otherwise falls back to the standard
	 * `dns.lookup()`.
	 */
	readonly lookup = (
		hostname: string,
		options: dns.LookupOptions,
		callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family: number) => void,
	): void => {
		const ip = this.resolve(hostname);
		if (ip) {
			const family = ip.includes(':') ? 6 : 4;
			if (options.all) {
				// When `all: true`, callback expects an array of LookupAddress
				(callback as (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void)(
					null, [{ address: ip, family }]
				);
			} else {
				(callback as (err: NodeJS.ErrnoException | null, address: string, family: number) => void)(
					null, ip, family
				);
			}
			return;
		}
		// Fallback to system DNS
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- dns.lookup overloads are complex
		(dns.lookup as any)(hostname, options, callback);
	};
}

/** Global singleton — shared by all scylla-http requests. */
export const hostResolver = new HostResolver();
