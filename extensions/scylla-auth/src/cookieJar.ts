/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { ParsedCookie } from './types';

// ---------------------------------------------------------------------------
// Cookie Jar — Persistent cookie storage across pipeline steps
// ---------------------------------------------------------------------------

export class CookieJar {

	private cookies: Map<string, ParsedCookie> = new Map();

	/**
	 * Parse "Set-Cookie" headers from an HTTP response and store them.
	 * Handles multiple Set-Cookie headers (array or single string).
	 */
	ingestSetCookieHeaders(
		headers: Record<string, string | string[] | undefined>,
		requestUrl: string,
	): ParsedCookie[] {
		const setCookies = this.extractSetCookieValues(headers);
		const parsed: ParsedCookie[] = [];

		for (const raw of setCookies) {
			const cookie = this.parseSetCookie(raw, requestUrl);
			if (cookie) {
				this.cookies.set(this.cookieKey(cookie), cookie);
				parsed.push(cookie);
			}
		}

		return parsed;
	}

	/**
	 * Get all cookies valid for the given URL, serialized as a Cookie header value.
	 * Example: "session_id=abc123; _token=xyz789"
	 */
	getCookieHeader(url: string): string {
		const targetUrl = this.safeParseUrl(url);
		if (!targetUrl) { return ''; }

		const validCookies: ParsedCookie[] = [];

		for (const cookie of this.cookies.values()) {
			if (this.isExpired(cookie)) { continue; }
			if (!this.domainMatches(cookie, targetUrl.hostname)) { continue; }
			if (!this.pathMatches(cookie, targetUrl.pathname)) { continue; }
			if (cookie.secure && targetUrl.protocol !== 'https:') { continue; }
			validCookies.push(cookie);
		}

		return validCookies
			.map(c => `${c.name}=${c.value}`)
			.join('; ');
	}

	/**
	 * Get all cookies as an array.
	 */
	getAllCookies(): ParsedCookie[] {
		return Array.from(this.cookies.values()).filter(c => !this.isExpired(c));
	}

	/**
	 * Get cookie count.
	 */
	get size(): number {
		return this.cookies.size;
	}

	/**
	 * Check if a specific cookie exists by name.
	 */
	hasCookie(name: string): boolean {
		for (const cookie of this.cookies.values()) {
			if (cookie.name === name && !this.isExpired(cookie)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get a specific cookie value by name.
	 */
	getCookieValue(name: string): string | undefined {
		for (const cookie of this.cookies.values()) {
			if (cookie.name === name && !this.isExpired(cookie)) {
				return cookie.value;
			}
		}
		return undefined;
	}

	/**
	 * Add a cookie directly (e.g., from a static cookie string).
	 */
	addCookie(cookie: ParsedCookie): void {
		this.cookies.set(this.cookieKey(cookie), cookie);
	}

	/**
	 * Parse a raw "Cookie: ..." header string and import all cookies.
	 * Used when the user provides a static cookie string.
	 */
	importCookieString(cookieString: string, domain?: string): void {
		const pairs = cookieString.split(';').map(p => p.trim()).filter(p => p.length > 0);
		for (const pair of pairs) {
			const eqIndex = pair.indexOf('=');
			if (eqIndex < 0) { continue; }
			const name = pair.slice(0, eqIndex).trim();
			const value = pair.slice(eqIndex + 1).trim();
			if (name.length === 0) { continue; }
			this.addCookie({ name, value, domain, path: '/' });
		}
	}

	/**
	 * Clear all cookies.
	 */
	clear(): void {
		this.cookies.clear();
	}

	/**
	 * Clear cookies for a specific domain.
	 */
	clearDomain(domain: string): void {
		for (const [key, cookie] of this.cookies) {
			if (cookie.domain === domain || cookie.domain === `.${domain}`) {
				this.cookies.delete(key);
			}
		}
	}

	// -----------------------------------------------------------------------
	// Set-Cookie Parser
	// -----------------------------------------------------------------------

	private parseSetCookie(raw: string, requestUrl: string): ParsedCookie | null {
		const parts = raw.split(';').map(p => p.trim());
		if (parts.length === 0) { return null; }

		// First part is name=value
		const firstPart = parts[0];
		const eqIndex = firstPart.indexOf('=');
		if (eqIndex < 0) { return null; }

		const name = firstPart.slice(0, eqIndex).trim();
		const value = firstPart.slice(eqIndex + 1).trim();
		if (name.length === 0) { return null; }

		const url = this.safeParseUrl(requestUrl);
		const cookie: ParsedCookie = {
			name,
			value,
			domain: url?.hostname,
			path: '/',
		};

		// Parse attributes
		for (let i = 1; i < parts.length; i++) {
			const attr = parts[i];
			const attrEq = attr.indexOf('=');
			const attrName = (attrEq >= 0 ? attr.slice(0, attrEq) : attr).trim().toLowerCase();
			const attrValue = attrEq >= 0 ? attr.slice(attrEq + 1).trim() : '';

			switch (attrName) {
				case 'domain':
					cookie.domain = attrValue.startsWith('.') ? attrValue : attrValue;
					break;
				case 'path':
					cookie.path = attrValue || '/';
					break;
				case 'expires':
					try { cookie.expires = new Date(attrValue); } catch { /* ignore */ }
					break;
				case 'max-age': {
					const seconds = parseInt(attrValue, 10);
					if (!isNaN(seconds)) {
						cookie.expires = new Date(Date.now() + seconds * 1000);
					}
					break;
				}
				case 'httponly':
					cookie.httpOnly = true;
					break;
				case 'secure':
					cookie.secure = true;
					break;
				case 'samesite':
					cookie.sameSite = attrValue.toLowerCase() as ParsedCookie['sameSite'];
					break;
			}
		}

		return cookie;
	}

	// -----------------------------------------------------------------------
	// Cookie Matching
	// -----------------------------------------------------------------------

	private cookieKey(cookie: ParsedCookie): string {
		return `${cookie.domain ?? ''}|${cookie.path ?? '/'}|${cookie.name}`;
	}

	private isExpired(cookie: ParsedCookie): boolean {
		if (!cookie.expires) { return false; }
		return cookie.expires.getTime() < Date.now();
	}

	private domainMatches(cookie: ParsedCookie, hostname: string): boolean {
		if (!cookie.domain) { return true; } // No domain restriction
		const cookieDomain = cookie.domain.toLowerCase();
		const host = hostname.toLowerCase();

		if (host === cookieDomain) { return true; }
		if (cookieDomain.startsWith('.') && (host.endsWith(cookieDomain) || host === cookieDomain.slice(1))) {
			return true;
		}
		return false;
	}

	private pathMatches(cookie: ParsedCookie, pathname: string): boolean {
		const cookiePath = cookie.path ?? '/';
		if (cookiePath === '/') { return true; }
		return pathname.startsWith(cookiePath);
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	private extractSetCookieValues(headers: Record<string, string | string[] | undefined>): string[] {
		const values: string[] = [];
		for (const [name, value] of Object.entries(headers)) {
			if (name.toLowerCase() === 'set-cookie') {
				if (Array.isArray(value)) {
					values.push(...value);
				} else if (typeof value === 'string') {
					values.push(value);
				}
			}
		}
		return values;
	}

	private safeParseUrl(url: string): URL | null {
		try {
			return new URL(url.startsWith('http') ? url : `http://${url}`);
		} catch {
			return null;
		}
	}
}
