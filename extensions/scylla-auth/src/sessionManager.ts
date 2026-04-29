/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as http from 'http';
import * as https from 'https';
import * as querystring from 'querystring';
import { CookieJar } from './cookieJar';
import { extractCsrfFromHtml, extractCsrfFromHeaders, getCsrfHeaderName } from './csrfExtractor';
import type {
	AuthProfile,
	AuthHeadersResult,
	LoginResult,
	MultiLoginResult,
	SessionCheckResult,
	SessionRefreshResult,
	SessionState,
} from './types';

// ---------------------------------------------------------------------------
// Session Manager — Core auth engine for Scylla 2.0
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB

export class SessionManager {

	private profiles: Map<string, AuthProfile> = new Map();
	private sessions: Map<string, SessionState> = new Map();
	private cookieJars: Map<string, CookieJar> = new Map();

	// -----------------------------------------------------------------------
	// Profile Management
	// -----------------------------------------------------------------------

	registerProfile(name: string, profile: AuthProfile): void {
		this.profiles.set(name, { ...profile, name });
	}

	registerProfiles(profiles: Record<string, AuthProfile>): void {
		for (const [name, profile] of Object.entries(profiles)) {
			this.registerProfile(name, profile);
		}
	}

	getProfile(name: string): AuthProfile | undefined {
		return this.profiles.get(name);
	}

	listProfiles(): Array<{ name: string; type: string; hasSession: boolean; sessionValid: boolean }> {
		const result: Array<{ name: string; type: string; hasSession: boolean; sessionValid: boolean }> = [];
		for (const [name, profile] of this.profiles) {
			const session = this.sessions.get(name);
			result.push({
				name,
				type: profile.type,
				hasSession: !!session,
				sessionValid: session?.valid ?? false,
			});
		}
		return result;
	}

	// -----------------------------------------------------------------------
	// Login Flows
	// -----------------------------------------------------------------------

	async login(profileName: string): Promise<LoginResult> {
		const profile = this.profiles.get(profileName);
		if (!profile) {
			return this.loginError(profileName, `Profile "${profileName}" not found.`);
		}

		try {
			switch (profile.type) {
				case 'form':
					return await this.loginForm(profileName, profile);
				case 'api':
					return await this.loginApi(profileName, profile);
				case 'oauth2-client-credentials':
					return await this.loginOAuthClientCredentials(profileName, profile);
				case 'bearer':
					return this.loginBearer(profileName, profile);
				case 'basic':
					return this.loginBasic(profileName, profile);
				case 'none':
					return this.loginNone(profileName);
				default:
					return await this.loginForm(profileName, profile);
			}
		} catch (error: unknown) {
			return this.loginError(profileName, error instanceof Error ? error.message : String(error));
		}
	}

	async loginAll(): Promise<MultiLoginResult> {
		const results: LoginResult[] = [];
		for (const name of this.profiles.keys()) {
			results.push(await this.login(name));
		}
		return {
			generatedAt: new Date().toISOString(),
			results,
			totalProfiles: this.profiles.size,
			successfulLogins: results.filter(r => r.success).length,
		};
	}

	/**
	 * Form-based login:
	 * 1. GET the login page to extract CSRF token (if csrfSelector is set)
	 * 2. POST the form fields + CSRF token
	 * 3. Extract session cookies from Set-Cookie headers
	 * 4. Validate login by checking successIndicator in response body
	 */
	private async loginForm(profileName: string, profile: AuthProfile): Promise<LoginResult> {
		const jar = this.getOrCreateJar(profileName);
		const loginUrl = profile.loginUrl;
		if (!loginUrl) {
			return this.loginError(profileName, 'loginUrl is required for form login.');
		}

		let csrfToken: string | undefined;
		let csrfHeaderName: string | undefined;

		// Step 1: GET login page for CSRF token
		if (profile.csrfSelector || profile.csrfHeader) {
			const getResponse = await this.httpRequest('GET', loginUrl, undefined, {}, DEFAULT_TIMEOUT_MS);
			jar.ingestSetCookieHeaders(getResponse.headers, loginUrl);

			csrfToken = extractCsrfFromHtml(getResponse.body, profile.csrfSelector);
			if (!csrfToken) {
				const headerResult = extractCsrfFromHeaders(getResponse.headers, profile.csrfHeader);
				if (headerResult) {
					csrfToken = headerResult.token;
					csrfHeaderName = headerResult.headerName;
				}
			}
		}

		// Step 2: POST login form
		const fields = { ...profile.fields };
		if (csrfToken && profile.csrfSelector) {
			// Extract the field name from the selector: input[name='_token'] → _token
			const fieldMatch = profile.csrfSelector.match(/\[name=['"](.+?)['"]\]/);
			if (fieldMatch) {
				fields[fieldMatch[1]] = csrfToken;
			}
		}

		const formBody = querystring.stringify(fields);
		const postHeaders: Record<string, string> = {
			'content-type': 'application/x-www-form-urlencoded',
			...this.buildCookieHeader(jar, loginUrl),
		};
		if (csrfToken && csrfHeaderName) {
			postHeaders[getCsrfHeaderName(profile.csrfHeader, csrfHeaderName)] = csrfToken;
		}
		if (profile.headers) {
			Object.assign(postHeaders, profile.headers);
		}

		const postResponse = await this.httpRequest('POST', loginUrl, formBody, postHeaders, DEFAULT_TIMEOUT_MS);
		const newCookies = jar.ingestSetCookieHeaders(postResponse.headers, loginUrl);

		// Handle redirect after login (common pattern: POST /login → 302 → /dashboard)
		if (this.isRedirect(postResponse.statusCode) && postResponse.headers.location) {
			const redirectUrl = this.resolveUrl(postResponse.headers.location as string, loginUrl);
			const redirectHeaders = { ...this.buildCookieHeader(jar, redirectUrl) };
			if (profile.headers) { Object.assign(redirectHeaders, profile.headers); }
			const redirectResponse = await this.httpRequest('GET', redirectUrl, undefined, redirectHeaders, DEFAULT_TIMEOUT_MS);
			jar.ingestSetCookieHeaders(redirectResponse.headers, redirectUrl);

			return this.finalizeLogin(profileName, profile, redirectResponse, jar, csrfToken, csrfHeaderName, newCookies.length);
		}

		return this.finalizeLogin(profileName, profile, postResponse, jar, csrfToken, csrfHeaderName, newCookies.length);
	}

	/**
	 * API-based login (JSON body):
	 * POST { username, password } → response with set-cookie or json { token }
	 */
	private async loginApi(profileName: string, profile: AuthProfile): Promise<LoginResult> {
		const jar = this.getOrCreateJar(profileName);
		const loginUrl = profile.loginUrl;
		if (!loginUrl) {
			return this.loginError(profileName, 'loginUrl is required for API login.');
		}

		const jsonBody = JSON.stringify(profile.fields ?? {});
		const headers: Record<string, string> = {
			'content-type': 'application/json',
			...this.buildCookieHeader(jar, loginUrl),
		};
		if (profile.headers) { Object.assign(headers, profile.headers); }

		const response = await this.httpRequest('POST', loginUrl, jsonBody, headers, DEFAULT_TIMEOUT_MS);
		const newCookies = jar.ingestSetCookieHeaders(response.headers, loginUrl);

		// Try to extract bearer token from JSON response
		let bearerToken: string | undefined;
		try {
			const body = JSON.parse(response.body);
			bearerToken = body.token ?? body.access_token ?? body.accessToken ?? body.jwt;
		} catch { /* not JSON, that's fine */ }

		const session = this.createSession(profileName);
		session.cookies = jar.getAllCookies();
		if (bearerToken) { session.bearerToken = bearerToken; }

		const success = response.statusCode >= 200 && response.statusCode < 400;
		session.valid = success;
		this.sessions.set(profileName, session);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success,
			sessionValid: success,
			cookiesObtained: newCookies.length,
		};
	}

	/**
	 * OAuth2 Client Credentials flow:
	 * POST token_url with client_id + client_secret → bearer token
	 */
	private async loginOAuthClientCredentials(profileName: string, profile: AuthProfile): Promise<LoginResult> {
		const oauth = profile.oauth;
		if (!oauth) {
			return this.loginError(profileName, 'OAuth2 config is required for oauth2-client-credentials login.');
		}

		const body = querystring.stringify({
			grant_type: 'client_credentials',
			client_id: oauth.clientId,
			client_secret: oauth.clientSecret,
			scope: oauth.scopes?.join(' ') ?? '',
		});

		const headers: Record<string, string> = {
			'content-type': 'application/x-www-form-urlencoded',
		};

		const response = await this.httpRequest('POST', oauth.tokenUrl, body, headers, DEFAULT_TIMEOUT_MS);

		try {
			const tokenData = JSON.parse(response.body);
			const accessToken = tokenData.access_token;
			if (!accessToken) {
				return this.loginError(profileName, `OAuth2 response missing access_token. Body: ${response.body.slice(0, 200)}`);
			}

			const session = this.createSession(profileName);
			session.bearerToken = accessToken;
			session.valid = true;
			if (tokenData.expires_in) {
				session.tokenExpiresAt = new Date(Date.now() + tokenData.expires_in * 1000).toISOString();
			}
			this.sessions.set(profileName, session);

			return {
				generatedAt: new Date().toISOString(),
				profileName,
				success: true,
				sessionValid: true,
				cookiesObtained: 0,
			};
		} catch {
			return this.loginError(profileName, `Failed to parse OAuth2 response: ${response.body.slice(0, 200)}`);
		}
	}

	/**
	 * Static bearer token — no login flow needed
	 */
	private loginBearer(profileName: string, profile: AuthProfile): LoginResult {
		if (!profile.authorization) {
			return this.loginError(profileName, 'authorization field is required for bearer auth.');
		}

		const session = this.createSession(profileName);
		session.bearerToken = profile.authorization.replace(/^bearer\s+/i, '');
		session.valid = true;
		this.sessions.set(profileName, session);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success: true,
			sessionValid: true,
			cookiesObtained: 0,
		};
	}

	/**
	 * Static basic auth — no login flow needed
	 */
	private loginBasic(profileName: string, _profile: AuthProfile): LoginResult {
		const session = this.createSession(profileName);
		session.valid = true;
		this.sessions.set(profileName, session);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success: true,
			sessionValid: true,
			cookiesObtained: 0,
		};
	}

	/**
	 * No-auth profile (guest access)
	 */
	private loginNone(profileName: string): LoginResult {
		const session = this.createSession(profileName);
		session.valid = true;
		this.sessions.set(profileName, session);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success: true,
			sessionValid: true,
			cookiesObtained: 0,
		};
	}

	// -----------------------------------------------------------------------
	// Session Check & Refresh
	// -----------------------------------------------------------------------

	async checkSession(profileName: string): Promise<SessionCheckResult> {
		const profile = this.profiles.get(profileName);
		const session = this.sessions.get(profileName);

		if (!profile || !session) {
			return { generatedAt: new Date().toISOString(), profileName, valid: false, error: 'No session found.' };
		}

		// Check token expiry
		if (session.tokenExpiresAt && new Date(session.tokenExpiresAt).getTime() < Date.now()) {
			session.valid = false;
			return { generatedAt: new Date().toISOString(), profileName, valid: false, error: 'Token expired.' };
		}

		// If sessionCheckUrl is configured, make a request to verify
		const checkUrl = profile.sessionCheckUrl ?? profile.loginUrl;
		if (!checkUrl) {
			session.lastCheckedAt = new Date().toISOString();
			return { generatedAt: new Date().toISOString(), profileName, valid: session.valid };
		}

		const headers = this.buildAuthHeaders(profileName);
		const response = await this.httpRequest('GET', checkUrl, undefined, headers, DEFAULT_TIMEOUT_MS);

		const expectedStatus = profile.sessionCheckExpectedStatus ?? 200;
		const valid = response.statusCode === expectedStatus ||
			(response.statusCode >= 200 && response.statusCode < 400 && response.statusCode !== 401 && response.statusCode !== 403);

		session.valid = valid;
		session.lastCheckedAt = new Date().toISOString();
		this.sessions.set(profileName, session);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			valid,
			statusCode: response.statusCode,
		};
	}

	async refreshSession(profileName: string): Promise<SessionRefreshResult> {
		const session = this.sessions.get(profileName);
		const refreshCount = session ? session.refreshCount + 1 : 1;

		// Clear old session
		this.sessions.delete(profileName);
		const jar = this.cookieJars.get(profileName);
		if (jar) { jar.clear(); }

		// Re-login
		const loginResult = await this.login(profileName);

		if (loginResult.success) {
			const newSession = this.sessions.get(profileName);
			if (newSession) { newSession.refreshCount = refreshCount; }
		}

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success: loginResult.success,
			refreshCount,
			error: loginResult.error,
		};
	}

	// -----------------------------------------------------------------------
	// Get Auth Headers (used by scanners)
	// -----------------------------------------------------------------------

	getAuthHeaders(profileName: string, targetUrl?: string): AuthHeadersResult {
		const headers = this.buildAuthHeaders(profileName, targetUrl);
		const session = this.sessions.get(profileName);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			headers,
			sessionValid: session?.valid ?? false,
		};
	}

	/**
	 * Build a complete set of headers for authenticated requests.
	 * Includes: Cookie, Authorization, CSRF token, custom headers.
	 */
	buildAuthHeaders(profileName: string, targetUrl?: string): Record<string, string> {
		const profile = this.profiles.get(profileName);
		const session = this.sessions.get(profileName);
		const jar = this.cookieJars.get(profileName);
		const headers: Record<string, string> = {};

		// Cookies from jar
		if (jar && targetUrl) {
			const cookieHeader = jar.getCookieHeader(targetUrl);
			if (cookieHeader) { headers['cookie'] = cookieHeader; }
		} else if (jar) {
			// No target URL, send all cookies
			const allCookies = jar.getAllCookies();
			if (allCookies.length > 0) {
				headers['cookie'] = allCookies.map(c => `${c.name}=${c.value}`).join('; ');
			}
		}

		// Static cookie from profile
		if (profile?.cookie && !headers['cookie']) {
			headers['cookie'] = profile.cookie;
		}

		// Bearer/Authorization
		if (session?.bearerToken) {
			headers['authorization'] = `Bearer ${session.bearerToken}`;
		} else if (profile?.authorization) {
			headers['authorization'] = profile.authorization;
		} else if (profile?.type === 'basic' && profile.fields) {
			const user = profile.fields['username'] ?? profile.fields['user'] ?? '';
			const pass = profile.fields['password'] ?? profile.fields['pass'] ?? '';
			headers['authorization'] = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
		}

		// CSRF token
		if (session?.csrfToken) {
			const headerName = session.csrfHeaderName ?? getCsrfHeaderName(profile?.csrfHeader);
			headers[headerName] = session.csrfToken;
		}

		// Custom headers from profile
		if (profile?.headers) {
			Object.assign(headers, profile.headers);
		}

		return headers;
	}

	// -----------------------------------------------------------------------
	// Clear
	// -----------------------------------------------------------------------

	clearSessions(): void {
		this.sessions.clear();
		this.cookieJars.clear();
	}

	clearAll(): void {
		this.profiles.clear();
		this.sessions.clear();
		this.cookieJars.clear();
	}

	// -----------------------------------------------------------------------
	// Internal Helpers
	// -----------------------------------------------------------------------

	private finalizeLogin(
		profileName: string,
		profile: AuthProfile,
		response: HttpResponse,
		jar: CookieJar,
		csrfToken: string | undefined,
		csrfHeaderName: string | undefined,
		cookiesObtained: number,
	): LoginResult {
		const session = this.createSession(profileName);
		session.cookies = jar.getAllCookies();
		session.csrfToken = csrfToken;
		session.csrfHeaderName = csrfHeaderName;

		// Determine success
		let success = response.statusCode >= 200 && response.statusCode < 400;

		if (profile.successIndicator) {
			success = response.body.includes(profile.successIndicator);
		}

		if (profile.sessionCookie) {
			success = success && jar.hasCookie(profile.sessionCookie);
		}

		session.valid = success;
		this.sessions.set(profileName, session);

		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success,
			sessionValid: success,
			cookiesObtained,
			csrfToken,
			error: success ? undefined : `Login failed. Status: ${response.statusCode}. Body snippet: ${response.body.slice(0, 200)}`,
		};
	}

	private createSession(profileName: string): SessionState {
		return {
			profileName,
			valid: false,
			createdAt: new Date().toISOString(),
			lastCheckedAt: new Date().toISOString(),
			refreshCount: 0,
			cookies: [],
		};
	}

	private getOrCreateJar(profileName: string): CookieJar {
		let jar = this.cookieJars.get(profileName);
		if (!jar) {
			jar = new CookieJar();
			this.cookieJars.set(profileName, jar);
		}

		// If the profile has a static cookie, import it
		const profile = this.profiles.get(profileName);
		if (profile?.cookie && jar.size === 0) {
			jar.importCookieString(profile.cookie);
		}

		return jar;
	}

	private buildCookieHeader(jar: CookieJar, url: string): Record<string, string> {
		const cookie = jar.getCookieHeader(url);
		return cookie ? { cookie } : {};
	}

	private loginError(profileName: string, error: string): LoginResult {
		return {
			generatedAt: new Date().toISOString(),
			profileName,
			success: false,
			sessionValid: false,
			cookiesObtained: 0,
			error,
		};
	}

	private isRedirect(statusCode: number): boolean {
		return statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308;
	}

	private resolveUrl(location: string, baseUrl: string): string {
		try {
			return new URL(location, baseUrl).toString();
		} catch {
			return location;
		}
	}

	// -----------------------------------------------------------------------
	// HTTP Client (self-contained — avoids circular dependency with scylla-http)
	// -----------------------------------------------------------------------

	private httpRequest(
		method: string,
		url: string,
		body: string | undefined,
		headers: Record<string, string>,
		timeoutMs: number,
	): Promise<HttpResponse> {
		return new Promise<HttpResponse>((resolve, reject) => {
			const parsedUrl = new URL(url);
			const transport = parsedUrl.protocol === 'https:' ? https : http;

			const finalHeaders = { ...headers };
			if (body && !this.hasHeader(finalHeaders, 'content-length')) {
				finalHeaders['content-length'] = String(Buffer.byteLength(body, 'utf8'));
			}

			const request = transport.request(
				{
					protocol: parsedUrl.protocol,
					hostname: parsedUrl.hostname,
					port: parsedUrl.port ? Number(parsedUrl.port) : undefined,
					path: `${parsedUrl.pathname}${parsedUrl.search}`,
					method: method.toUpperCase(),
					headers: finalHeaders,
					timeout: timeoutMs,
				},
				incoming => {
					const chunks: Buffer[] = [];
					let storedBytes = 0;

					incoming.on('data', (chunk: Buffer | string) => {
						const normalizedChunk = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
						if (storedBytes < DEFAULT_MAX_BODY_BYTES) {
							const remaining = DEFAULT_MAX_BODY_BYTES - storedBytes;
							chunks.push(normalizedChunk.subarray(0, Math.min(normalizedChunk.length, remaining)));
							storedBytes += Math.min(normalizedChunk.length, remaining);
						}
					});

					incoming.on('end', () => {
						resolve({
							statusCode: incoming.statusCode ?? 0,
							headers: this.flattenHeaders(incoming.headers),
							body: Buffer.concat(chunks).toString('utf8'),
						});
					});

					incoming.on('error', reject);
				}
			);

			request.on('timeout', () => {
				request.destroy(new Error(`Request timed out after ${timeoutMs}ms.`));
			});
			request.on('error', reject);

			if (body) { request.write(body); }
			request.end();
		});
	}

	private hasHeader(headers: Record<string, string>, name: string): boolean {
		return Object.keys(headers).some(k => k.toLowerCase() === name.toLowerCase());
	}

	private flattenHeaders(headers: http.IncomingHttpHeaders): Record<string, string | string[]> {
		const result: Record<string, string | string[]> = {};
		for (const [name, value] of Object.entries(headers)) {
			if (value !== undefined) {
				result[name.toLowerCase()] = Array.isArray(value) ? value : String(value);
			}
		}
		return result;
	}
}

interface HttpResponse {
	statusCode: number;
	headers: Record<string, string | string[]>;
	body: string;
}

// ---------------------------------------------------------------------------
// Singleton — shared across the extension lifetime
// ---------------------------------------------------------------------------

export const sessionManager = new SessionManager();
