/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Auth Configuration Types
// ---------------------------------------------------------------------------

export type AuthType = 'form' | 'api' | 'oauth2-client-credentials' | 'oauth2-authorization-code' | 'bearer' | 'basic' | 'none';

export interface AuthProfile {
	/** Display name for this profile */
	name: string;
	/** Authentication method */
	type: AuthType;
	/** Login endpoint URL */
	loginUrl?: string;
	/** Form/API fields to submit for login */
	fields?: Record<string, string>;
	/** CSS selector for CSRF token in the login form */
	csrfSelector?: string;
	/** Custom CSRF header name (e.g., X-CSRF-Token, X-XSRF-TOKEN) */
	csrfHeader?: string;
	/** String to look for in the response that confirms successful login */
	successIndicator?: string;
	/** Name of the session cookie to track */
	sessionCookie?: string;
	/** URL of a page that requires auth — used to verify the session is alive */
	sessionCheckUrl?: string;
	/** Expected status code for a valid session (default: 200) */
	sessionCheckExpectedStatus?: number;
	/** Static cookie string to use instead of login flow */
	cookie?: string;
	/** Static Authorization header value (e.g., 'Bearer xxx') */
	authorization?: string;
	/** Extra headers to inject for this profile */
	headers?: Record<string, string>;
	/** OAuth2-specific config */
	oauth?: OAuthConfig;
}

export interface OAuthConfig {
	/** OAuth2 token endpoint */
	tokenUrl: string;
	/** OAuth2 client ID */
	clientId: string;
	/** OAuth2 client secret */
	clientSecret: string;
	/** OAuth2 scopes */
	scopes?: string[];
	/** OAuth2 authorization code endpoint (for authorization_code flow) */
	authUrl?: string;
	/** OAuth2 redirect URI */
	redirectUri?: string;
}

// ---------------------------------------------------------------------------
// Session State
// ---------------------------------------------------------------------------

export interface SessionState {
	/** Profile name this session belongs to */
	profileName: string;
	/** Whether this session is currently valid */
	valid: boolean;
	/** When this session was created */
	createdAt: string;
	/** When this session was last validated */
	lastCheckedAt: string;
	/** Number of times this session has been refreshed */
	refreshCount: number;
	/** Cookies obtained from login */
	cookies: ParsedCookie[];
	/** CSRF token extracted from the target */
	csrfToken?: string;
	/** CSRF header name */
	csrfHeaderName?: string;
	/** Bearer token (from OAuth2) */
	bearerToken?: string;
	/** Token expiry time (ISO string) */
	tokenExpiresAt?: string;
}

// ---------------------------------------------------------------------------
// Cookie Types
// ---------------------------------------------------------------------------

export interface ParsedCookie {
	name: string;
	value: string;
	domain?: string;
	path?: string;
	expires?: Date;
	httpOnly?: boolean;
	secure?: boolean;
	sameSite?: 'strict' | 'lax' | 'none';
}

// ---------------------------------------------------------------------------
// Command Options
// ---------------------------------------------------------------------------

export interface LoginCommandOptions {
	/** Auth profile configuration */
	profile?: AuthProfile;
	/** Named profiles from the job file auth config */
	profiles?: Record<string, AuthProfile>;
	/** Which profile to login with (when using named profiles) */
	profileName?: string;
	/** Login all profiles at once */
	loginAll?: boolean;
	/** Extra headers for the login request */
	headers?: Record<string, string>;
	/** Timeout for the login request */
	timeoutMs?: number;
	/** Don't show UI notifications */
	quiet?: boolean;
}

export interface OAuthCommandOptions {
	/** OAuth2 configuration */
	oauth?: OAuthConfig;
	/** Named profile to use */
	profileName?: string;
	/** Timeout for the OAuth2 flow */
	timeoutMs?: number;
	/** Don't show UI notifications */
	quiet?: boolean;
}

export interface SessionCheckCommandOptions {
	/** Profile name to check */
	profileName?: string;
	/** Check all profiles */
	checkAll?: boolean;
	/** Don't show UI notifications */
	quiet?: boolean;
}

export interface SessionRefreshCommandOptions {
	/** Profile name to refresh */
	profileName?: string;
	/** Refresh all profiles */
	refreshAll?: boolean;
	/** Don't show UI notifications */
	quiet?: boolean;
}

export interface GetHeadersCommandOptions {
	/** Profile name to get headers for */
	profileName?: string;
	/**
	 * Target URL to scope cookies to. When set, only cookies whose domain/path
	 * match this URL are returned (closes the cross-host session leak). When
	 * omitted, the legacy all-cookies behavior is preserved for back-compat.
	 */
	targetUrl?: string;
	/** Don't show UI notifications */
	quiet?: boolean;
}

// ---------------------------------------------------------------------------
// Command Results
// ---------------------------------------------------------------------------

export interface LoginResult {
	generatedAt: string;
	profileName: string;
	success: boolean;
	sessionValid: boolean;
	cookiesObtained: number;
	csrfToken?: string;
	error?: string;
}

export interface MultiLoginResult {
	generatedAt: string;
	results: LoginResult[];
	totalProfiles: number;
	successfulLogins: number;
}

export interface SessionCheckResult {
	generatedAt: string;
	profileName: string;
	valid: boolean;
	statusCode?: number;
	error?: string;
}

export interface SessionRefreshResult {
	generatedAt: string;
	profileName: string;
	success: boolean;
	refreshCount: number;
	error?: string;
}

export interface AuthHeadersResult {
	generatedAt: string;
	profileName: string;
	headers: Record<string, string>;
	sessionValid: boolean;
}
