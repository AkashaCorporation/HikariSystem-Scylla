/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface HttpProbeResponse {
	statusCode: number;
	bodyText: string;
	elapsedMs: number;
	headers: Record<string, string>;
}

interface WafSignature {
	name: string;
	/** Check HTTP headers (lowercased keys). Return evidence strings. */
	matchHeaders(headers: Record<string, string>): string[];
	/** Check response body. Return evidence strings. */
	matchBody(body: string): string[];
	/** Bypass suggestions specific to this WAF. */
	bypasses: string[];
}

// ---------------------------------------------------------------------------
// WAF signature database
// ---------------------------------------------------------------------------

const WAF_SIGNATURES: WafSignature[] = [
	// ── Cloudflare ────────────────────────────────────────────────────────
	{
		name: 'Cloudflare',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['cf-ray']) {
				ev.push(`Header cf-ray: ${h['cf-ray']}`);
			}
			if (h['cf-cache-status']) {
				ev.push(`Header cf-cache-status: ${h['cf-cache-status']}`);
			}
			if (h['server']?.toLowerCase().includes('cloudflare')) {
				ev.push(`Server header contains "cloudflare": ${h['server']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/__cfduid|__cf_bm|cf_clearance/.test(setCookie)) {
				ev.push('Cloudflare cookie detected (__cfduid / __cf_bm / cf_clearance)');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('attention required! | cloudflare')) {
				ev.push('Cloudflare challenge page detected (title)');
			}
			if (lower.includes('cf-browser-verification')) {
				ev.push('Cloudflare browser verification challenge detected');
			}
			if (lower.includes('cloudflare ray id')) {
				ev.push('Cloudflare Ray ID reference in body');
			}
			if (/cdn-cgi\/l\/chk_jschl/.test(body)) {
				ev.push('Cloudflare JS challenge endpoint reference');
			}
			if (lower.includes('performance & security by cloudflare')) {
				ev.push('Cloudflare branding in body');
			}
			return ev;
		},
		bypasses: [
			'HTTP Parameter Pollution: duplicate params (?id=1&id=2) to confuse rule matching',
			'Double URL encoding: e.g. %2527 instead of %27 for single quote',
			'Unicode normalization bypass: use full-width characters (e.g. \uFF07 for quote)',
			'Newline injection in headers to split rules (\\r\\n)',
			'Origin IP discovery via DNS history, Shodan, or mail server headers to bypass proxy',
			'Try alternate HTTP methods (e.g. PUT/PATCH) that may have weaker rule coverage',
		],
	},

	// ── Akamai ────────────────────────────────────────────────────────────
	{
		name: 'Akamai',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['x-akamai-transformed']) {
				ev.push(`Header x-akamai-transformed: ${h['x-akamai-transformed']}`);
			}
			if (h['x-akamai-request-id']) {
				ev.push(`Header x-akamai-request-id: ${h['x-akamai-request-id']}`);
			}
			if (h['server']?.toLowerCase().includes('akamaighost')) {
				ev.push(`Server header contains "AkamaiGHost": ${h['server']}`);
			}
			if (h['x-check-cacheable']) {
				ev.push(`Header x-check-cacheable: ${h['x-check-cacheable']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/akamai|ak_bmsc|bm_sv/.test(setCookie.toLowerCase())) {
				ev.push('Akamai bot-manager cookie detected (ak_bmsc / bm_sv)');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('akamai') && lower.includes('reference')) {
				ev.push('Akamai reference error page detected');
			}
			if (lower.includes('access denied') && lower.includes('akamai')) {
				ev.push('Akamai access denied page detected');
			}
			if (/ak\.staticcontent\.io/.test(body)) {
				ev.push('Akamai static content reference detected');
			}
			return ev;
		},
		bypasses: [
			'Chunked Transfer-Encoding: split payloads across chunks to evade pattern matching',
			'Null byte injection: insert %00 before payloads',
			'Comment fragmentation in SQL: SELECT/**/FROM or SEL/**/ECT',
			'Use HTTP/0.9 or HTTP/1.0 to bypass HTTP/1.1-specific rules',
			'Parameter name manipulation: duplicate or unusual param names',
		],
	},

	// ── Imperva / Incapsula ──────────────────────────────────────────────
	{
		name: 'Imperva/Incapsula',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['x-iinfo']) {
				ev.push(`Header x-iinfo: ${h['x-iinfo']}`);
			}
			if (h['x-cdn']?.toLowerCase().includes('incapsula')) {
				ev.push(`Header x-cdn contains "Incapsula": ${h['x-cdn']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/incap_ses_|visid_incap_/.test(setCookie)) {
				ev.push('Incapsula session cookies detected (incap_ses_ / visid_incap_)');
			}
			if (/nlbi_/.test(setCookie)) {
				ev.push('Incapsula load-balancer cookie detected (nlbi_)');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('incapsula incident')) {
				ev.push('Incapsula incident ID in response body');
			}
			if (lower.includes('powered by incapsula')) {
				ev.push('Incapsula branding in body');
			}
			if (lower.includes('_incapsula_resource')) {
				ev.push('Incapsula resource reference detected');
			}
			return ev;
		},
		bypasses: [
			'Use alternate encodings: UTF-7, UTF-16 payloads',
			'HPP (HTTP Parameter Pollution) to confuse param parsing',
			'Multipart form-data with nested boundaries',
			'Header injection via overlong headers',
			'Request smuggling via CL/TE desync (Content-Length vs Transfer-Encoding)',
		],
	},

	// ── AWS WAF ──────────────────────────────────────────────────────────
	{
		name: 'AWS WAF',
		matchHeaders(h) {
			const ev: string[] = [];
			for (const key of Object.keys(h)) {
				if (key.startsWith('x-amzn-waf')) {
					ev.push(`Header ${key}: ${h[key]}`);
				}
			}
			if (h['x-amzn-requestid']) {
				ev.push(`Header x-amzn-requestid: ${h['x-amzn-requestid']}`);
			}
			if (h['x-amz-cf-id']) {
				ev.push(`Header x-amz-cf-id (CloudFront): ${h['x-amz-cf-id']}`);
			}
			if (h['x-amz-apigw-id']) {
				ev.push(`Header x-amz-apigw-id (API Gateway): ${h['x-amz-apigw-id']}`);
			}
			if (h['server']?.toLowerCase().includes('awselb')) {
				ev.push(`Server header contains "awselb": ${h['server']}`);
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (/aws|amazon/i.test(body) && lower.includes('request blocked')) {
				ev.push('AWS WAF block page detected');
			}
			if (lower.includes('403 forbidden') && /x-amzn|awswaf/i.test(body)) {
				ev.push('AWS WAF 403 forbidden response');
			}
			return ev;
		},
		bypasses: [
			'Case mixing: SeLeCt, UnIoN to evade case-sensitive regex rules',
			'Unicode encoding of SQL keywords',
			'JSON-based SQL injection in API endpoints',
			'Payload splitting across multiple parameters',
			'Use non-standard Content-Type headers',
		],
	},

	// ── Azure WAF / Front Door ───────────────────────────────────────────
	{
		name: 'Azure WAF/Front Door',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['x-azure-ref']) {
				ev.push(`Header x-azure-ref: ${h['x-azure-ref']}`);
			}
			if (h['x-fd-healthprobe']) {
				ev.push(`Header x-fd-healthprobe: ${h['x-fd-healthprobe']}`);
			}
			if (h['x-ms-ref']) {
				ev.push(`Header x-ms-ref: ${h['x-ms-ref']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/afd_|azurefd/i.test(setCookie)) {
				ev.push('Azure Front Door cookie detected');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('azure') && lower.includes('web application firewall')) {
				ev.push('Azure WAF block page detected');
			}
			if (lower.includes('ref: ') && lower.includes('front door')) {
				ev.push('Azure Front Door error page reference');
			}
			return ev;
		},
		bypasses: [
			'Double URL encoding to evade normalization',
			'Payload in JSON body instead of query string',
			'Use multipart/form-data with custom boundaries',
			'Encoding payloads as base64 in parameter values',
			'HTTP verb tampering (e.g. use POST with _method=PUT override)',
		],
	},

	// ── Google Cloud Armor ───────────────────────────────────────────────
	{
		name: 'Google Cloud Armor',
		matchHeaders(h) {
			const ev: string[] = [];
			for (const key of Object.keys(h)) {
				if (key.startsWith('x-goog-')) {
					ev.push(`Header ${key}: ${h[key]}`);
				}
			}
			if (h['server']?.toLowerCase().includes('google frontend') || h['server']?.toLowerCase() === 'gfe') {
				ev.push(`Server header indicates Google Frontend: ${h['server']}`);
			}
			if (h['via']?.toLowerCase().includes('google')) {
				ev.push(`Via header references Google: ${h['via']}`);
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('google cloud armor')) {
				ev.push('Google Cloud Armor mentioned in body');
			}
			if (lower.includes('error 403') && lower.includes('google')) {
				ev.push('Google 403 error page detected');
			}
			return ev;
		},
		bypasses: [
			'Payload obfuscation via hex encoding (0x...)',
			'Use alternate SQL comment styles: # vs -- vs /* */',
			'Whitespace manipulation: tabs, vertical tabs, form-feeds instead of spaces',
			'URL path manipulation with ../ and double slashes',
		],
	},

	// ── ModSecurity ──────────────────────────────────────────────────────
	{
		name: 'ModSecurity',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['server']?.toLowerCase().includes('mod_security') || h['server']?.toLowerCase().includes('modsecurity')) {
				ev.push(`Server header contains "ModSecurity": ${h['server']}`);
			}
			for (const key of Object.keys(h)) {
				if (key.toLowerCase().includes('modsecurity')) {
					ev.push(`ModSecurity-related header: ${key}: ${h[key]}`);
				}
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('mod_security') || lower.includes('modsecurity')) {
				ev.push('ModSecurity reference in response body');
			}
			if (lower.includes('not acceptable') && lower.includes('security module')) {
				ev.push('ModSecurity "Not Acceptable" error page');
			}
			if (/this error was generated by mod_security/i.test(body)) {
				ev.push('ModSecurity error message detected');
			}
			if (/rules?\.data/i.test(body) && lower.includes('security')) {
				ev.push('ModSecurity rules data reference in body');
			}
			return ev;
		},
		bypasses: [
			'MySQL version comments: /*!50000SELECT*/ to hide SQL keywords',
			'Case mixing: sElEcT, uNiOn to bypass case-sensitive CRS rules',
			'Inline comments in SQL: SEL/**/ECT or UN/**/ION',
			'HPP (HTTP Parameter Pollution) to split payloads across params',
			'Use equivalent SQL functions: MID() instead of SUBSTRING()',
			'Bypass OWASP CRS paranoia levels with payloads below scoring threshold',
		],
	},

	// ── F5 BIG-IP ASM ────────────────────────────────────────────────────
	{
		name: 'F5 BIG-IP',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['server']?.toLowerCase().includes('big-ip') || h['server']?.toLowerCase().includes('bigip')) {
				ev.push(`Server header contains "BIG-IP": ${h['server']}`);
			}
			if (h['x-wa-info']) {
				ev.push(`Header x-wa-info (F5 ASM): ${h['x-wa-info']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/BIGipServer/i.test(setCookie)) {
				ev.push('F5 BIG-IP persistence cookie detected (BIGipServer)');
			}
			if (/TS[0-9a-f]{6,}=/i.test(setCookie)) {
				ev.push('F5 BIG-IP TS cookie detected');
			}
			if (/f5_cspm/.test(setCookie)) {
				ev.push('F5 Client-Side Protection Module cookie detected (f5_cspm)');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('the requested url was rejected')) {
				ev.push('F5 ASM block page: "The requested URL was rejected"');
			}
			if (/support\s*id/i.test(body) && lower.includes('please consult')) {
				ev.push('F5 ASM support ID reference in block page');
			}
			return ev;
		},
		bypasses: [
			'Use chunked transfer encoding to split malicious payloads',
			'URL encoding of entire payload',
			'Use HTTP/2 multiplexing to confuse request inspection',
			'JSON-wrapped payloads in POST body',
			'Whitespace manipulation with null bytes',
		],
	},

	// ── Fortinet / FortiWeb ──────────────────────────────────────────────
	{
		name: 'Fortinet/FortiWeb',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['server']?.toLowerCase().includes('fortiweb')) {
				ev.push(`Server header contains "FortiWeb": ${h['server']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/FORTIWAFSID/i.test(setCookie)) {
				ev.push('FortiWeb session cookie detected (FORTIWAFSID)');
			}
			if (/cookiesession1/.test(setCookie)) {
				ev.push('FortiWeb cookiesession1 cookie detected');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('fortigate') || lower.includes('fortiweb')) {
				ev.push('Fortinet/FortiWeb reference in response body');
			}
			if (lower.includes('.fgt_icon') || lower.includes('fgt-icon')) {
				ev.push('FortiGate icon reference detected');
			}
			if (lower.includes('web page blocked') && lower.includes('fortinet')) {
				ev.push('FortiWeb block page detected');
			}
			return ev;
		},
		bypasses: [
			'Double encoding: %2527 for single quote bypass',
			'Use alternate XSS vectors: event handlers (onmouseover, onfocus) instead of <script>',
			'Payload fragmentation via multipart POST',
			'CRLF injection to split header inspection',
			'Case variation in HTML tags: <ScRiPt>',
		],
	},

	// ── Sucuri ────────────────────────────────────────────────────────────
	{
		name: 'Sucuri',
		matchHeaders(h) {
			const ev: string[] = [];
			if (h['x-sucuri-id']) {
				ev.push(`Header x-sucuri-id: ${h['x-sucuri-id']}`);
			}
			if (h['x-sucuri-cache']) {
				ev.push(`Header x-sucuri-cache: ${h['x-sucuri-cache']}`);
			}
			if (h['server']?.toLowerCase().includes('sucuri')) {
				ev.push(`Server header contains "Sucuri": ${h['server']}`);
			}
			const setCookie = h['set-cookie'] ?? '';
			if (/sucuri_cloudproxy/i.test(setCookie)) {
				ev.push('Sucuri CloudProxy cookie detected');
			}
			return ev;
		},
		matchBody(body) {
			const ev: string[] = [];
			const lower = body.toLowerCase();
			if (lower.includes('sucuri') && lower.includes('cloudproxy')) {
				ev.push('Sucuri CloudProxy reference in body');
			}
			if (lower.includes('access denied - sucuri')) {
				ev.push('Sucuri access denied page detected');
			}
			if (lower.includes('sucuri website firewall')) {
				ev.push('Sucuri Website Firewall branding in body');
			}
			return ev;
		},
		bypasses: [
			'Origin IP discovery via DNS history to bypass proxy',
			'Double URL encoding to evade pattern matching',
			'HPP (HTTP Parameter Pollution)',
			'Alternate request content types (application/json vs form-urlencoded)',
			'Use form-data encoding vs URL-encoded parameters',
		],
	},
];

// ---------------------------------------------------------------------------
// Generic bypass suggestions (always appended)
// ---------------------------------------------------------------------------

const GENERIC_BYPASS_SUGGESTIONS: string[] = [
	'Double encoding: encode payloads twice (%2527 = %27 = \')',
	'Case variation: mIxEd CaSe in SQL/HTML keywords',
	'Whitespace manipulation: use tabs (\\t), newlines (\\n), or /**/ instead of spaces',
	'Form-data vs URL params: move payloads from query string to POST body',
	'Content-Type switching: application/json, multipart/form-data, text/xml',
	'HTTP method override: X-HTTP-Method-Override, X-Method-Override headers',
	'Wildcard and glob characters in path traversal',
	'IP rotation and request throttling to avoid rate-based blocking',
];

// ---------------------------------------------------------------------------
// Probe payloads
// ---------------------------------------------------------------------------

const XSS_USER_AGENT = '<script>alert(1)</script>';
const SQLI_PARAM = `?id=1' OR 1=1--`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 15_000;

function flattenHeaders(headers: Record<string, string | string[] | undefined> | undefined): Record<string, string> {
	const flat: Record<string, string> = {};
	if (!headers) {
		return flat;
	}
	for (const [key, value] of Object.entries(headers)) {
		if (value !== undefined) {
			flat[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
		}
	}
	return flat;
}

async function sendProbe(
	targetUrl: string,
	extraHeaders: Record<string, string> = {},
): Promise<HttpProbeResponse | null> {
	try {
		const result = await vscode.commands.executeCommand<{
			response: {
				statusCode: number;
				bodyText: string;
				elapsedMs: number;
				headers?: Record<string, string>;
			};
		}>('scylla.http.sendHeadless', {
			url: targetUrl,
			method: 'GET',
			timeoutMs: DEFAULT_TIMEOUT_MS,
			followRedirects: true,
			quiet: true,
			headers: { ...extraHeaders },
		});

		if (!result?.response) {
			return null;
		}

		return {
			statusCode: result.response.statusCode,
			bodyText: result.response.bodyText ?? '',
			elapsedMs: result.response.elapsedMs,
			headers: flattenHeaders(result.response.headers as Record<string, string | string[] | undefined>),
		};
	} catch {
		return null;
	}
}

function evaluateSignatures(
	responses: (HttpProbeResponse | null)[],
): { wafName: string; confidence: number; evidence: string[]; bypasses: string[] } | null {

	let bestMatch: { wafName: string; confidence: number; evidence: string[]; bypasses: string[] } | null = null;

	for (const sig of WAF_SIGNATURES) {
		const allEvidence: string[] = [];

		for (let i = 0; i < responses.length; i++) {
			const resp = responses[i];
			if (!resp) {
				continue;
			}

			const probeLabel = ['baseline', 'SQLi probe', 'XSS probe'][i];

			const headerEv = sig.matchHeaders(resp.headers);
			for (const e of headerEv) {
				allEvidence.push(`[${probeLabel}] ${e}`);
			}

			const bodyEv = sig.matchBody(resp.bodyText);
			for (const e of bodyEv) {
				allEvidence.push(`[${probeLabel}] ${e}`);
			}
		}

		if (allEvidence.length === 0) {
			continue;
		}

		// Confidence scoring:
		//   1 evidence item  -> 0.4 (low)
		//   2 evidence items -> 0.6 (medium)
		//   3 evidence items -> 0.75 (high)
		//   4+ evidence items -> 0.85-0.95 (very high)
		// Bonus if detected in multiple probe types
		const probeTypes = new Set(allEvidence.map(e => e.match(/^\[([^\]]+)\]/)?.[1]));
		const baseConfidence = Math.min(0.95, 0.3 + allEvidence.length * 0.15);
		const probeBonus = (probeTypes.size - 1) * 0.05;
		const confidence = Math.min(0.99, baseConfidence + probeBonus);

		if (!bestMatch || confidence > bestMatch.confidence || allEvidence.length > bestMatch.evidence.length) {
			bestMatch = {
				wafName: sig.name,
				confidence: Math.round(confidence * 100) / 100,
				evidence: allEvidence,
				bypasses: sig.bypasses,
			};
		}
	}

	return bestMatch;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Detect WAF presence on a target URL by sending multiple probes and
 * fingerprinting responses against a database of known WAF signatures.
 *
 * Sends three requests:
 * 1. Normal GET (baseline)
 * 2. GET with SQLi payload in query string
 * 3. GET with XSS payload in User-Agent header
 *
 * Ported from Tsurugi waf.py.
 */
export async function detectWaf(
	targetUrl: string,
	options?: { headers?: Record<string, string>; cookie?: string },
): Promise<WafDetectResult> {
	const start = Date.now();

	const customHeaders: Record<string, string> = { ...(options?.headers ?? {}) };
	if (options?.cookie) {
		customHeaders['cookie'] = options.cookie;
	}

	// ── Probe 1: baseline GET ────────────────────────────────────────────
	const baselinePromise = sendProbe(targetUrl, customHeaders);

	// ── Probe 2: SQLi payload in query string ────────────────────────────
	const sqliUrl = targetUrl.includes('?')
		? `${targetUrl}&id=1' OR 1=1--`
		: `${targetUrl}${SQLI_PARAM}`;
	const sqliPromise = sendProbe(sqliUrl, customHeaders);

	// ── Probe 3: XSS payload in User-Agent ───────────────────────────────
	const xssHeaders = { ...customHeaders, 'user-agent': XSS_USER_AGENT };
	const xssPromise = sendProbe(targetUrl, xssHeaders);

	const [baseline, sqliResp, xssResp] = await Promise.all([baselinePromise, sqliPromise, xssPromise]);

	// Check that at least one probe succeeded
	if (!baseline && !sqliResp && !xssResp) {
		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			wafDetected: false,
			wafName: null,
			confidence: 0,
			evidence: ['All probes failed - target may be unreachable'],
			bypassSuggestions: [],
			elapsedMs: Date.now() - start,
		};
	}

	// Evaluate signatures across all responses
	const match = evaluateSignatures([baseline, sqliResp, xssResp]);

	// Additional heuristic: check for status-code divergence between
	// baseline and attack probes (common WAF behavior).
	const heuristicEvidence: string[] = [];
	if (baseline && sqliResp && baseline.statusCode !== sqliResp.statusCode) {
		if (sqliResp.statusCode === 403 || sqliResp.statusCode === 406 || sqliResp.statusCode === 429 || sqliResp.statusCode === 503) {
			heuristicEvidence.push(
				`Status code divergence: baseline=${baseline.statusCode}, SQLi probe=${sqliResp.statusCode} (possible WAF block)`
			);
		}
	}
	if (baseline && xssResp && baseline.statusCode !== xssResp.statusCode) {
		if (xssResp.statusCode === 403 || xssResp.statusCode === 406 || xssResp.statusCode === 429 || xssResp.statusCode === 503) {
			heuristicEvidence.push(
				`Status code divergence: baseline=${baseline.statusCode}, XSS probe=${xssResp.statusCode} (possible WAF block)`
			);
		}
	}

	if (match) {
		const evidence = [...match.evidence, ...heuristicEvidence];
		const bypassSuggestions = [...match.bypasses, ...GENERIC_BYPASS_SUGGESTIONS];

		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			wafDetected: true,
			wafName: match.wafName,
			confidence: match.confidence,
			evidence,
			bypassSuggestions,
			elapsedMs: Date.now() - start,
		};
	}

	// No signature matched, but heuristic might indicate generic WAF
	if (heuristicEvidence.length > 0) {
		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			wafDetected: true,
			wafName: 'Unknown / Generic WAF',
			confidence: 0.3,
			evidence: heuristicEvidence,
			bypassSuggestions: [...GENERIC_BYPASS_SUGGESTIONS],
			elapsedMs: Date.now() - start,
		};
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		wafDetected: false,
		wafName: null,
		confidence: 0,
		evidence: ['No WAF signatures or behavioral indicators detected'],
		bypassSuggestions: [],
		elapsedMs: Date.now() - start,
	};
}

/**
 * Generate a human-readable Markdown report from a WAF detection result.
 */
export function generateWafDetectReport(result: WafDetectResult): string {
	const lines: string[] = [];

	lines.push('# Scylla Recon - WAF Detection Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **WAF Detected:** ${result.wafDetected ? 'Yes' : 'No'}`);
	if (result.wafName) {
		lines.push(`- **WAF Name:** ${result.wafName}`);
	}
	lines.push(`- **Confidence:** ${Math.round(result.confidence * 100)}%`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	// Evidence
	lines.push('## Evidence');
	lines.push('');
	if (result.evidence.length === 0) {
		lines.push('No evidence collected.');
	} else {
		for (const ev of result.evidence) {
			lines.push(`- ${ev}`);
		}
	}
	lines.push('');

	// Bypass suggestions
	if (result.wafDetected && result.bypassSuggestions.length > 0) {
		lines.push('## Bypass Suggestions');
		lines.push('');
		lines.push(`> These are informational bypass techniques for **${result.wafName ?? 'the detected WAF'}**.`);
		lines.push('> Use responsibly and only against systems you have authorization to test.');
		lines.push('');

		// Split into WAF-specific and generic
		const wafSpecific = result.bypassSuggestions.slice(0, result.bypassSuggestions.length - GENERIC_BYPASS_SUGGESTIONS.length);
		const generic = result.bypassSuggestions.slice(result.bypassSuggestions.length - GENERIC_BYPASS_SUGGESTIONS.length);

		if (wafSpecific.length > 0) {
			lines.push(`### ${result.wafName}-Specific`);
			lines.push('');
			for (const s of wafSpecific) {
				lines.push(`- ${s}`);
			}
			lines.push('');
		}

		if (generic.length > 0) {
			lines.push('### Generic Techniques');
			lines.push('');
			for (const s of generic) {
				lines.push(`- ${s}`);
			}
			lines.push('');
		}
	}

	return lines.join('\n');
}
