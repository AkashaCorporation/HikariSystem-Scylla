/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// CSRF Token Extractor — Auto-extract tokens from HTML forms & headers
// ---------------------------------------------------------------------------

/**
 * Extract a CSRF token from an HTML body using a CSS-like selector.
 *
 * Supported selectors:
 * - `input[name='_token']` → <input name="_token" value="xxx">
 * - `meta[name='csrf-token']` → <meta name="csrf-token" content="xxx">
 * - `input[name='csrfmiddlewaretoken']` (Django)
 * - `input[name='authenticity_token']` (Rails)
 *
 * Falls back to common patterns when no explicit selector is provided.
 */
export function extractCsrfFromHtml(html: string, selector?: string): string | undefined {
	if (selector) {
		return extractBySelector(html, selector);
	}

	// Try common CSRF token patterns in order of prevalence
	const commonSelectors = [
		// Standard HTML input fields
		'input[name="_token"]',
		'input[name="csrf_token"]',
		'input[name="_csrf"]',
		'input[name="csrfmiddlewaretoken"]',   // Django
		'input[name="authenticity_token"]',     // Rails
		'input[name="__RequestVerificationToken"]', // ASP.NET
		'input[name="nonce"]',
		'input[name="_nonce"]',
		// Meta tags
		'meta[name="csrf-token"]',
		'meta[name="csrf_token"]',
		'meta[name="_token"]',
	];

	for (const sel of commonSelectors) {
		const value = extractBySelector(html, sel);
		if (value) { return value; }
	}

	return undefined;
}

/**
 * Extract a CSRF token from response headers.
 *
 * Checks common CSRF headers:
 * - `X-CSRF-Token`
 * - `X-XSRF-TOKEN`
 * - `X-CSRFToken`
 */
export function extractCsrfFromHeaders(
	headers: Record<string, string | string[] | undefined>,
	customHeaderName?: string,
): { token: string; headerName: string } | undefined {

	const headerNames = [
		customHeaderName,
		'x-csrf-token',
		'x-xsrf-token',
		'x-csrftoken',
		'csrf-token',
	].filter((h): h is string => !!h);

	for (const [name, value] of Object.entries(headers)) {
		const normalized = name.toLowerCase();
		if (headerNames.includes(normalized)) {
			const tokenValue = Array.isArray(value) ? value[0] : value;
			if (tokenValue && tokenValue.trim().length > 0) {
				return { token: tokenValue.trim(), headerName: name };
			}
		}
	}

	return undefined;
}

/**
 * Determine the correct CSRF header name to use when sending requests.
 * Defaults to X-CSRF-Token if no specific header was configured or detected.
 */
export function getCsrfHeaderName(customHeaderName?: string, detectedHeaderName?: string): string {
	return customHeaderName ?? detectedHeaderName ?? 'X-CSRF-Token';
}

// ---------------------------------------------------------------------------
// Selector-based HTML extraction (minimal regex-based parser)
// ---------------------------------------------------------------------------

/**
 * Parse a simplified CSS selector and extract the value from HTML.
 *
 * Supports:
 * - `input[name='xxx']` → extracts value attribute
 * - `meta[name='xxx']` → extracts content attribute
 * - `input[name="xxx"]` → both quote types
 */
function extractBySelector(html: string, selector: string): string | undefined {
	// Parse: tagName[attrName='attrValue']
	const match = selector.match(/^(\w+)\[(\w+)=['"](.*?)['"]\]$/);
	if (!match) { return undefined; }

	const [, tagName, attrName, attrValue] = match;

	// Build a regex to find the tag with the matching attribute
	// Example: <input name="_token" value="abc123" />
	const tagRegex = new RegExp(
		`<${tagName}\\b[^>]*?${attrName}\\s*=\\s*["']${escapeRegex(attrValue)}["'][^>]*?>`,
		'gi'
	);

	const tagMatch = tagRegex.exec(html);
	if (!tagMatch) { return undefined; }

	const tagHtml = tagMatch[0];

	// Extract the value/content attribute from the matched tag
	const valueAttr = tagName.toLowerCase() === 'meta' ? 'content' : 'value';
	const valueRegex = new RegExp(`${valueAttr}\\s*=\\s*["'](.*?)["']`, 'i');
	const valueMatch = valueRegex.exec(tagHtml);

	return valueMatch?.[1] ?? undefined;
}

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
