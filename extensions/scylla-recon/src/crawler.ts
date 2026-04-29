/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { delay } from './concurrencyPool';
import type {
	CrawlResult,
	DiscoveredEndpoint,
	DiscoveredForm,
	DiscoveredParameter,
	FormInput
} from './types';

const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_MAX_PAGES = 200;
const DEFAULT_DELAY_MS = 100;
const DEFAULT_TIMEOUT_MS = 10_000;

export interface CrawlProgress {
	visited: number;
	queued: number;
	found: number;
}

export async function crawl(
	seedUrl: string,
	options: {
		maxDepth?: number;
		maxPages?: number;
		scope?: 'host' | 'domain' | 'path';
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {},
	onProgress?: (progress: CrawlProgress) => void
): Promise<CrawlResult> {
	const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
	const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const scope = options.scope ?? 'host';

	let normalizedSeedUrl = seedUrl.trim();
	if (!normalizedSeedUrl.toLowerCase().startsWith('http://') && !normalizedSeedUrl.toLowerCase().startsWith('https://')) {
		normalizedSeedUrl = `http://${normalizedSeedUrl}`;
	}

	let seedParsed: URL;
	try {
		seedParsed = new URL(normalizedSeedUrl);
	} catch (e) {
		throw new Error(`Invalid URL provided for crawling: ${seedUrl}`);
	}

	const visited = new Set<string>();
	const queue: Array<{ url: string; depth: number }> = [{ url: normalizeUrl(normalizedSeedUrl), depth: 0 }];
	const discovered: DiscoveredEndpoint[] = [];
	const forms: DiscoveredForm[] = [];
	const parameters: DiscoveredParameter[] = [];
	const jsRoutes: string[] = [];
	const externalLinks: string[] = [];
	const paramsSeen = new Set<string>();

	const start = Date.now();

	while (queue.length > 0 && visited.size < maxPages) {
		const item = queue.shift()!;
		const normalized = normalizeUrl(item.url);

		if (visited.has(normalized)) { continue; }
		if (item.depth > maxDepth) { continue; }
		if (!isInScope(normalized, seedParsed, scope)) {
			externalLinks.push(normalized);
			continue;
		}

		visited.add(normalized);

		try {
			const sendOptions: Record<string, unknown> = {
				url: normalized,
				method: 'GET',
				timeoutMs,
				followRedirects: true,
				quiet: true,
				maxBodyBytes: 1024 * 1024,
			};

			if (options.headers) { sendOptions.headers = options.headers; }
			if (options.cookie) {
				sendOptions.headers = {
					...(sendOptions.headers as Record<string, string> ?? {}),
					cookie: options.cookie
				};
			}

			const result = await vscode.commands.executeCommand<{
				response: {
					statusCode: number;
					headers: Record<string, string | string[]>;
					bodyText: string;
					finalUrl: string;
				};
			}>('scylla.http.sendHeadless', sendOptions);

			if (!result?.response) { continue; }

			const { response } = result;
			const contentType = getHeader(response.headers, 'content-type') ?? '';

			discovered.push({
				url: normalized,
				method: 'GET',
				statusCode: response.statusCode,
				contentType,
				depth: item.depth,
			});

			// Extract URL query parameters
			try {
				const parsedUrl = new URL(normalized);
				for (const [name] of parsedUrl.searchParams) {
					const key = `query:${name}:${normalized}`;
					if (!paramsSeen.has(key)) {
						paramsSeen.add(key);
						parameters.push({ name, location: 'query', url: normalized, method: 'GET' });
					}
				}
			} catch { /* ignore */ }

			// Only parse HTML content
			if (!contentType.includes('text/html') && !contentType.includes('text/xhtml')) {
				// Check for JS routes if it's JavaScript
				if (contentType.includes('javascript') || normalized.endsWith('.js')) {
					jsRoutes.push(...extractJsRoutes(response.bodyText, seedParsed));
				}
				continue;
			}

			const body = response.bodyText;

			// Extract links
			const links = extractLinks(body, normalized);
			for (const link of links) {
				if (!visited.has(normalizeUrl(link))) {
					queue.push({ url: link, depth: item.depth + 1 });
				}
			}

			// Extract forms
			const pageForms = extractForms(body, normalized);
			forms.push(...pageForms);
			for (const form of pageForms) {
				for (const input of form.inputs) {
					if (input.name) {
						const loc = form.method.toUpperCase() === 'GET' ? 'query' : 'body';
						const key = `${loc}:${input.name}:${form.action}`;
						if (!paramsSeen.has(key)) {
							paramsSeen.add(key);
							parameters.push({
								name: input.name,
								location: loc as 'query' | 'body',
								url: form.action,
								method: form.method.toUpperCase()
							});
						}
					}
				}
			}

			// Extract JS routes from inline scripts
			const inlineJsRoutes = extractJsRoutes(body, seedParsed);
			for (const route of inlineJsRoutes) {
				if (!jsRoutes.includes(route)) { jsRoutes.push(route); }
			}

			// Extract script sources for crawling
			const scriptSrcs = extractScriptSources(body, normalized);
			for (const src of scriptSrcs) {
				if (!visited.has(normalizeUrl(src))) {
					queue.push({ url: src, depth: item.depth + 1 });
				}
			}

		} catch {
			// Network errors are expected during crawling
		}

		if (delayMs > 0) { await delay(delayMs); }

		if (onProgress && visited.size % 5 === 0) {
			onProgress({ visited: visited.size, queued: queue.length, found: discovered.length });
		}
	}

	return {
		generatedAt: new Date().toISOString(),
		seedUrl,
		pagesVisited: visited.size,
		discovered,
		forms,
		parameters,
		jsRoutes,
		externalLinks: [...new Set(externalLinks)],
		elapsedMs: Date.now() - start,
	};
}

function normalizeUrl(url: string): string {
	try {
		const parsed = new URL(url);
		parsed.hash = '';
		return parsed.href;
	} catch {
		return url;
	}
}

function isInScope(url: string, seed: URL, scope: 'host' | 'domain' | 'path'): boolean {
	try {
		const parsed = new URL(url);
		if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') { return false; }
		switch (scope) {
			case 'host':
				return parsed.hostname === seed.hostname;
			case 'domain': {
				const seedParts = seed.hostname.split('.');
				const urlParts = parsed.hostname.split('.');
				const seedDomain = seedParts.slice(-2).join('.');
				const urlDomain = urlParts.slice(-2).join('.');
				return seedDomain === urlDomain;
			}
			case 'path':
				return parsed.hostname === seed.hostname && parsed.pathname.startsWith(seed.pathname);
			default:
				return parsed.hostname === seed.hostname;
		}
	} catch {
		return false;
	}
}

function extractLinks(html: string, pageUrl: string): string[] {
	const links: string[] = [];
	// <a href="...">
	const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi;
	let match: RegExpExecArray | null;
	while ((match = hrefRegex.exec(html)) !== null) {
		const resolved = resolveUrl(match[1], pageUrl);
		if (resolved) { links.push(resolved); }
	}
	return links;
}

function extractForms(html: string, pageUrl: string): DiscoveredForm[] {
	const forms: DiscoveredForm[] = [];
	const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
	let formMatch: RegExpExecArray | null;

	while ((formMatch = formRegex.exec(html)) !== null) {
		const formTag = formMatch[0];
		const formBody = formMatch[1];

		const actionMatch = formTag.match(/action\s*=\s*["']([^"']*)["']/i);
		const methodMatch = formTag.match(/method\s*=\s*["']([^"']*)["']/i);

		const action = resolveUrl(actionMatch?.[1] ?? '', pageUrl) ?? pageUrl;
		const method = methodMatch?.[1]?.toUpperCase() ?? 'GET';

		const inputs: FormInput[] = [];
		const inputRegex = /<(?:input|select|textarea)[^>]*>/gi;
		let inputMatch: RegExpExecArray | null;

		while ((inputMatch = inputRegex.exec(formBody)) !== null) {
			const tag = inputMatch[0];
			const nameMatch = tag.match(/name\s*=\s*["']([^"']*)["']/i);
			const typeMatch = tag.match(/type\s*=\s*["']([^"']*)["']/i);
			const valueMatch = tag.match(/value\s*=\s*["']([^"']*)["']/i);

			if (nameMatch) {
				inputs.push({
					name: nameMatch[1],
					type: typeMatch?.[1] ?? 'text',
					value: valueMatch?.[1],
				});
			}
		}

		forms.push({ action, method, inputs, pageUrl });
	}

	return forms;
}

function extractJsRoutes(content: string, seed: URL): string[] {
	const routes: string[] = [];
	const patterns = [
		/["'`](\/api\/[^"'`\s]+)["'`]/g,
		/["'`](\/v[0-9]+\/[^"'`\s]+)["'`]/g,
		/fetch\s*\(\s*["'`](\/[^"'`\s]+)["'`]/g,
		/axios\.[a-z]+\s*\(\s*["'`](\/[^"'`\s]+)["'`]/g,
		/\.(?:get|post|put|delete|patch)\s*\(\s*["'`](\/[^"'`\s]+)["'`]/g,
		/["'`](\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+){1,5})["'`]/g,
	];

	const seen = new Set<string>();
	for (const pattern of patterns) {
		let match: RegExpExecArray | null;
		while ((match = pattern.exec(content)) !== null) {
			const route = match[1];
			if (!seen.has(route) && route.length > 1 && !route.includes('..') &&
				!route.endsWith('.css') && !route.endsWith('.png') && !route.endsWith('.jpg') &&
				!route.endsWith('.svg') && !route.endsWith('.ico') && !route.endsWith('.woff')) {
				seen.add(route);
				routes.push(`${seed.protocol}//${seed.host}${route}`);
			}
		}
	}
	return routes;
}

function extractScriptSources(html: string, pageUrl: string): string[] {
	const sources: string[] = [];
	const srcRegex = /<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
	let match: RegExpExecArray | null;
	while ((match = srcRegex.exec(html)) !== null) {
		const resolved = resolveUrl(match[1], pageUrl);
		if (resolved) { sources.push(resolved); }
	}
	return sources;
}

function resolveUrl(href: string, base: string): string | null {
	if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('data:')) {
		return null;
	}
	try {
		return new URL(href, base).href;
	} catch {
		return null;
	}
}

function getHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
	const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
	if (!key) { return undefined; }
	const val = headers[key];
	return Array.isArray(val) ? val[0] : val;
}

export function generateCrawlReport(result: CrawlResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Recon - Crawl Report');
	lines.push('');
	lines.push(`- **Seed URL:** \`${result.seedUrl}\``);
	lines.push(`- **Pages Visited:** ${result.pagesVisited}`);
	lines.push(`- **Endpoints Found:** ${result.discovered.length}`);
	lines.push(`- **Forms Found:** ${result.forms.length}`);
	lines.push(`- **Parameters Found:** ${result.parameters.length}`);
	lines.push(`- **JS Routes Found:** ${result.jsRoutes.length}`);
	lines.push(`- **External Links:** ${result.externalLinks.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.discovered.length > 0) {
		lines.push('## Discovered Endpoints');
		lines.push('');
		lines.push('| URL | Method | Status | Content-Type | Depth |');
		lines.push('|-----|--------|--------|-------------|-------|');
		for (const ep of result.discovered.slice(0, 200)) {
			const ct = ep.contentType.split(';')[0].trim();
			lines.push(`| \`${truncate(ep.url, 60)}\` | ${ep.method} | ${ep.statusCode} | ${ct} | ${ep.depth} |`);
		}
		lines.push('');
	}

	if (result.forms.length > 0) {
		lines.push('## Discovered Forms');
		lines.push('');
		for (const form of result.forms) {
			lines.push(`### ${form.method} \`${truncate(form.action, 60)}\``);
			lines.push(`Page: \`${truncate(form.pageUrl, 60)}\``);
			lines.push('');
			if (form.inputs.length > 0) {
				lines.push('| Name | Type | Default Value |');
				lines.push('|------|------|---------------|');
				for (const input of form.inputs) {
					lines.push(`| ${input.name} | ${input.type} | ${input.value ?? '-'} |`);
				}
				lines.push('');
			}
		}
	}

	if (result.parameters.length > 0) {
		lines.push('## Discovered Parameters');
		lines.push('');
		lines.push('| Name | Location | URL | Method |');
		lines.push('|------|----------|-----|--------|');
		for (const param of result.parameters.slice(0, 100)) {
			lines.push(`| ${param.name} | ${param.location} | \`${truncate(param.url, 50)}\` | ${param.method} |`);
		}
		lines.push('');
	}

	if (result.jsRoutes.length > 0) {
		lines.push('## JS Routes');
		lines.push('');
		for (const route of result.jsRoutes.slice(0, 50)) {
			lines.push(`- \`${route}\``);
		}
		lines.push('');
	}

	return lines.join('\n');
}

function truncate(text: string, maxLen: number): string {
	return text.length > maxLen ? text.slice(0, maxLen) + '...' : text;
}
