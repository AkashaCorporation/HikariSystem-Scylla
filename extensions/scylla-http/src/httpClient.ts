/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as http from 'http';
import * as https from 'https';
import type { HttpRequestDefinition, HttpResponseData } from './types';
import { normalizeHeaders } from './artifacts';
import { hostResolver } from './hostResolver';

const DEFAULT_REDIRECT_LIMIT = 5;

export async function performRequest(
	requestDefinition: HttpRequestDefinition,
	maxBodyBytes: number
): Promise<HttpResponseData> {
	return performRequestInternal(requestDefinition, maxBodyBytes, DEFAULT_REDIRECT_LIMIT);
}

function performRequestInternal(
	requestDefinition: HttpRequestDefinition,
	maxBodyBytes: number,
	redirectsRemaining: number,
	redirectCount: number = 0,
	currentUrl: string = requestDefinition.url
): Promise<HttpResponseData> {
	return new Promise<HttpResponseData>((resolve, reject) => {
		const url = new URL(currentUrl);
		const transport = url.protocol === 'https:' ? https : http;
		const method = requestDefinition.method.toUpperCase();
		const headers = { ...normalizeHeaders(requestDefinition.headers) };
		const body = typeof requestDefinition.body === 'string' ? Buffer.from(requestDefinition.body, 'utf8') : undefined;
		if (body && !hasHeader(headers, 'content-length')) {
			headers['content-length'] = String(body.length);
		}
		if (body && !hasHeader(headers, 'content-type')) {
			headers['content-type'] = 'application/json; charset=utf-8';
		}

		const startedAt = Date.now();
		const requestOptions: http.RequestOptions = {
			protocol: url.protocol,
			hostname: url.hostname,
			port: url.port ? Number(url.port) : undefined,
			path: `${url.pathname}${url.search}`,
			method,
			headers,
			timeout: requestDefinition.timeoutMs,
		};

		// Inject custom DNS resolver so Scylla can resolve CTF/HTB vhosts
		// (e.g. facts.htb → 10.129.x.x) without touching the system hosts file.
		if (!hostResolver.isEmpty) {
			requestOptions.lookup = hostResolver.lookup;
		}

		const request = transport.request(
			requestOptions,
			incoming => {
				const chunks: Buffer[] = [];
				let bodyBytes = 0;
				let storedBytes = 0;
				let truncated = false;

				incoming.on('data', (chunk: Buffer | string) => {
					const normalizedChunk = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
					bodyBytes += normalizedChunk.length;
					if (storedBytes >= maxBodyBytes) {
						truncated = true;
						return;
					}

					const remaining = maxBodyBytes - storedBytes;
					if (normalizedChunk.length <= remaining) {
						chunks.push(normalizedChunk);
						storedBytes += normalizedChunk.length;
						return;
					}

					chunks.push(normalizedChunk.subarray(0, remaining));
					storedBytes += remaining;
					truncated = true;
				});

				incoming.on('end', async () => {
					const statusCode = incoming.statusCode ?? 0;
					const location = typeof incoming.headers.location === 'string' ? incoming.headers.location : undefined;
					
					const currentResponseData: HttpResponseData = {
						statusCode,
						statusMessage: incoming.statusMessage ?? '',
						headers: normalizeResponseHeaders(incoming.headers),
						bodyText: decodeResponseBody(Buffer.concat(chunks)),
						bodyBytes,
						truncated,
						elapsedMs: Date.now() - startedAt,
						redirected: redirectCount > 0,
						redirectCount,
						finalUrl: currentUrl
					};

					if (
						requestDefinition.followRedirects !== false &&
						location &&
						isRedirectStatus(statusCode) &&
						redirectsRemaining > 0
					) {
						try {
							const redirectedUrl = new URL(location, currentUrl).toString();
							const nextRequest: HttpRequestDefinition = {
								...requestDefinition,
								method: statusCode === 303 ? 'GET' : requestDefinition.method,
								body: statusCode === 303 ? undefined : requestDefinition.body
							};
							const redirected = await performRequestInternal(
								nextRequest,
								maxBodyBytes,
								redirectsRemaining - 1,
								redirectCount + 1,
								redirectedUrl
							);
							resolve(redirected);
						} catch (error: unknown) {
							// If the redirect failed (e.g. DNS ENOTFOUND on a local CTF domain),
							// we gracefully return the current 30X response instead of crashing the pipeline.
							resolve(currentResponseData);
						}
						return;
					}

					resolve(currentResponseData);
				});

				incoming.on('error', reject);
			}
		);

		request.on('timeout', () => {
			request.destroy(new Error(`Request timed out after ${requestDefinition.timeoutMs}ms.`));
		});
		request.on('error', reject);

		if (body) {
			request.write(body);
		}

		request.end();
	});
}

function normalizeResponseHeaders(headers: http.IncomingHttpHeaders): Record<string, string | string[]> {
	const normalized: Record<string, string | string[]> = {};
	for (const [name, value] of Object.entries(headers)) {
		if (value === undefined) {
			continue;
		}
		normalized[name.toLowerCase()] = Array.isArray(value) ? value : String(value);
	}
	return normalized;
}

function decodeResponseBody(buffer: Buffer): string {
	try {
		return buffer.toString('utf8');
	} catch {
		return buffer.toString('base64');
	}
}

function hasHeader(headers: Record<string, string>, expectedName: string): boolean {
	return Object.keys(headers).some(name => name.toLowerCase() === expectedName.toLowerCase());
}

function isRedirectStatus(statusCode: number): boolean {
	return statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308;
}
