/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License for XSStrike-inspired logic.
 *--------------------------------------------------------------------------------------------*/

import type { ParameterTarget } from '../types';
import { RateLimiter } from './rateLimiter';
import * as vscode from 'vscode';

export interface FilterScore {
	char: string;
	status: 'passed' | 'encoded' | 'deleted' | 'blocked';
}

/**
 * WafFuzzer
 * Sends boundary canaries to accurately measure which characters the server WAF/Filter
 * allows, HTML-encodes, deletes, or outright blocks (HTTP 403).
 */
export class WafFuzzer {
	private rateLimiter: RateLimiter;
	private targetUrl: string;
	private headers?: Record<string, string>;
	private cookie?: string;
	private timeoutMs: number;

	// Characters critical for XSS construction
	private readonly FUZZ_CHARS = ['<', '>', '"', "'", '/', '\\', '(', ')', ';', ':'];

	constructor(
		rateLimiter: RateLimiter,
		targetUrl: string,
		timeoutMs: number,
		headers?: Record<string, string>,
		cookie?: string
	) {
		this.rateLimiter = rateLimiter;
		this.targetUrl = targetUrl;
		this.timeoutMs = timeoutMs;
		this.headers = headers;
		this.cookie = cookie;
	}

	/**
	 * Scans a parameter to determine the fate of each critical character.
	 */
	public async detectFilters(param: ParameterTarget): Promise<FilterScore[]> {
		const scores: FilterScore[] = [];

		for (const char of this.FUZZ_CHARS) {
			const canaryPrefix = `dlx${Math.random().toString(36).slice(2, 6)}`;
			const canarySuffix = `${Math.random().toString(36).slice(2, 6)}xld`;
			const payload = `${canaryPrefix}${char}${canarySuffix}`;

			const response = await this.rateLimiter.executeWithBackoff(
				() => this.sendPayload(param, payload),
				(res) => res !== null && res.statusCode < 400 // Success if not 400, 403, 429
			);

			if (!response) {
				scores.push({ char, status: 'blocked' });
				continue;
			}

			const body = response.bodyText;
			
			if (body.includes(payload)) {
				scores.push({ char, status: 'passed' });
			} else if (body.includes(`${canaryPrefix}${this.encodeHtml(char)}${canarySuffix}`)) {
				scores.push({ char, status: 'encoded' });
			} else if (body.includes(`${canaryPrefix}${canarySuffix}`)) {
				scores.push({ char, status: 'deleted' });
			} else {
				// Partially mangled or blocked by application logic without 403
				scores.push({ char, status: 'blocked' });
			}
		}

		return scores;
	}

	private encodeHtml(char: string): string {
		const entities: Record<string, string> = {
			'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;', '&': '&amp;'
		};
		return entities[char] || char;
	}

	private async sendPayload(param: ParameterTarget, payload: string) {
		try {
			const url = new URL(this.targetUrl);
			const sendOptions: Record<string, unknown> = {
				timeoutMs: this.timeoutMs,
				followRedirects: true,
				quiet: true,
				maxBodyBytes: 128 * 1024,
			};

			if (this.headers) { sendOptions.headers = { ...this.headers }; }
			if (this.cookie) {
				sendOptions.headers = {
					...(sendOptions.headers as Record<string, string> ?? {}),
					cookie: this.cookie,
				};
			}

			if (param.location === 'query') {
				url.searchParams.set(param.name, payload);
				sendOptions.url = url.href;
				sendOptions.method = 'GET';
			} else if (param.location === 'body') {
				sendOptions.url = url.href;
				sendOptions.method = 'POST';
				sendOptions.body = `${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
				sendOptions.headers = {
					...(sendOptions.headers as Record<string, string> ?? {}),
					'content-type': 'application/x-www-form-urlencoded',
				};
			}

			const result = await vscode.commands.executeCommand<{
				response: { statusCode: number; bodyText: string; elapsedMs: number };
			}>('scylla.http.sendHeadless', sendOptions);

			return result?.response || null;
		} catch {
			return null;
		}
	}
}
