/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import * as fs from 'fs';

// ---------------------------------------------------------------------------
// Built-in Wordlist Registry
// ---------------------------------------------------------------------------

export interface WordlistInfo {
	/** Short identifier (e.g. "common-dirs") */
	id: string;
	/** Human-readable name */
	name: string;
	/** Category for grouping */
	category: 'directories' | 'parameters' | 'subdomains' | 'credentials' | 'payloads' | 'general';
	/** Description */
	description: string;
	/** Absolute path to the .txt file */
	filePath: string;
	/** Number of entries (computed lazily) */
	lineCount?: number;
}

const WORDLISTS_DIR = path.join(__dirname, '..', 'wordlists');

const REGISTRY: Omit<WordlistInfo, 'filePath'>[] = [
	{ id: 'common-dirs', name: 'Common Directories', category: 'directories', description: 'Frequently found web directories and files (admin panels, configs, backups).' },
	{ id: 'api-endpoints', name: 'API Endpoints', category: 'directories', description: 'REST/GraphQL API path patterns.' },
	{ id: 'common-params', name: 'Common Parameters', category: 'parameters', description: 'Frequently used query/body parameter names.' },
	{ id: 'hidden-params', name: 'Hidden Parameters', category: 'parameters', description: 'Debug, internal, and undocumented parameter names.' },
	{ id: 'common-subdomains', name: 'Common Subdomains', category: 'subdomains', description: 'Popular subdomain prefixes for DNS enumeration.' },
	{ id: 'default-credentials', name: 'Default Credentials', category: 'credentials', description: 'Common username:password pairs for web apps and services.' },
	{ id: 'sqli-payloads', name: 'SQLi Payloads', category: 'payloads', description: 'SQL injection test strings.' },
	{ id: 'xss-payloads', name: 'XSS Payloads', category: 'payloads', description: 'Cross-site scripting test vectors.' },
	{ id: 'lfi-traversals', name: 'LFI Traversals', category: 'payloads', description: 'Local file inclusion path traversal patterns.' },
	{ id: 'ssti-payloads', name: 'SSTI Payloads', category: 'payloads', description: 'Server-side template injection polyglots.' },
	{ id: 'user-agents', name: 'User Agents', category: 'general', description: 'Browser and bot user-agent strings.' },
];

export class WordlistProvider {

	private wordlists: Map<string, WordlistInfo> = new Map();

	constructor() {
		this.loadRegistry();
	}

	private loadRegistry(): void {
		for (const entry of REGISTRY) {
			const filePath = path.join(WORDLISTS_DIR, `${entry.id}.txt`);
			this.wordlists.set(entry.id, { ...entry, filePath });
		}
	}

	/** List all available wordlists */
	listWordlists(): WordlistInfo[] {
		const result: WordlistInfo[] = [];
		for (const [, wl] of this.wordlists) {
			if (!wl.lineCount && fs.existsSync(wl.filePath)) {
				wl.lineCount = this.countLines(wl.filePath);
			}
			result.push({ ...wl });
		}
		return result;
	}

	/** Get a wordlist by ID */
	getWordlist(id: string): WordlistInfo | undefined {
		return this.wordlists.get(id);
	}

	/** Get the absolute file path for a wordlist by ID */
	getPath(id: string): string | undefined {
		const wl = this.wordlists.get(id);
		if (!wl) { return undefined; }
		return fs.existsSync(wl.filePath) ? wl.filePath : undefined;
	}

	/** Preview the first N lines of a wordlist */
	preview(id: string, maxLines: number = 50): string[] {
		const wl = this.wordlists.get(id);
		if (!wl || !fs.existsSync(wl.filePath)) { return []; }

		const content = fs.readFileSync(wl.filePath, 'utf8');
		const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
		return lines.slice(0, maxLines);
	}

	/** List wordlists by category */
	listByCategory(category: string): WordlistInfo[] {
		return this.listWordlists().filter(wl => wl.category === category);
	}

	private countLines(filePath: string): number {
		try {
			const content = fs.readFileSync(filePath, 'utf8');
			return content.split(/\r?\n/).filter(l => l.trim().length > 0).length;
		} catch {
			return 0;
		}
	}
}
