/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { ConcurrencyPool, delay } from './concurrencyPool';
import type { DirFuzzHit, DirFuzzResult } from './types';

const DEFAULT_CONCURRENCY = 20;
const DEFAULT_DELAY_MS = 50;
const DEFAULT_TIMEOUT_MS = 10_000;

export interface DirFuzzProgress {
	completed: number;
	total: number;
	found: number;
}

export async function fuzzDirectories(
	baseUrl: string,
	options: {
		wordlist?: 'common' | 'medium' | string;
		extensions?: string[];
		concurrency?: number;
		delayMs?: number;
		timeoutMs?: number;
		followRedirects?: boolean;
		filterStatus?: number[];
		headers?: Record<string, string>;
		cookie?: string;
	} = {},
	onProgress?: (progress: DirFuzzProgress) => void
): Promise<DirFuzzResult> {
	const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const followRedirects = options.followRedirects ?? false;
	const extensions = options.extensions ?? [''];

	const words = loadWordlist(options.wordlist ?? 'common');
	if (words.length === 0) {
		throw new Error('Wordlist is empty.');
	}

	// Normalize base URL
	const cleanBase = baseUrl.replace(/\/+$/, '');

	// Build all paths to test
	const paths: string[] = [];
	for (const word of words) {
		if (extensions.length === 0 || (extensions.length === 1 && extensions[0] === '')) {
			paths.push(`/${word}`);
		} else {
			for (const ext of extensions) {
				paths.push(`/${word}${ext.startsWith('.') ? ext : ext ? '.' + ext : ''}`);
			}
			// Also test without extension
			if (!extensions.includes('')) {
				paths.push(`/${word}`);
			}
		}
	}

	const pool = new ConcurrencyPool(concurrency);
	const discovered: DirFuzzHit[] = [];
	let completed = 0;
	const totalRequests = paths.length;

	const start = Date.now();

	const tasks = paths.map(testPath =>
		pool.run(async () => {
			const url = `${cleanBase}${testPath}`;
			try {
				const sendOptions: Record<string, unknown> = {
					url,
					method: 'GET',
					timeoutMs,
					followRedirects,
					quiet: true,
					maxBodyBytes: 4096,
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
						bodyBytes: number;
						finalUrl: string;
					};
				}>('scylla.http.sendHeadless', sendOptions);

				if (!result?.response) { return; }

				const { statusCode, headers, bodyBytes, finalUrl } = result.response;

				// Filter by status code
				if (options.filterStatus && options.filterStatus.length > 0) {
					if (!options.filterStatus.includes(statusCode)) { return; }
				} else {
					// Default: exclude 404
					if (statusCode === 404) { return; }
				}

				const contentType = getHeader(headers, 'content-type') ?? '';
				const location = getHeader(headers, 'location');

				discovered.push({
					path: testPath,
					url,
					statusCode,
					contentLength: bodyBytes,
					contentType: contentType.split(';')[0].trim(),
					redirectUrl: statusCode >= 300 && statusCode < 400 ? location : undefined,
				});
			} catch {
				// Network errors are expected
			}

			completed++;
			if (delayMs > 0) { await delay(delayMs); }

			if (onProgress && completed % 20 === 0) {
				onProgress({ completed, total: totalRequests, found: discovered.length });
			}
		})
	);

	await Promise.all(tasks);

	discovered.sort((a, b) => a.statusCode - b.statusCode || a.path.localeCompare(b.path));

	return {
		generatedAt: new Date().toISOString(),
		baseUrl: cleanBase,
		wordlistUsed: options.wordlist ?? 'common',
		totalRequests,
		discovered,
		elapsedMs: Date.now() - start,
	};
}

function loadWordlist(spec: string): string[] {
	// Built-in wordlists
	if (spec === 'common' || spec === 'medium') {
		const wordlistPath = path.join(__dirname, '..', 'src', 'wordlists', `${spec}.txt`);
		// Try compiled output path first, then source path
		const paths = [
			path.join(__dirname, 'wordlists', `${spec}.txt`),
			wordlistPath,
			path.join(__dirname, '..', 'wordlists', `${spec}.txt`),
		];
		for (const p of paths) {
			if (fs.existsSync(p)) {
				return fs.readFileSync(p, 'utf8')
					.split('\n')
					.map(l => l.trim())
					.filter(l => l.length > 0 && !l.startsWith('#'));
			}
		}
		// Fallback: embedded minimal common wordlist
		return EMBEDDED_COMMON_WORDS;
	}

	// Custom file path
	if (fs.existsSync(spec)) {
		return fs.readFileSync(spec, 'utf8')
			.split('\n')
			.map(l => l.trim())
			.filter(l => l.length > 0 && !l.startsWith('#'));
	}

	throw new Error(`Wordlist not found: ${spec}`);
}

function getHeader(headers: Record<string, string | string[]>, name: string): string | undefined {
	const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
	if (!key) { return undefined; }
	const val = headers[key];
	return Array.isArray(val) ? val[0] : val;
}

export function generateDirFuzzReport(result: DirFuzzResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Recon - Directory Fuzzing Report');
	lines.push('');
	lines.push(`- **Base URL:** \`${result.baseUrl}\``);
	lines.push(`- **Wordlist:** ${result.wordlistUsed}`);
	lines.push(`- **Total Requests:** ${result.totalRequests}`);
	lines.push(`- **Discovered:** ${result.discovered.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.discovered.length === 0) {
		lines.push('No hidden paths discovered.');
	} else {
		lines.push('## Discovered Paths');
		lines.push('');
		lines.push('| Path | Status | Size | Content-Type | Redirect |');
		lines.push('|------|--------|------|-------------|----------|');
		for (const hit of result.discovered) {
			const redirect = hit.redirectUrl ? `\`${hit.redirectUrl}\`` : '-';
			lines.push(`| \`${hit.path}\` | ${hit.statusCode} | ${hit.contentLength} | ${hit.contentType} | ${redirect} |`);
		}
	}

	lines.push('');
	return lines.join('\n');
}

/**
 * Embedded fallback wordlist - top ~500 common web paths.
 * Used when the wordlist file cannot be found at the expected path.
 */
const EMBEDDED_COMMON_WORDS: string[] = [
	'admin', 'login', 'wp-admin', 'administrator', 'wp-login.php',
	'dashboard', 'api', 'config', 'backup', 'test', 'dev',
	'staging', 'old', 'new', 'temp', 'tmp', 'upload', 'uploads',
	'images', 'img', 'css', 'js', 'static', 'assets', 'media',
	'files', 'docs', 'doc', 'documents', 'downloads', 'download',
	'data', 'database', 'db', 'sql', 'mysql', 'phpmyadmin',
	'pma', 'adminer', 'phpinfo', 'info', 'debug', 'trace',
	'console', 'shell', 'cmd', 'command', 'exec', 'system',
	'server-status', 'server-info', 'status', 'health', 'healthcheck',
	'robots.txt', 'sitemap.xml', '.htaccess', '.htpasswd', '.env',
	'.git', '.svn', '.hg', 'web.config', 'crossdomain.xml',
	'favicon.ico', 'humans.txt', 'security.txt', '.well-known',
	'wp-content', 'wp-includes', 'wp-json', 'xmlrpc.php',
	'readme', 'README', 'changelog', 'CHANGELOG', 'license',
	'cgi-bin', 'bin', 'sbin', 'scripts', 'cron', 'cronjob',
	'include', 'includes', 'inc', 'lib', 'libs', 'library',
	'vendor', 'node_modules', 'bower_components', 'packages',
	'src', 'source', 'sources', 'build', 'dist', 'release',
	'public', 'private', 'internal', 'external', 'secure',
	'secret', 'secrets', 'hidden', 'restricted', 'protected',
	'user', 'users', 'account', 'accounts', 'profile', 'profiles',
	'member', 'members', 'register', 'signup', 'signin', 'auth',
	'authentication', 'authorize', 'authorization', 'oauth',
	'token', 'tokens', 'session', 'sessions', 'cookie', 'cookies',
	'reset', 'password', 'forgot', 'recover', 'recovery',
	'home', 'index', 'default', 'main', 'root', 'base',
	'about', 'contact', 'help', 'support', 'faq', 'terms',
	'privacy', 'policy', 'legal', 'tos', 'eula',
	'search', 'find', 'query', 'lookup', 'browse', 'explore',
	'blog', 'news', 'posts', 'articles', 'pages', 'content',
	'category', 'categories', 'tag', 'tags', 'archive', 'archives',
	'feed', 'rss', 'atom', 'xml', 'json', 'api/v1', 'api/v2',
	'rest', 'graphql', 'swagger', 'openapi', 'api-docs',
	'panel', 'cpanel', 'control', 'manager', 'manage',
	'portal', 'gateway', 'proxy', 'redirect', 'forward',
	'log', 'logs', 'error', 'errors', 'report', 'reports',
	'monitor', 'monitoring', 'metrics', 'stats', 'statistics',
	'analytics', 'tracking', 'telemetry', 'audit', 'activity',
	'install', 'setup', 'wizard', 'configure', 'settings',
	'preferences', 'options', 'config.php', 'config.yml',
	'config.json', 'config.xml', 'config.ini', 'config.bak',
	'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old',
	'application', 'app', 'webapp', 'webapps', 'service',
	'services', 'microservice', 'endpoint', 'endpoints',
	'checkout', 'cart', 'shop', 'store', 'product', 'products',
	'order', 'orders', 'payment', 'pay', 'invoice', 'invoices',
	'mail', 'email', 'webmail', 'smtp', 'imap', 'pop',
	'chat', 'message', 'messages', 'notification', 'notifications',
	'socket', 'websocket', 'ws', 'wss', 'realtime',
	'file', 'filemanager', 'editor', 'ide', 'workspace',
	'git', 'gitlab', 'github', 'bitbucket', 'repository',
	'jenkins', 'ci', 'cd', 'pipeline', 'build-status',
	'docker', 'kubernetes', 'k8s', 'container', 'containers',
	'server', 'cluster', 'node', 'nodes', 'instance',
	'aws', 'azure', 'gcp', 'cloud', 'cdn',
	'cache', 'redis', 'memcached', 'elasticsearch',
	'graphql', 'grpc', 'soap', 'wsdl', 'wadl',
	'v1', 'v2', 'v3', 'version', 'latest',
	'mobile', 'android', 'ios', 'app', 'native',
	'socket.io', 'hub', 'connect', 'callback',
	'export', 'import', 'migrate', 'migration', 'seed',
	'cron', 'job', 'jobs', 'task', 'tasks', 'queue', 'worker',
	'healthz', 'readyz', 'livez', 'ping', 'pong',
	'actuator', 'jolokia', 'jmx', 'heap', 'threaddump',
	'backup.zip', 'backup.tar.gz', 'backup.sql', 'dump.sql',
	'database.sql', 'db.sql', 'site.sql', 'export.sql',
	'.DS_Store', 'Thumbs.db', 'desktop.ini',
	'.gitignore', '.dockerignore', '.editorconfig',
	'Dockerfile', 'docker-compose.yml', 'Makefile',
	'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
	'Procfile', 'Vagrantfile', '.travis.yml', 'Jenkinsfile',
];
