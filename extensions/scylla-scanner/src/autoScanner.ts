/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { scanCors } from './corsScanner';
import { scanDomxss } from './domxssScanner';
import { scanGraphql } from './graphqlScanner';
import { scanHeaders } from './headersScanner';
import { scanLfi } from './lfiScanner';
import { scanParams } from './paramsScanner';
import { scanRedirect } from './redirectScanner';
import { scanSecrets } from './secretsScanner';
import { scanSqli } from './sqliScanner';
import { scanSsrf } from './ssrfScanner';
import { scanSsti } from './sstiScanner';
import { scanXss } from './xssScanner';
import type { AutoScanResult, ParameterTarget, VulnFinding } from './types';

type ScannerName = 'sqli' | 'xss' | 'lfi' | 'ssti' | 'secrets' | 'cors' | 'headers' | 'domxss' | 'params' | 'redirect' | 'jwt' | 'graphql' | 'ssrf';

export async function autoScan(
	targetUrl: string,
	parameters: ParameterTarget[],
	options: {
		scanners?: ScannerName[];
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	} = {}
): Promise<AutoScanResult> {
	const scanners = options.scanners ?? ['sqli', 'xss', 'lfi', 'ssti', 'secrets', 'cors', 'headers'];
	const commonOpts = {
		delayMs: options.delayMs,
		timeoutMs: options.timeoutMs,
		headers: options.headers,
		cookie: options.cookie,
	};

	const allFindings: VulnFinding[] = [];
	const scannerResults: Record<string, { findings: number; elapsedMs: number }> = {};
	const start = Date.now();

	for (const scanner of scanners) {
		const scanStart = Date.now();
		let findings: VulnFinding[] = [];

		try {
			switch (scanner) {
				case 'sqli': {
					const result = await scanSqli(targetUrl, parameters, commonOpts);
					findings = result.findings;
					break;
				}
				case 'xss': {
					const result = await scanXss(targetUrl, parameters, commonOpts);
					findings = result.findings;
					break;
				}
				case 'lfi': {
					const result = await scanLfi(targetUrl, parameters, commonOpts);
					findings = result.findings;
					break;
				}
				case 'ssti': {
					const result = await scanSsti(targetUrl, parameters, commonOpts);
					findings = result.findings;
					break;
				}
				case 'secrets': {
					const result = await scanSecrets({ url: targetUrl, ...commonOpts });
					findings = result.findings;
					break;
				}
				case 'cors': {
					const result = await scanCors(targetUrl, commonOpts);
					findings = result.findings;
					break;
				}
				case 'headers': {
					const result = await scanHeaders(targetUrl, commonOpts);
					findings = result.findings;
					break;
				}
				case 'domxss': {
					const result = await scanDomxss(targetUrl, commonOpts);
					findings = result.findings;
					break;
				}
				case 'params': {
					const result = await scanParams(targetUrl, commonOpts);
					findings = result.findings;
					break;
				}
				case 'redirect': {
					const result = await scanRedirect(targetUrl, parameters, commonOpts);
					findings = result.findings;
					break;
				}
				case 'graphql': {
					const result = await scanGraphql(targetUrl, commonOpts);
					findings = result.findings;
					break;
				}
				case 'ssrf': {
					const result = await scanSsrf(targetUrl, parameters, commonOpts);
					findings = result.findings;
					break;
				}
			}
		} catch {
			// Scanner failed, continue with others
		}

		allFindings.push(...findings);
		scannerResults[scanner] = {
			findings: findings.length,
			elapsedMs: Date.now() - scanStart,
		};
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		scannersRun: scanners,
		totalFindings: allFindings.length,
		findings: allFindings,
		scannerResults,
		elapsedMs: Date.now() - start,
	};
}

export function generateAutoScanReport(result: AutoScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - Auto Scan Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Scanners Run:** ${result.scannersRun.join(', ')}`);
	lines.push(`- **Total Findings:** ${result.totalFindings}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	// Scanner summary
	lines.push('## Scanner Summary');
	lines.push('');
	lines.push('| Scanner | Findings | Time |');
	lines.push('|---------|----------|------|');
	for (const [scanner, stats] of Object.entries(result.scannerResults)) {
		lines.push(`| ${scanner.toUpperCase()} | ${stats.findings} | ${stats.elapsedMs}ms |`);
	}
	lines.push('');

	if (result.totalFindings === 0) {
		lines.push('No vulnerabilities detected.');
	} else {
		// Group by severity
		const bySeverity: Record<string, VulnFinding[]> = {};
		for (const f of result.findings) {
			(bySeverity[f.severity] ??= []).push(f);
		}

		for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
			const group = bySeverity[severity];
			if (!group || group.length === 0) { continue; }

			lines.push(`## ${severity.toUpperCase()} (${group.length})`);
			lines.push('');
			for (const f of group) {
				lines.push(`### [${f.type.toUpperCase()}] ${f.title}`);
				lines.push(`- **Parameter:** \`${f.parameter ?? 'N/A'}\``);
				lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
				lines.push(`- **Payload:** \`${f.payload.slice(0, 80)}\``);
				lines.push(`- **Evidence:** ${f.evidence}`);
				lines.push('');
			}
		}
	}

	return lines.join('\n');
}
