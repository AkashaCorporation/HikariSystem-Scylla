/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { ScyllaJobFile } from './types';

export interface PipelinePreset {
	id: string;
	name: string;
	description: string;
	template: ScyllaJobFile;
}

export const PRESETS: PipelinePreset[] = [
	{
		id: 'web-recon',
		name: 'Web Recon',
		description: 'Full web reconnaissance: port scan, tech detect, crawl, dir fuzz.',
		template: {
			target: '${target}',
			outDir: '.scylla/pipeline-output',
			quiet: true,
			steps: [
				{
					cmd: 'scylla.recon.portscanHeadless',
					args: { ports: 'top1000' },
					timeoutMs: 120_000,
				},
				{
					cmd: 'scylla.recon.techdetectHeadless',
					timeoutMs: 30_000,
				},
				{
					cmd: 'scylla.recon.crawlHeadless',
					args: { maxDepth: 3, maxPages: 200, scope: 'host' },
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.recon.dirfuzzHeadless',
					args: { wordlist: 'common' },
					timeoutMs: 600_000,
				},
			],
		},
	},
	{
		id: 'vuln-scan',
		name: 'Vulnerability Scan',
		description: 'Run all vulnerability scanners against a target.',
		template: {
			target: '${target}',
			outDir: '.scylla/pipeline-output',
			quiet: true,
			steps: [
				{
					cmd: 'scylla.scanner.autoHeadless',
					args: { createFindings: true },
					timeoutMs: 600_000,
				},
			],
		},
	},
	{
		id: 'htb-easy',
		name: 'HTB Easy Machine',
		description: 'Full pipeline for easy HackTheBox machines: recon + scan + report.',
		template: {
			target: '${target}',
			outDir: '.scylla/pipeline-output',
			quiet: true,
			steps: [
				{
					cmd: 'scylla.recon.portscanHeadless',
					args: { ports: 'top1000' },
					timeoutMs: 120_000,
				},
				{
					cmd: 'scylla.recon.techdetectHeadless',
					timeoutMs: 30_000,
				},
				{
					cmd: 'scylla.recon.crawlHeadless',
					args: { maxDepth: 3, maxPages: 500, scope: 'host' },
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.recon.dirfuzzHeadless',
					args: { wordlist: 'common', extensions: ['.php', '.html', '.txt', '.bak'] },
					timeoutMs: 600_000,
				},
				{
					cmd: 'scylla.scanner.sqliHeadless',
					args: { crawlResultFile: '${outDir}/03-scylla-recon-crawlheadless.json', createFindings: true },
					continueOnError: true,
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.scanner.xssHeadless',
					args: { crawlResultFile: '${outDir}/03-scylla-recon-crawlheadless.json', createFindings: true },
					continueOnError: true,
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.scanner.lfiHeadless',
					args: { crawlResultFile: '${outDir}/03-scylla-recon-crawlheadless.json', createFindings: true },
					continueOnError: true,
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.scanner.sstiHeadless',
					args: { crawlResultFile: '${outDir}/03-scylla-recon-crawlheadless.json', createFindings: true },
					continueOnError: true,
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.scanner.secretsHeadless',
					args: { crawlResultFile: '${outDir}/03-scylla-recon-crawlheadless.json', createFindings: true },
					continueOnError: true,
					timeoutMs: 120_000,
				},
				{
					cmd: 'scylla.reporting.generateHeadless',
					args: { title: 'HTB Machine Assessment' },
					timeoutMs: 60_000,
				},
			],
		},
	},
	{
		id: 'secrets-only',
		name: 'Secrets Hunt',
		description: 'Crawl and scan for exposed secrets and credentials.',
		template: {
			target: '${target}',
			outDir: '.scylla/pipeline-output',
			quiet: true,
			steps: [
				{
					cmd: 'scylla.recon.crawlHeadless',
					args: { maxDepth: 3, maxPages: 300, scope: 'host' },
					timeoutMs: 300_000,
				},
				{
					cmd: 'scylla.scanner.secretsHeadless',
					args: { crawlResultFile: '${outDir}/01-scylla-recon-crawlheadless.json', createFindings: true },
					timeoutMs: 120_000,
				},
				{
					cmd: 'scylla.reporting.generateHeadless',
					args: { title: 'Secrets Assessment' },
					timeoutMs: 60_000,
				},
			],
		},
	},
];

export function getPreset(id: string): PipelinePreset | undefined {
	return PRESETS.find(p => p.id === id);
}

export function materializePreset(preset: PipelinePreset, target: string, outDir?: string): ScyllaJobFile {
	const json = JSON.stringify(preset.template);
	const replaced = json
		.replace(/\$\{target\}/g, target)
		.replace(/\$\{outDir\}/g, outDir ?? '.scylla/pipeline-output');
	return JSON.parse(replaced);
}
