/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as net from 'net';
import { ConcurrencyPool } from './concurrencyPool';
import { lookupService, parsePorts } from './portDatabase';
import { governor } from './governor';
import type { OpenPort, PortScanResult } from './types';

const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_CONCURRENCY = 100;
const BANNER_WAIT_MS = 2_000;
const BANNER_MAX_BYTES = 512;

export interface PortScanProgress {
	scanned: number;
	total: number;
	found: number;
}

export async function scanPorts(
	target: string,
	portsSpec: string,
	timeoutMs: number = DEFAULT_TIMEOUT_MS,
	concurrency: number = DEFAULT_CONCURRENCY,
	onProgress?: (progress: PortScanProgress) => void
): Promise<PortScanResult> {
	// Governor scope gate: a port scan is raw TCP egress that does NOT pass
	// through the scylla-http chokepoint, so it must enforce the engagement scope
	// itself. This blocks scanning out-of-scope, internal (RFC1918), localhost, or
	// cloud-metadata hosts when a scope is configured (permissive when it is not).
	governor.assertInScope(target);

	const ports = parsePorts(portsSpec);
	if (ports.length === 0) {
		throw new Error('No valid ports to scan.');
	}

	const pool = new ConcurrencyPool(Math.min(concurrency, ports.length));
	const openPorts: OpenPort[] = [];
	let closedCount = 0;
	let filteredCount = 0;
	let scanned = 0;

	const start = Date.now();

	const tasks = ports.map(port =>
		pool.run(async () => {
			// Per-connect governor token + concurrency slot so the per-host rate
			// limit and global concurrency cap also bound the port-scan burst.
			await governor.acquire(target);
			const result = await probePort(target, port, timeoutMs).finally(() => governor.release(target));
			scanned++;

			if (result.state === 'open') {
				openPorts.push({ port: result.port, state: 'open', service: result.service, banner: result.banner, protocol: 'tcp' });
			} else if (result.state === 'closed') {
				closedCount++;
			} else {
				filteredCount++;
			}

			if (onProgress && scanned % 10 === 0) {
				onProgress({ scanned, total: ports.length, found: openPorts.length });
			}
		})
	);

	await Promise.all(tasks);

	openPorts.sort((a, b) => a.port - b.port);

	return {
		generatedAt: new Date().toISOString(),
		target,
		portsScanned: ports.length,
		openPorts,
		closedCount,
		filteredCount,
		elapsedMs: Date.now() - start,
	};
}

interface ProbeResult {
	port: number;
	state: 'open' | 'closed' | 'filtered';
	service: string;
	banner?: string;
}

function probePort(host: string, port: number, timeoutMs: number): Promise<ProbeResult> {
	return new Promise<ProbeResult>(resolve => {
		const socket = new net.Socket();
		let banner: string | undefined;
		let settled = false;

		const finish = (state: 'open' | 'closed' | 'filtered') => {
			if (settled) { return; }
			settled = true;
			socket.removeAllListeners();
			socket.destroy();
			resolve({
				port,
				state,
				service: lookupService(port),
				banner: state === 'open' ? banner : undefined
			});
		};

		socket.setTimeout(timeoutMs);

		socket.on('connect', () => {
			// Port is reachable — disable the connect-phase socket timeout so it
			// does not race against BANNER_WAIT_MS for servers that require a
			// client request before sending data (HTTP, FTP, SMTP, etc.)
			socket.setTimeout(0);
			// Try to grab a banner
			const bannerTimeout = setTimeout(() => finish('open'), BANNER_WAIT_MS);
			socket.once('data', (data: Buffer) => {
				clearTimeout(bannerTimeout);
				const raw = data.subarray(0, BANNER_MAX_BYTES).toString('utf8');
				// Only keep printable chars
				banner = raw.replace(/[^\x20-\x7E\r\n\t]/g, '').trim() || undefined;
				finish('open');
			});
		});

		socket.on('timeout', () => finish('filtered'));
		socket.on('error', (err: NodeJS.ErrnoException) => {
			if (err.code === 'ECONNREFUSED') {
				finish('closed');
			} else {
				finish('filtered');
			}
		});

		socket.connect(port, host);
	});
}

export function generatePortScanReport(result: PortScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Recon - Port Scan Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Ports Scanned:** ${result.portsScanned}`);
	lines.push(`- **Open:** ${result.openPorts.length}`);
	lines.push(`- **Closed:** ${result.closedCount}`);
	lines.push(`- **Filtered:** ${result.filteredCount}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.openPorts.length === 0) {
		lines.push('No open ports found.');
	} else {
		lines.push('## Open Ports');
		lines.push('');
		lines.push('| Port | Protocol | Service | Banner |');
		lines.push('|------|----------|---------|--------|');
		for (const p of result.openPorts) {
			const bannerCol = p.banner ? `\`${p.banner.slice(0, 60)}\`` : '-';
			lines.push(`| ${p.port} | ${p.protocol} | ${p.service} | ${bannerCol} |`);
		}
	}

	lines.push('');
	return lines.join('\n');
}
