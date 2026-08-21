/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { CommandCapability, PipelineRunStatus, PipelineStep, PipelineStepStatus, ScyllaJobFile } from './types';

// ---------------------------------------------------------------------------
// Command Capabilities Registry
// ---------------------------------------------------------------------------

const COMMAND_CAPABILITIES = new Map<string, CommandCapability>([
	// scylla-http
	['scylla.http.sendHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: false }],
	['scylla.http.saveRequestHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.http.replayHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: false }],
	// scylla-recon
	['scylla.recon.portscanHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.recon.crawlHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.recon.dirfuzzHeadless', { headless: true, defaultTimeoutMs: 600_000, validateOutput: true }],
	['scylla.recon.techdetectHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	['scylla.recon.wafdetectHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	// scylla-scanner
	['scylla.scanner.sqliHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.xssHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.lfiHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.sstiHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.secretsHeadless', { headless: true, defaultTimeoutMs: 120_000, validateOutput: true }],
	['scylla.scanner.corsHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	['scylla.scanner.headersHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	['scylla.scanner.domxssHeadless', { headless: true, defaultTimeoutMs: 120_000, validateOutput: true }],
	['scylla.scanner.paramsHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.redirectHeadless', { headless: true, defaultTimeoutMs: 120_000, validateOutput: true }],
	['scylla.scanner.jwtHeadless', { headless: true, defaultTimeoutMs: 60_000, validateOutput: true }],
	['scylla.scanner.graphqlHeadless', { headless: true, defaultTimeoutMs: 120_000, validateOutput: true }],
	['scylla.scanner.ssrfHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.autoHeadless', { headless: true, defaultTimeoutMs: 600_000, validateOutput: true }],
	// scylla-scanner exploitation
	['scylla.scanner.sqliExtractHeadless', { headless: true, defaultTimeoutMs: 600_000, validateOutput: true }],
	['scylla.scanner.xssExploitHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	['scylla.scanner.lfiExploitHeadless', { headless: true, defaultTimeoutMs: 600_000, validateOutput: true }],
	// scylla-findings
	['scylla.findings.createHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.findings.appendEvidenceHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.findings.createFromHttpHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	// scylla-engagements
	['scylla.engagement.createHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.getHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.listHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.setActiveHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.addIdentityHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.registerResourceHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.recordTransactionHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	['scylla.engagement.probeHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: false }],
	['scylla.engagement.authorizationMatrixHeadless', { headless: true, defaultTimeoutMs: 10_000, validateOutput: false }],
	// scylla-reporting
	['scylla.reporting.generateHeadless', { headless: true, defaultTimeoutMs: 60_000, validateOutput: true }],
	// hexcore utilities (reusable)
	['hexcore.hashcalc.calculate', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	['hexcore.strings.extract', { headless: true, defaultTimeoutMs: 60_000, validateOutput: true }],
	['hexcore.base64.decodeHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: true }],
	['hexcore.yara.scan', { headless: true, defaultTimeoutMs: 120_000, validateOutput: true }],
	// scylla-auth (Scylla 2.0)
	['scylla.auth.loginHeadless', { headless: true, defaultTimeoutMs: 60_000, validateOutput: false }],
	['scylla.auth.oauthHeadless', { headless: true, defaultTimeoutMs: 60_000, validateOutput: false }],
	['scylla.auth.sessionCheckHeadless', { headless: true, defaultTimeoutMs: 30_000, validateOutput: false }],
	['scylla.auth.sessionRefreshHeadless', { headless: true, defaultTimeoutMs: 60_000, validateOutput: false }],
	['scylla.auth.getHeadersHeadless', { headless: true, defaultTimeoutMs: 5_000, validateOutput: false }],
	// scylla 2.0 scanners
	['scylla.scanner.idorHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.privescHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
	['scylla.scanner.massAssignHeadless', { headless: true, defaultTimeoutMs: 300_000, validateOutput: true }],
]);

const COMMAND_ALIASES = new Map<string, string>([
	['scylla.scan.sqli', 'scylla.scanner.sqliHeadless'],
	['scylla.scan.xss', 'scylla.scanner.xssHeadless'],
	['scylla.scan.lfi', 'scylla.scanner.lfiHeadless'],
	['scylla.scan.ssti', 'scylla.scanner.sstiHeadless'],
	['scylla.scan.secrets', 'scylla.scanner.secretsHeadless'],
	['scylla.scan.auto', 'scylla.scanner.autoHeadless'],
	['scylla.recon.portscan', 'scylla.recon.portscanHeadless'],
	['scylla.recon.crawl', 'scylla.recon.crawlHeadless'],
	['scylla.recon.dirfuzz', 'scylla.recon.dirfuzzHeadless'],
	['scylla.recon.techdetect', 'scylla.recon.techdetectHeadless'],
	['scylla.recon.wafdetect', 'scylla.recon.wafdetectHeadless'],
	['scylla.scan.cors', 'scylla.scanner.corsHeadless'],
	['scylla.scan.headers', 'scylla.scanner.headersHeadless'],
	['scylla.scan.domxss', 'scylla.scanner.domxssHeadless'],
	['scylla.scan.params', 'scylla.scanner.paramsHeadless'],
	['scylla.scan.redirect', 'scylla.scanner.redirectHeadless'],
	['scylla.scan.jwt', 'scylla.scanner.jwtHeadless'],
	['scylla.scan.graphql', 'scylla.scanner.graphqlHeadless'],
	['scylla.scan.ssrf', 'scylla.scanner.ssrfHeadless'],
	// exploitation aliases
	['scylla.exploit.sqli', 'scylla.scanner.sqliExtractHeadless'],
	['scylla.exploit.xss', 'scylla.scanner.xssExploitHeadless'],
	['scylla.exploit.lfi', 'scylla.scanner.lfiExploitHeadless'],
	// scylla 2.0 aliases
	['scylla.scan.idor', 'scylla.scanner.idorHeadless'],
	['scylla.scan.privesc', 'scylla.scanner.privescHeadless'],
	['scylla.scan.massAssign', 'scylla.scanner.massAssignHeadless'],
]);

// ---------------------------------------------------------------------------
// Pipeline Runner
// ---------------------------------------------------------------------------

export class PipelineRunner {

	/**
	 * When auto-detect discovers a vhost redirect (e.g. 10.129.10.78 → wingdata.htb),
	 * this is set so that all subsequent web-facing steps use the vhost URL instead
	 * of the raw IP.  The raw IP stays in `job.target` for port scanning.
	 */
	private detectedVhostUrl: string | undefined;

	async runJobFile(jobFilePath: string, quietOverride?: boolean): Promise<PipelineRunStatus> {
		this.detectedVhostUrl = undefined;
		const resolvedPath = this.resolvePath(jobFilePath);
		if (!fs.existsSync(resolvedPath)) {
			throw new Error(`Job file not found: ${resolvedPath}`);
		}

		const raw = fs.readFileSync(resolvedPath, 'utf8');
		let job: ScyllaJobFile;
		try {
			job = JSON.parse(raw);
		} catch {
			throw new Error(`Invalid JSON in job file: ${resolvedPath}`);
		}

		this.validateJob(job);

		const quiet = quietOverride ?? job.quiet ?? true;
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!workspaceRoot) { throw new Error('A workspace folder is required.'); }

		const outDir = path.isAbsolute(job.outDir)
			? job.outDir
			: path.join(workspaceRoot, job.outDir);

		fs.mkdirSync(outDir, { recursive: true });

		const status: PipelineRunStatus = {
			jobFile: resolvedPath,
			target: job.target,
			outDir,
			status: 'running',
			startedAt: new Date().toISOString(),
			totalSteps: job.steps.length,
			completedSteps: 0,
			failedSteps: 0,
			steps: [],
		};

		const statusPath = path.join(outDir, 'scylla-pipeline.status.json');
		const logPath = path.join(outDir, 'scylla-pipeline.log');

		// Clear previous log file on new run
		fs.writeFileSync(logPath, '', 'utf8');

		const log: string[] = [];
		const appendLog = (line: string) => {
			log.push(line);
			fs.appendFileSync(logPath, line + '\n', 'utf8');
		};

		const flushStatus = () => {
			fs.writeFileSync(statusPath, JSON.stringify(status, null, 2), 'utf8');
		};

		flushStatus();

		appendLog('='.repeat(60));
		appendLog('Scylla Pipeline Runner');
		appendLog(`Workspace: ${workspaceRoot}`);
		appendLog(`Job file:  ${resolvedPath}`);
		appendLog(`Target:    ${job.target}`);
		appendLog(`Output:    ${outDir}`);
		appendLog(`Steps:     ${job.steps.length}`);
		appendLog(`Started:   ${status.startedAt}`);
		appendLog('='.repeat(60));

		// Register custom DNS hosts (resolves CTF/HTB vhosts without system hosts file)
		if (job.hosts && Object.keys(job.hosts).length > 0) {
			try {
				await vscode.commands.executeCommand('scylla.http.setHostsHeadless', { hosts: job.hosts });
				const entries = Object.entries(job.hosts).map(([h, ip]) => `${h} -> ${ip}`).join(', ');
				appendLog(`[DNS] Registered ${Object.keys(job.hosts).length} custom host(s): ${entries}`);
			} catch {
				appendLog('[DNS] Warning: Could not register custom hosts (scylla-http not available).');
			}
		}

		// Governor scope publish: constrain the egress layer to this job's declared
		// target(s) BEFORE any auth login or scan step runs (mirrors the custom-hosts
		// registration above). Cleared in the finally below so one job's scope never
		// leaks into the next run or an interactive send.
		await this.publishScope(job, appendLog);

		try {

		// Auth Phase: Handle Multi-Profile Authentication Before Scanning
		if (job.auth?.profiles && Object.keys(job.auth.profiles).length > 0) {
			const shouldLoginAll = job.auth.loginAll ?? true;
			if (shouldLoginAll) {
				appendLog('[Auth] Initializing authentication profiles...');
				try {
					const result = await vscode.commands.executeCommand<{ successfulLogins: number; totalProfiles: number }>(
						'scylla.auth.loginHeadless',
						{ profiles: job.auth.profiles, loginAll: true, quiet: true }
					);
					if (result) {
						appendLog(`[Auth] Logged in successfully: ${result.successfulLogins}/${result.totalProfiles} profiles.`);
						if (result.successfulLogins < result.totalProfiles) {
							appendLog('[Auth] WARNING: Not all profiles logged in successfully. Check target reachability or credentials.');
						}
					}
				} catch (err: unknown) {
					appendLog(`[Auth] ERROR: Auth extension failed or threw error: ${err}`);
					if (!job.steps[0]?.continueOnError) {
						status.status = 'error';
						flushStatus();
						return status; // Abort if auth fails and it's critical
					}
				}
			} else {
				appendLog('[Auth] Profiles registered (skipping immediate login due to loginAll=false).');
				try {
					await vscode.commands.executeCommand(
						'scylla.auth.loginHeadless',
						{ profiles: job.auth.profiles, quiet: true }
					);
				} catch { /* ignore */ }
			}
		}

		for (let i = 0; i < job.steps.length; i++) {
			const step = job.steps[i];
			const stepStatus = await this.executeStep(i, step, job, outDir, quiet, appendLog);
			status.steps.push(stepStatus);

			// Auto-detect vhost from redirect after recon steps
			if (stepStatus.status === 'ok' && stepStatus.outputPath) {
				await this.autoDetectVhost(stepStatus, job, appendLog);
			}

			if (stepStatus.status === 'ok') {
				status.completedSteps++;
			} else {
				status.failedSteps++;
				if (!step.continueOnError) {
					appendLog(`[Step ${i + 1}] ERROR: Pipeline aborted.`);
					status.status = 'error';
					flushStatus();
					break;
				}
			}
			flushStatus();
		}

		if (status.status === 'running') {
			status.status = status.failedSteps > 0 ? 'error' : 'ok';
		}
		status.finishedAt = new Date().toISOString();

		appendLog('');
		appendLog(`Job finished with status: ${status.status}`);
		appendLog(`Completed: ${status.completedSteps}/${status.totalSteps} steps (Failed: ${status.failedSteps})`);
		
		flushStatus();
		return status;
		} finally {
			await this.clearScope(appendLog);
		}
	}

	private async executeStep(
		index: number,
		step: PipelineStep,
		job: ScyllaJobFile,
		outDir: string,
		quiet: boolean,
		appendLog: (line: string) => void,
	): Promise<PipelineStepStatus> {
		const resolvedCmd = COMMAND_ALIASES.get(step.cmd) ?? step.cmd;
		const capability = COMMAND_CAPABILITIES.get(resolvedCmd);

		const stepStatus: PipelineStepStatus = {
			index,
			cmd: step.cmd,
			resolvedCmd,
			status: 'error',
			startedAt: new Date().toISOString(),
			finishedAt: '',
			durationMs: 0,
			attemptCount: 0,
		};

		const timeoutMs = step.timeoutMs ?? capability?.defaultTimeoutMs ?? 60_000;
		const retryCount = step.retryCount ?? 0;
		const retryDelayMs = step.retryDelayMs ?? 1_000;
		
		appendLog(`[Step ${index + 1}] ${step.cmd} -> ${resolvedCmd}`);
		appendLog(`[Step ${index + 1}] Timeout: ${timeoutMs}ms`);
		appendLog(`[Step ${index + 1}] Retries: ${retryCount} (delay=${retryDelayMs}ms)`);

		if (capability && !capability.headless) {
			stepStatus.status = 'skipped';
			stepStatus.error = capability.reason ?? 'Command is not headless-safe.';
			stepStatus.finishedAt = new Date().toISOString();
			appendLog(`[Step ${index + 1}] SKIPPED: ${stepStatus.error}`);
			return stepStatus;
		}

		// Build command options
		const commandOptions = this.buildCommandOptions(step, job, outDir, index, quiet);

		// Auto-generate output path if step has output config or we want structured output
		let outputPath: string | undefined;
		if (step.output?.path) {
			outputPath = step.output.path.startsWith('/')
				? step.output.path
				: path.join(outDir, step.output.path);
			commandOptions.output = { path: outputPath, format: step.output.format ?? 'json' };
		} else {
			// Auto-generate output path
			const stepName = resolvedCmd.replace(/\./g, '-').toLowerCase();
			outputPath = path.join(outDir, `${String(index + 1).padStart(2, '0')}-${stepName}.json`);
			commandOptions.output = { path: outputPath, format: 'json' };
		}

		stepStatus.outputPath = outputPath;

		for (let attempt = 0; attempt <= retryCount; attempt++) {
			stepStatus.attemptCount = attempt + 1;
			appendLog(`[Step ${index + 1}] Attempt ${attempt + 1}/${retryCount + 1}`);

			if (attempt > 0) {
				await this.sleep(retryDelayMs);
			}

			try {
				const startTime = Date.now();

				const result = await Promise.race<unknown>([
					vscode.commands.executeCommand(resolvedCmd, commandOptions),
					this.timeout(timeoutMs),
				]);

				stepStatus.durationMs = Date.now() - startTime;

				if (result === '__TIMEOUT__') {
					stepStatus.status = 'timeout';
					stepStatus.error = `Step timed out after ${timeoutMs}ms`;
					appendLog(`[Step ${index + 1}] TIMEOUT (${timeoutMs}ms)`);
					continue;
				}

				// If we got a result and output was expected, write it
				if (result && outputPath && !fs.existsSync(outputPath)) {
					fs.mkdirSync(path.dirname(outputPath), { recursive: true });
					fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
				}
				
				// Handle Auth Auto-Refresh logic if target returned 401/403
				if (job.auth?.autoRefresh !== false) {
					// Check if result has a response object with statusCode (common for scylla.http and scanners)
					const anyResult = result as any;
					if (anyResult?.response?.statusCode === 401 || anyResult?.response?.statusCode === 403) {
						appendLog(`[Step ${index + 1}] Received auto-refreshable status code (${anyResult.response.statusCode}). Attempting session refresh...`);
						try {
							const refreshResponse = await vscode.commands.executeCommand<{ success: boolean; refreshCount: number }>(
								'scylla.auth.sessionRefreshHeadless',
								{ refreshAll: true, quiet: true }
							);
							if (refreshResponse?.success) {
								appendLog(`[Step ${index + 1}] Session refresh successful. Retrying step...`);
								if (attempt < retryCount) {
									continue; // Retry the step since we refreshed successfully
								} else {
									appendLog(`[Step ${index + 1}] Session refreshed but out of retries.`);
								}
							} else {
								appendLog(`[Step ${index + 1}] Session refresh failed.`);
							}
						} catch (refreshErr) {
							appendLog(`[Step ${index + 1}] Failed to call refresh command: ${refreshErr}`);
						}
					}
				}

				stepStatus.status = 'ok';
				stepStatus.finishedAt = new Date().toISOString();
				appendLog(`[Step ${index + 1}] OK (${stepStatus.durationMs}ms, attempts=${stepStatus.attemptCount})`);
				return stepStatus;

			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				stepStatus.error = message;
				appendLog(`[Step ${index + 1}] ERROR: ${message}`);
			}
		}

		stepStatus.finishedAt = new Date().toISOString();
		return stepStatus;
	}

	private buildCommandOptions(
		step: PipelineStep,
		job: ScyllaJobFile,
		outDir: string,
		_index: number,
		quiet: boolean,
	): Record<string, unknown> {
		const options: Record<string, unknown> = {
			quiet,
			...(step.args ?? {}),
		};

		// Pass target as url or target depending on what the command expects
		// `target` stays raw (hostname/IP) for port scanning
		// `url`    always has http:// prefix for web scanners that call new URL()
		// If auto-detect found a vhost (e.g. wingdata.htb), use it for web-facing URL
		// so requests go to the correct virtual host instead of getting 301 redirects.
		if (!options.url && !options.target) {
			options.target = job.target;
			if (this.detectedVhostUrl) {
				options.url = this.detectedVhostUrl;
			} else {
				options.url = /^https?:\/\//i.test(job.target)
					? job.target
					: 'http://' + job.target;
			}
		}

		// Replace template variables
		// Scanners like sqliHeadless explicitly look for paths using their hardcoded template
		// Wait! HexCore had a static path in the `.scylla_job.json` but it now executes inside dynamic `outDir`.
		// We'll replace the literally defined `outDir` from the JSON with our actual resolved `outDir` strings.
		const variables: Record<string, string> = {
			target: job.target,
			outDir: outDir,
			// Allow users to just type ${workspaceRoot}
			workspaceRoot: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '',
			...(job.variables ?? {}),
		};

		// If the job step has a hardcoded path matching the JSON outDir, replace it with the dynamic outDir
		this.replaceStaticPrefixes(options, job.outDir, outDir);

		this.replaceVariables(options, variables);

		return options;
	}

	private replaceStaticPrefixes(obj: Record<string, unknown>, staticPrefix: string, dynamicPrefix: string): void {
		// Example: staticPrefix: .scylla/pipeline-output
		// dynamicPrefix: C:\Users\... \.scylla\pipeline-output-3
		
		// Convert to posix for easier matching in json paths 
		const normalizedStatic = staticPrefix.replace(/\\/g, '/');
		
		for (const [key, value] of Object.entries(obj)) {
			if (typeof value === 'string') {
				let replaced = value.replace(/\\/g, '/');
				if (replaced.includes(normalizedStatic)) {
					// We replace it assuming it's a relative path starting from workspace root
					// But our outDir is already absolute.
					// So if the string contains the staticPrefix, we swap it for the absolute dynamicPrefix.
					replaced = replaced.replace(normalizedStatic, dynamicPrefix.replace(/\\/g, '/'));
					// Flip slashes back to platform specific if needed by path utils, or keep posix (Node fs handles posix)
					obj[key] = replaced;
				}
			} else if (Array.isArray(value)) {
				for (let i = 0; i < value.length; i++) {
					if (typeof value[i] === 'string') {
						let replaced = (value[i] as string).replace(/\\/g, '/');
						if (replaced.includes(normalizedStatic)) {
							replaced = replaced.replace(normalizedStatic, dynamicPrefix.replace(/\\/g, '/'));
							value[i] = replaced;
						}
					}
				}
			} else if (value && typeof value === 'object') {
				this.replaceStaticPrefixes(value as Record<string, unknown>, staticPrefix, dynamicPrefix);
			}
		}
	}

	private replaceVariables(obj: Record<string, unknown>, variables: Record<string, string>): void {
		for (const [key, value] of Object.entries(obj)) {
			if (typeof value === 'string') {
				let replaced = value;
				for (const [varName, varValue] of Object.entries(variables)) {
					replaced = replaced.replace(new RegExp(`\\$\\{${varName}\\}`, 'g'), varValue);
				}
				obj[key] = replaced;
			} else if (Array.isArray(value)) {
				for (let i = 0; i < value.length; i++) {
					if (typeof value[i] === 'string') {
						let replaced = value[i] as string;
						for (const [varName, varValue] of Object.entries(variables)) {
							replaced = replaced.replace(new RegExp(`\\$\\{${varName}\\}`, 'g'), varValue);
						}
						value[i] = replaced;
					}
				}
			} else if (value && typeof value === 'object') {
				this.replaceVariables(value as Record<string, unknown>, variables);
			}
		}
	}

	/**
	 * Publish this job's engagement scope to the governor (egress + auth hosts)
	 * so out-of-scope traffic is blocked. Derived from `job.scope` (if any) plus
	 * the job target and any declared custom-host keys. Best-effort: a missing
	 * scylla-http / scylla-auth extension is tolerated.
	 */
	private async publishScope(job: ScyllaJobFile, appendLog: (line: string) => void): Promise<void> {
		const patterns = this.deriveScopePatterns(job);
		if (patterns.length === 0) { return; }
		try {
			await vscode.commands.executeCommand('scylla.http.setScopeHeadless', { scope: patterns, replace: true });
			appendLog(`[Scope] Engagement scope set: ${patterns.join(', ')}`);
		} catch {
			appendLog('[Scope] Warning: could not set egress scope (scylla-http not available).');
		}
		// Forward-compatible: also scope the auth host if it exposes the command.
		try {
			await vscode.commands.executeCommand('scylla.auth.setScopeHeadless', { scope: patterns, replace: true });
		} catch { /* scylla-auth may not expose scope yet */ }
	}

	/** Drop the ephemeral run scope from the governor (settings scope is untouched). */
	private async clearScope(appendLog: (line: string) => void): Promise<void> {
		try {
			await vscode.commands.executeCommand('scylla.http.clearScopeHeadless');
		} catch { /* ignore */ }
		try {
			await vscode.commands.executeCommand('scylla.auth.clearScopeHeadless');
		} catch { /* ignore */ }
		appendLog('[Scope] Engagement scope cleared.');
	}

	/** Reduce a job's target / scope / hosts into governor host patterns. */
	private deriveScopePatterns(job: ScyllaJobFile): string[] {
		const out = new Set<string>();
		const addHost = (value: string | undefined): void => {
			if (!value || typeof value !== 'string') { return; }
			const v = value.trim();
			if (!v) { return; }
			if (v.startsWith('*.')) { out.add(v.toLowerCase()); return; }
			try {
				const withScheme = v.includes('://') ? v : `http://${v}`;
				const host = new URL(withScheme).hostname.toLowerCase();
				if (host) { out.add(host); }
			} catch {
				const bare = v.toLowerCase().split('/')[0].split(':')[0];
				if (bare) { out.add(bare); }
			}
		};
		addHost(job.target);
		for (const p of job.scope ?? []) { addHost(p); }
		for (const h of Object.keys(job.hosts ?? {})) { addHost(h); }
		return Array.from(out);
	}

	private validateJob(job: ScyllaJobFile): void {
		if (!job.target || typeof job.target !== 'string') {
			throw new Error('Job file must have a "target" field (URL or hostname).');
		}
		if (!job.outDir || typeof job.outDir !== 'string') {
			throw new Error('Job file must have an "outDir" field.');
		}
		if (!Array.isArray(job.steps) || job.steps.length === 0) {
			throw new Error('Job file must have a non-empty "steps" array.');
		}
		for (let i = 0; i < job.steps.length; i++) {
			const step = job.steps[i];
			if (!step.cmd || typeof step.cmd !== 'string') {
				throw new Error(`Step ${i + 1} must have a "cmd" field.`);
			}
		}
		if (job.hosts !== undefined && (typeof job.hosts !== 'object' || Array.isArray(job.hosts))) {
			throw new Error('Job "hosts" must be an object mapping hostnames to IP addresses.');
		}
	}

	validateJobFile(jobFilePath: string): { valid: boolean; errors: string[] } {
		const resolvedPath = this.resolvePath(jobFilePath);
		const errors: string[] = [];

		if (!fs.existsSync(resolvedPath)) {
			return { valid: false, errors: [`File not found: ${resolvedPath}`] };
		}

		let job: ScyllaJobFile;
		try {
			job = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
		} catch {
			return { valid: false, errors: ['Invalid JSON'] };
		}

		try {
			this.validateJob(job);
		} catch (e: unknown) {
			errors.push(e instanceof Error ? e.message : String(e));
		}

		// Check all commands are known
		for (let i = 0; i < job.steps.length; i++) {
			const cmd = job.steps[i].cmd;
			const resolved = COMMAND_ALIASES.get(cmd) ?? cmd;
			if (!COMMAND_CAPABILITIES.has(resolved)) {
				errors.push(`Step ${i + 1}: Unknown command "${cmd}".`);
			}
		}

		return { valid: errors.length === 0, errors };
	}

	listCapabilities(): Array<{ command: string; headless: boolean; defaultTimeoutMs: number }> {
		const result: Array<{ command: string; headless: boolean; defaultTimeoutMs: number }> = [];
		for (const [command, cap] of COMMAND_CAPABILITIES) {
			result.push({ command, headless: cap.headless, defaultTimeoutMs: cap.defaultTimeoutMs });
		}
		return result.sort((a, b) => a.command.localeCompare(b.command));
	}

	/**
	 * After a recon step completes, inspect its output for redirect `Location`
	 * headers pointing to a hostname we haven't registered yet.  When found,
	 * automatically register it via `scylla.http.setHostsHeadless` so that
	 * subsequent steps can resolve the vhost without the system hosts file.
	 *
	 * Typical case: techdetect hits `http://10.129.10.5` → 302 → `http://facts.htb/`
	 * We extract `facts.htb`, derive the IP from `job.target`, and register it.
	 */
	private async autoDetectVhost(
		stepStatus: PipelineStepStatus,
		job: ScyllaJobFile,
		appendLog: (line: string) => void,
	): Promise<void> {
		// Only process recon steps that might have redirect headers
		const reconCommands = [
			'scylla.recon.techdetectHeadless',
			'scylla.recon.wafdetectHeadless',
			'scylla.recon.crawlHeadless',
		];
		if (!reconCommands.includes(stepStatus.resolvedCmd)) { return; }
		if (!stepStatus.outputPath || !fs.existsSync(stepStatus.outputPath)) { return; }

		try {
			const output = JSON.parse(fs.readFileSync(stepStatus.outputPath, 'utf8'));
			const locations: string[] = [];

			// techdetect/wafdetect: headers.location
			if (output.headers?.location) {
				locations.push(output.headers.location);
			}
			// crawl: discovered URLs or finalUrl
			if (output.finalUrl && typeof output.finalUrl === 'string') {
				locations.push(output.finalUrl);
			}
			// crawl: externalLinks
			if (Array.isArray(output.externalLinks)) {
				locations.push(...output.externalLinks.filter((l: unknown) => typeof l === 'string'));
			}

			if (locations.length === 0) { return; }

			// Extract the raw IP from job.target (strip protocol/port/path)
			const targetRaw = job.target.replace(/^https?:\/\//, '').split(/[:/]/)[0];
			const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(targetRaw);
			if (!isIp) { return; } // Auto-detect only makes sense when target is an IP

			const hostsToRegister: Record<string, string> = {};

			for (const loc of locations) {
				try {
					const locUrl = new URL(loc.startsWith('http') ? loc : `http://${loc}`);
					const hostname = locUrl.hostname.toLowerCase();
					// Skip if it's an IP itself or already registered in job.hosts
					if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) { continue; }
					if (job.hosts?.[hostname]) { continue; }
					hostsToRegister[hostname] = targetRaw;
				} catch {
					// Invalid URL, skip
				}
			}

			if (Object.keys(hostsToRegister).length === 0) { return; }

			await vscode.commands.executeCommand('scylla.http.setHostsHeadless', { hosts: hostsToRegister });
			for (const [hostname, ip] of Object.entries(hostsToRegister)) {
				appendLog(`[Auto-DNS] Registered ${hostname} -> ${ip} (detected from ${stepStatus.cmd} redirect)`);
			}

			// Keep the governor scope consistent with what the pipeline now scans:
			// each detected vhost resolves to the target IP (the same box), so add
			// them to the engagement scope ADDITIVELY. Without this, an enforced
			// scope would block the very vhost traffic the pipeline just switched to.
			try {
				const newScope = Object.keys(hostsToRegister);
				await vscode.commands.executeCommand('scylla.http.setScopeHeadless', { scope: newScope, replace: false });
				await vscode.commands.executeCommand('scylla.auth.setScopeHeadless', { scope: newScope, replace: false });
				appendLog(`[Scope] Extended engagement scope with detected vhost(s): ${newScope.join(', ')}`);
			} catch { /* scope commands are best-effort */ }

			// Use the first detected vhost as the URL for all subsequent web-facing steps.
			// This prevents every request from hitting the raw IP and getting 301 redirects.
			if (!this.detectedVhostUrl) {
				const firstHostname = Object.keys(hostsToRegister)[0];
				this.detectedVhostUrl = `http://${firstHostname}`;
				appendLog(`[Auto-DNS] Web URL switched to ${this.detectedVhostUrl} for subsequent steps`);
			}

			// Also add to job.hosts so we don't re-register on subsequent steps
			if (!job.hosts) { job.hosts = {}; }
			Object.assign(job.hosts, hostsToRegister);

		} catch {
			// Silently ignore parse errors — non-critical feature
		}
	}

	private resolvePath(candidate: string): string {
		if (path.isAbsolute(candidate)) { return candidate; }
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		return workspaceRoot ? path.join(workspaceRoot, candidate) : path.resolve(candidate);
	}

	private timeout(ms: number): Promise<string> {
		return new Promise(resolve => setTimeout(() => resolve('__TIMEOUT__'), ms));
	}

	private sleep(ms: number): Promise<void> {
		return new Promise(resolve => setTimeout(resolve, ms));
	}
}
