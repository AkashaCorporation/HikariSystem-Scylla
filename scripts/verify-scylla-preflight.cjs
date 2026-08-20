/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const errors = [];
const notes = [];

function full(relativePath) {
	return path.join(root, relativePath);
}

function readText(relativePath) {
	const filePath = full(relativePath);
	if (!fs.existsSync(filePath)) {
		errors.push(`Missing file: ${relativePath}`);
		return '';
	}
	return fs.readFileSync(filePath, 'utf8');
}

function readJson(relativePath) {
	const text = readText(relativePath);
	if (!text) { return null; }
	try {
		return JSON.parse(text);
	} catch (error) {
		errors.push(`Invalid JSON: ${relativePath}: ${error instanceof Error ? error.message : String(error)}`);
		return null;
	}
}

function assertIncludes(text, needle, label) {
	if (!text.includes(needle)) {
		errors.push(`${label} is missing expected content: ${needle}`);
	}
}

function escapeRegex(value) {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function verifyProduct() {
	const product = readJson('product.json');
	if (!product) { return; }
	if (product.nameShort !== 'Scylla') {
		errors.push(`product.json nameShort must be Scylla (got ${String(product.nameShort)})`);
	}
	if (product.applicationName !== 'scylla') {
		errors.push(`product.json applicationName must be scylla (got ${String(product.applicationName)})`);
	}
	if (product.dataFolderName !== '.scylla') {
		errors.push(`product.json dataFolderName must be .scylla (got ${String(product.dataFolderName)})`);
	}
}

function verifyEngagementBuildCoverage() {
	const dirs = readText('build/npm/dirs.ts');
	const gulp = readText('build/gulpfile.extensions.ts');
	assertIncludes(dirs, `'extensions/scylla-engagements'`, 'build/npm/dirs.ts');
	assertIncludes(gulp, `'extensions/scylla-engagements/tsconfig.json'`, 'build/gulpfile.extensions.ts');

	for (const required of [
		'extensions/scylla-engagements/package.json',
		'extensions/scylla-engagements/package-lock.json',
		'extensions/scylla-engagements/tsconfig.json',
		'extensions/scylla-engagements/src/extension.ts',
		'extensions/scylla-engagements/src/store.ts',
		'extensions/scylla-engagements/src/types.ts',
		'extensions/scylla-engagements/src/scannerImport.ts',
	]) {
		readText(required);
	}
}

function extractJobCommands(runnerSource) {
	const commands = new Set();
	const tuple = /\['([^']+)'\s*,/g;
	let match;
	while ((match = tuple.exec(runnerSource)) !== null) {
		commands.add(match[1]);
	}
	return commands;
}

function verifyEngagementCommands() {
	const manifest = readJson('extensions/scylla-engagements/package.json');
	const source = readText('extensions/scylla-engagements/src/extension.ts');
	const runner = readText('extensions/scylla-jobs/src/pipelineRunner.ts');
	if (!manifest) { return; }

	const jobCommands = extractJobCommands(runner);
	const contributed = (manifest.contributes?.commands ?? [])
		.map(entry => entry?.command)
		.filter(command => typeof command === 'string' && command.length > 0);

	if (contributed.length === 0) {
		errors.push('scylla-engagements contributes no commands');
	}

	for (const command of contributed) {
		const registration = new RegExp(`registerCommand\\(\\s*['"]${escapeRegex(command)}['"]`);
		if (!registration.test(source)) {
			errors.push(`scylla-engagements source does not register command: ${command}`);
		}
		if (!jobCommands.has(command)) {
			errors.push(`Scylla Jobs does not register engagement command: ${command}`);
		}
	}
	notes.push(`Engagement commands checked: ${contributed.length}`);
}

function verifyJobExamples() {
	const jobsDir = full('docs/jobs');
	if (!fs.existsSync(jobsDir)) {
		errors.push('Missing directory: docs/jobs');
		return;
	}

	const runner = readText('extensions/scylla-jobs/src/pipelineRunner.ts');
	const knownCommands = extractJobCommands(runner);
	const files = fs.readdirSync(jobsDir)
		.filter(name => name.endsWith('.scylla_job.json'))
		.sort();

	if (files.length === 0) {
		errors.push('No docs/jobs/*.scylla_job.json examples found');
		return;
	}

	for (const name of files) {
		const relativePath = path.join('docs', 'jobs', name);
		const job = readJson(relativePath);
		if (!job) { continue; }
		if (typeof job.target !== 'string' || !job.target) {
			errors.push(`${relativePath}: target is required`);
		}
		if (typeof job.outDir !== 'string' || !job.outDir) {
			errors.push(`${relativePath}: outDir is required`);
		}
		if (!Array.isArray(job.steps) || job.steps.length === 0) {
			errors.push(`${relativePath}: non-empty steps array is required`);
			continue;
		}
		for (const [index, step] of job.steps.entries()) {
			if (!step || typeof step.cmd !== 'string' || !step.cmd) {
				errors.push(`${relativePath}: step ${index + 1} is missing cmd`);
				continue;
			}
			if (!knownCommands.has(step.cmd)) {
				errors.push(`${relativePath}: step ${index + 1} uses command not registered by Scylla Jobs: ${step.cmd}`);
			}
		}
	}
	notes.push(`Job examples checked: ${files.length}`);
}

function verifyWorkflows() {
	const ci = readText('.github/workflows/hexcore-build.yml');
	const installer = readText('.github/workflows/hexcore-installer.yml');

	for (const required of [
		'name: Scylla CI',
		'node-version: "22.21.1"',
		'extensions/scylla-*',
	]) {
		assertIncludes(ci, required, '.github/workflows/hexcore-build.yml');
	}

	for (const required of [
		'name: Scylla Windows Build',
		'runs-on: windows-2022',
		'node-version: "22.21.1"',
		'Scylla-win32-x64.zip',
		'scylla-engagements',
		'vscode-win32-x64-min',
	]) {
		assertIncludes(installer, required, '.github/workflows/hexcore-installer.yml');
	}
	if (installer.includes('HexCore-win32-x64.zip')) {
		errors.push('Scylla installer must not emit HexCore-win32-x64.zip');
	}
}

function verifySafetyContracts() {
	const engagementSource = readText('extensions/scylla-engagements/src/extension.ts');
	const privesc = readText('extensions/scylla-scanner/src/privescScanner.ts');
	const httpArtifacts = readText('extensions/scylla-http/src/artifacts.ts');

	assertIncludes(engagementSource, 'SAFE_PROBE_METHODS', 'scylla-engagements probe');
	assertIncludes(engagementSource, 'allowStateChange', 'scylla-engagements probe');
	assertIncludes(engagementSource, 'Refusing to downgrade the probe to anonymous.', 'scylla-engagements auth provenance');
	assertIncludes(engagementSource, 'resource?.canonicalUrl?.trim() || arg.url?.trim()', 'scylla-engagements resource URL precedence');
	assertIncludes(privesc, 'No POST, PUT, PATCH, or DELETE request was issued by this scanner.', 'scylla-privesc safety contract');
	assertIncludes(httpArtifacts, 'redactRequestHeaders', 'scylla-http evidence redaction');
	assertIncludes(httpArtifacts, 'redactResponseHeaders', 'scylla-http evidence redaction');
}

verifyProduct();
verifyEngagementBuildCoverage();
verifyEngagementCommands();
verifyJobExamples();
verifyWorkflows();
verifySafetyContracts();

if (errors.length > 0) {
	console.error(`Scylla preflight failed with ${errors.length} error(s):`);
	for (const error of errors) {
		console.error(` - ${error}`);
	}
	process.exit(1);
}

console.log('Scylla preflight passed.');
for (const note of notes) {
	console.log(` - ${note}`);
}
