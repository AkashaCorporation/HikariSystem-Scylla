/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface ExportFinding {
	id: string;
	title: string;
	severity: string;
	status: string;
	target: string;
	createdAt: string;
	updatedAt: string;
	tags: string[];
	summary: string;
	reproduction: string;
	remediation: string;
	evidence: string[];
}

export interface ExportOptions {
	/** Path to findings directory (default: .scylla/findings) */
	findingsDir?: string;
	/** Output file path */
	outputPath?: string;
	/** Filter by severity */
	severity?: string;
	/** Filter by status */
	status?: string;
	/** Quiet mode (no notifications) */
	quiet?: boolean;
}

export interface ExportResult {
	generatedAt: string;
	format: string;
	outputPath: string;
	findingsCount: number;
}
