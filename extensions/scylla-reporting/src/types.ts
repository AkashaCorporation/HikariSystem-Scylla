/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface ReportGenerateCommandOptions {
	findingsDir?: string;
	scanResultsDir?: string;
	pipelineStatus?: string;
	format?: 'md' | 'html';
	title?: string;
	output?: { path: string };
	quiet?: boolean;
}

export interface ReportData {
	generatedAt: string;
	title: string;
	target: string;
	executiveSummary: ExecutiveSummary;
	findings: FindingEntry[];
	reconSummary?: ReconSummary;
	timeline: TimelineEntry[];
}

export interface ExecutiveSummary {
	totalFindings: number;
	bySeverity: Record<string, number>;
	riskLevel: string;
}

export interface FindingEntry {
	id: string;
	title: string;
	severity: string;
	status: string;
	target: string;
	summary: string;
	tags: string[];
}

export interface ReconSummary {
	openPorts: number;
	discoveredEndpoints: number;
	technologies: string[];
	hiddenPaths: number;
}

export interface TimelineEntry {
	timestamp: string;
	event: string;
	status: string;
}
