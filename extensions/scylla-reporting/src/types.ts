/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export type FindingClassification = 'observation' | 'candidate' | 'validated';

export interface FindingSource {
	scanner?: string;
	command?: string;
	strategy?: string;
}

export interface FindingActors {
	attackerProfile?: string;
	baselineProfile?: string;
	resourceOwnerProfile?: string;
}

export interface ReportGenerateCommandOptions {
	findingsDir?: string;
	scanResultsDir?: string;
	pipelineStatus?: string;
	engagementFile?: string;
	authorizationMatrixFile?: string;
	format?: 'md' | 'html';
	title?: string;
	/** Human-facing report destination; Jobs reserves `output` for result JSON. */
	reportOutput?: { path: string };
	/** Legacy report destination, honored only for `.md` or `.html` paths. */
	output?: { path: string };
	includeCandidates?: boolean;
	includeObservations?: boolean;
	/** Return full report data in the command result. Defaults to false. */
	includeData?: boolean;
	quiet?: boolean;
}

export interface ReportData {
	generatedAt: string;
	title: string;
	target: string;
	executiveSummary: ExecutiveSummary;
	/** All parsed records, irrespective of lifecycle classification. */
	records: FindingEntry[];
	/** Validated findings only. */
	findings: FindingEntry[];
	candidates: FindingEntry[];
	observations: FindingEntry[];
	reconSummary?: ReconSummary;
	engagementSummary?: EngagementSummary;
	authorizationSummary?: AuthorizationSummary;
	timeline: TimelineEntry[];
}

export interface ExecutiveSummary {
	/** Number of validated findings; candidates do not contribute. */
	totalFindings: number;
	totalRecords: number;
	validatedFindings: number;
	candidates: number;
	observations: number;
	/** Validated findings only. */
	bySeverity: Record<string, number>;
	/** Provisional severity assigned to candidates. */
	candidateBySeverity: Record<string, number>;
	riskLevel: string;
	riskBasis: 'validated-findings-only';
}

export interface FindingEntry {
	id: string;
	title: string;
	severity: string;
	status: string;
	classification: FindingClassification;
	confidence?: number;
	source?: FindingSource;
	actors?: FindingActors;
	target: string;
	createdAt?: string;
	updatedAt?: string;
	summary: string;
	reproduction?: string;
	remediation?: string;
	evidence: string[];
	tags: string[];
	filePath: string;
}

export interface ReconSummary {
	openPorts: number;
	pagesVisited: number;
	discoveredEndpoints: number;
	forms: number;
	parameters: number;
	javascriptRoutes: number;
	hiddenPaths: number;
	technologies: string[];
	waf?: {
		detected: boolean;
		name?: string;
		confidence?: number;
		mode?: string;
	};
}

export interface EngagementSummary {
	id: string;
	name: string;
	targets: string[];
	scope: string[];
	identities: number;
	resources: number;
	transactions: number;
	filePath: string;
}

export interface AuthorizationSummary {
	engagementId?: string;
	identities: number;
	resources: number;
	cells: number;
	mismatches: number;
	filePath: string;
}

export interface TimelineEntry {
	timestamp: string;
	event: string;
	status: string;
	durationMs?: number;
}
