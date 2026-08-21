import type { ReportData, ReportGenerateCommandOptions } from './types';

declare module './htmlRenderer' {
	export function renderHtmlReport(data: ReportData, options?: ReportGenerateCommandOptions): string;
}

declare module './artifacts' {
	/** Compatibility declaration for the legacy extension entrypoint. */
	export function resolveOutputPath(options?: ReportGenerateCommandOptions): string;
}
