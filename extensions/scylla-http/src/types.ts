/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export type OutputFormat = 'json' | 'md';

export interface HttpRequestDefinition {
	name?: string;
	method: string;
	url: string;
	headers?: Record<string, string>;
	body?: string;
	timeoutMs?: number;
	followRedirects?: boolean;
	tags?: string[];
}

export interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

export interface SaveCommandOutputOptions {
	path?: string;
}

export interface HttpSendCommandOptions {
	file?: string;
	url?: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
	name?: string;
	timeoutMs?: number;
	followRedirects?: boolean;
	output?: CommandOutputOptions;
	quiet?: boolean;
	saveResponse?: boolean;
	maxBodyBytes?: number;
}

export interface HttpSaveRequestCommandOptions {
	name?: string;
	method?: string;
	url?: string;
	headers?: Record<string, string>;
	body?: string;
	timeoutMs?: number;
	followRedirects?: boolean;
	tags?: string[];
	output?: SaveCommandOutputOptions;
	quiet?: boolean;
}

export interface HttpResponseData {
	statusCode: number;
	statusMessage: string;
	headers: Record<string, string | string[]>;
	bodyText: string;
	bodyBytes: number;
	truncated: boolean;
	elapsedMs: number;
	redirected: boolean;
	redirectCount: number;
	finalUrl: string;
}

export interface HttpSendResult {
	generatedAt: string;
	request: {
		name?: string;
		method: string;
		url: string;
		headers: Record<string, string>;
		body?: string;
		timeoutMs: number;
		followRedirects: boolean;
	};
	response: HttpResponseData;
	requestFile?: string;
	responseFile?: string;
	reportMarkdown: string;
}

export interface SavedRequestResult {
	requestFile: string;
	request: HttpRequestDefinition;
	generatedAt: string;
}
