/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { GraphqlScanResult, VulnFinding } from './types';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_DELAY_MS = 100;

const COMMON_GRAPHQL_PATHS = [
	'/graphql',
	'/graphiql',
	'/api/graphql',
	'/v1/graphql',
];

const SIMPLE_INTROSPECTION_QUERY = '{__schema{types{name}}}';

const FULL_INTROSPECTION_QUERY = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name ofType { kind name } } }
      }
      inputFields {
        name
        type { kind name ofType { kind name ofType { kind name } } }
      }
      enumValues(includeDeprecated: true) { name }
    }
    directives {
      name
      locations
    }
  }
}`;

const INJECTION_PAYLOADS = [
	{ name: 'sqli-single-quote', value: "'" },
	{ name: 'sqli-union', value: "' UNION SELECT null--" },
	{ name: 'sqli-or-true', value: "' OR '1'='1" },
	{ name: 'xss-script', value: '<script>alert(1)</script>' },
	{ name: 'xss-img', value: '<img src=x onerror=alert(1)>' },
	{ name: 'xss-svg', value: '<svg/onload=alert(1)>' },
	{ name: 'nosql-or', value: '{"$gt":""}' },
	{ name: 'template-injection', value: '{{7*7}}' },
];

const COMMON_FIELD_NAMES = [
	'user', 'users', 'admin', 'me', 'login', 'register',
	'createUser', 'deleteUser', 'posts', 'comments',
	'products', 'orders', 'settings', 'config', 'flag', 'secret',
];

interface GraphqlResponse {
	statusCode: number;
	bodyText: string;
	elapsedMs: number;
	headers?: Record<string, string>;
}

async function sendGraphqlRequest(
	url: string,
	body: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<GraphqlResponse | null> {
	try {
		const requestHeaders: Record<string, string> = {
			...(headers ?? {}),
			'Content-Type': 'application/json',
		};

		if (cookie) {
			requestHeaders['cookie'] = cookie;
		}

		const result = await vscode.commands.executeCommand<{
			response: {
				statusCode: number;
				bodyText: string;
				elapsedMs: number;
				headers?: Record<string, string>;
			};
		}>('scylla.http.sendHeadless', {
			url,
			method: 'POST',
			timeoutMs,
			followRedirects: true,
			quiet: true,
			headers: requestHeaders,
			body,
		});

		if (!result?.response) { return null; }
		return {
			statusCode: result.response.statusCode,
			bodyText: result.response.bodyText,
			elapsedMs: result.response.elapsedMs,
			headers: result.response.headers,
		};
	} catch {
		return null;
	}
}

function isGraphqlEndpoint(response: GraphqlResponse): boolean {
	if (!response.bodyText) { return false; }
	const body = response.bodyText.toLowerCase();
	return body.includes('"data"') || body.includes('"errors"') || body.includes('__schema');
}

function parseJsonSafe(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return null;
	}
}

async function discoverEndpoint(
	targetUrl: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<string | null> {
	// Try the URL as-is first
	const directBody = JSON.stringify({ query: SIMPLE_INTROSPECTION_QUERY });
	const directResponse = await sendGraphqlRequest(targetUrl, directBody, timeoutMs, headers, cookie);
	if (directResponse && isGraphqlEndpoint(directResponse)) {
		return targetUrl;
	}

	// Try common paths
	const baseUrl = targetUrl.replace(/\/+$/, '');
	for (const gqlPath of COMMON_GRAPHQL_PATHS) {
		const candidateUrl = baseUrl + gqlPath;
		if (candidateUrl === targetUrl) { continue; }

		const response = await sendGraphqlRequest(candidateUrl, directBody, timeoutMs, headers, cookie);
		if (response && isGraphqlEndpoint(response)) {
			return candidateUrl;
		}
	}

	return null;
}

async function testIntrospection(
	endpointUrl: string,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ enabled: boolean; findings: VulnFinding[]; types: string[]; queries: string[]; mutations: string[] }> {
	const findings: VulnFinding[] = [];
	const types: string[] = [];
	const queries: string[] = [];
	const mutations: string[] = [];

	// Simple introspection test
	const simpleBody = JSON.stringify({ query: SIMPLE_INTROSPECTION_QUERY });
	const simpleResponse = await sendGraphqlRequest(endpointUrl, simpleBody, timeoutMs, headers, cookie);
	if (!simpleResponse) {
		return { enabled: false, findings, types, queries, mutations };
	}

	const simpleJson = parseJsonSafe(simpleResponse.bodyText) as Record<string, unknown> | null;
	const hasSchemaData = simpleJson
		&& typeof simpleJson === 'object'
		&& simpleJson.data
		&& typeof simpleJson.data === 'object'
		&& (simpleJson.data as Record<string, unknown>).__schema;

	if (!hasSchemaData) {
		return { enabled: false, findings, types, queries, mutations };
	}

	// Introspection is enabled - now run full query
	findings.push({
		type: 'graphql',
		severity: 'medium',
		title: 'GraphQL Introspection Enabled',
		url: endpointUrl,
		payload: SIMPLE_INTROSPECTION_QUERY,
		evidence: 'Server returned __schema data in response to introspection query',
		confidence: 0.95,
		details: `GraphQL introspection is enabled on ${endpointUrl}. This allows attackers to enumerate the entire API schema, including all types, queries, mutations, and field definitions. Introspection should be disabled in production.`,
	});

	if (delayMs > 0) { await sleep(delayMs); }

	// Full introspection query
	const fullBody = JSON.stringify({ query: FULL_INTROSPECTION_QUERY });
	const fullResponse = await sendGraphqlRequest(endpointUrl, fullBody, timeoutMs, headers, cookie);
	if (fullResponse) {
		const fullJson = parseJsonSafe(fullResponse.bodyText) as Record<string, unknown> | null;
		if (fullJson && typeof fullJson === 'object' && fullJson.data) {
			const data = fullJson.data as Record<string, unknown>;
			const schema = data.__schema as Record<string, unknown> | undefined;

			if (schema) {
				// Extract types
				const schemaTypes = schema.types as Array<Record<string, unknown>> | undefined;
				if (Array.isArray(schemaTypes)) {
					for (const t of schemaTypes) {
						const typeName = t.name as string | undefined;
						if (typeName && !typeName.startsWith('__')) {
							types.push(typeName);
						}
					}
				}

				// Extract queries from queryType
				const queryTypeName = (schema.queryType as Record<string, unknown> | undefined)?.name as string | undefined;
				if (queryTypeName && Array.isArray(schemaTypes)) {
					const queryType = schemaTypes.find(t => t.name === queryTypeName);
					const queryFields = queryType?.fields as Array<Record<string, unknown>> | undefined;
					if (Array.isArray(queryFields)) {
						for (const f of queryFields) {
							if (f.name) { queries.push(f.name as string); }
						}
					}
				}

				// Extract mutations from mutationType
				const mutationTypeName = (schema.mutationType as Record<string, unknown> | undefined)?.name as string | undefined;
				if (mutationTypeName && Array.isArray(schemaTypes)) {
					const mutationType = schemaTypes.find(t => t.name === mutationTypeName);
					const mutationFields = mutationType?.fields as Array<Record<string, unknown>> | undefined;
					if (Array.isArray(mutationFields)) {
						for (const f of mutationFields) {
							if (f.name) { mutations.push(f.name as string); }
						}
					}
				}

				if (types.length > 0 || queries.length > 0 || mutations.length > 0) {
					findings.push({
						type: 'graphql',
						severity: 'medium',
						title: 'GraphQL Full Schema Extracted',
						url: endpointUrl,
						payload: 'IntrospectionQuery (full)',
						evidence: `Types: ${types.length}, Queries: ${queries.length}, Mutations: ${mutations.length}`,
						confidence: 0.95,
						details: `Full schema extraction successful. Found ${types.length} types (${types.slice(0, 10).join(', ')}${types.length > 10 ? '...' : ''}), ${queries.length} queries (${queries.slice(0, 10).join(', ')}${queries.length > 10 ? '...' : ''}), ${mutations.length} mutations (${mutations.slice(0, 10).join(', ')}${mutations.length > 10 ? '...' : ''}).`,
					});
				}
			}
		}
	}

	return { enabled: true, findings, types, queries, mutations };
}

async function testInjection(
	endpointUrl: string,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<VulnFinding[]> {
	const findings: VulnFinding[] = [];
	const testedPayloads = new Set<string>();

	for (const injection of INJECTION_PAYLOADS) {
		if (testedPayloads.has(injection.value)) { continue; }
		testedPayloads.add(injection.value);

		// Test via query variables
		const body = JSON.stringify({
			query: 'query Test($input: String) { __typename }',
			variables: { input: injection.value },
		});

		const response = await sendGraphqlRequest(endpointUrl, body, timeoutMs, headers, cookie);
		if (!response) { continue; }

		const bodyLower = response.bodyText.toLowerCase();

		// Check for SQL error signatures in response
		const sqlErrors = [
			'sql syntax', 'mysql', 'postgresql', 'sqlite',
			'unclosed quotation', 'unterminated string',
			'syntax error', 'odbc', 'oracle', 'sql server',
			'pg_query', 'mysql_fetch', 'mysqli',
		];
		for (const sig of sqlErrors) {
			if (bodyLower.includes(sig)) {
				findings.push({
					type: 'graphql',
					severity: 'critical',
					title: `GraphQL SQL Injection (${injection.name})`,
					url: endpointUrl,
					payload: injection.value,
					evidence: `SQL error pattern "${sig}" found in response`,
					confidence: 0.85,
					details: `SQL injection detected through GraphQL variables. The payload "${injection.value}" triggered a database error containing "${sig}". This suggests that user-supplied input in GraphQL variables is not properly sanitized before being used in SQL queries.`,
				});
				break;
			}
		}

		// Check for XSS reflection
		if (response.bodyText.includes(injection.value) && injection.name.startsWith('xss')) {
			findings.push({
				type: 'graphql',
				severity: 'high',
				title: `GraphQL XSS Reflection (${injection.name})`,
				url: endpointUrl,
				payload: injection.value,
				evidence: 'Payload reflected unescaped in response body',
				confidence: 0.75,
				details: `The XSS payload "${injection.value}" was reflected in the GraphQL response without sanitization. If this data is rendered in a browser, it could lead to cross-site scripting.`,
			});
		}

		// Check for verbose error messages
		if (bodyLower.includes('stack') && bodyLower.includes('trace') || bodyLower.includes('traceback')) {
			findings.push({
				type: 'graphql',
				severity: 'low',
				title: 'GraphQL Verbose Error Disclosure',
				url: endpointUrl,
				payload: injection.value,
				evidence: 'Stack trace or traceback found in error response',
				confidence: 0.9,
				details: `The GraphQL endpoint returned verbose error information (stack trace) when processing the payload "${injection.value}". Verbose errors can leak internal implementation details, file paths, and library versions to attackers.`,
			});
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	return findings;
}

async function testBatchingAndAliasing(
	endpointUrl: string,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<VulnFinding[]> {
	const findings: VulnFinding[] = [];

	// Test query batching: send multiple queries in a JSON array
	const batchPayload = JSON.stringify([
		{ query: '{ __typename }' },
		{ query: '{ __typename }' },
		{ query: '{ __typename }' },
		{ query: '{ __typename }' },
		{ query: '{ __typename }' },
	]);

	const batchResponse = await sendGraphqlRequest(endpointUrl, batchPayload, timeoutMs, headers, cookie);
	if (batchResponse) {
		const batchJson = parseJsonSafe(batchResponse.bodyText);
		if (Array.isArray(batchJson) && batchJson.length >= 2) {
			findings.push({
				type: 'graphql',
				severity: 'medium',
				title: 'GraphQL Query Batching Enabled',
				url: endpointUrl,
				payload: '[{query: "{ __typename }"}, ...] (5 queries)',
				evidence: `Server processed batch of ${batchJson.length} queries and returned array response`,
				confidence: 0.9,
				details: `The GraphQL endpoint accepts batched queries (multiple operations in a single HTTP request). An attacker can abuse this to bypass rate limiting, perform brute-force attacks (e.g., testing many passwords in one request), or amplify denial-of-service impact. ${batchJson.length} responses were returned for 5 batched queries.`,
			});
		}
	}

	if (delayMs > 0) { await sleep(delayMs); }

	// Test query aliasing for DoS amplification
	const aliasCount = 50;
	const aliases = Array.from({ length: aliasCount }, (_, i) => `a${i}:__typename`).join(' ');
	const aliasingPayload = JSON.stringify({ query: `{ ${aliases} }` });

	const aliasingResponse = await sendGraphqlRequest(endpointUrl, aliasingPayload, timeoutMs, headers, cookie);
	if (aliasingResponse) {
		const aliasingJson = parseJsonSafe(aliasingResponse.bodyText) as Record<string, unknown> | null;
		if (aliasingJson && typeof aliasingJson === 'object' && aliasingJson.data) {
			const data = aliasingJson.data as Record<string, unknown>;
			const returnedAliases = Object.keys(data).filter(k => k.startsWith('a'));
			if (returnedAliases.length >= aliasCount / 2) {
				findings.push({
					type: 'graphql',
					severity: 'medium',
					title: 'GraphQL Query Aliasing Amplification',
					url: endpointUrl,
					payload: `{ a0:__typename a1:__typename ... } (${aliasCount} aliases)`,
					evidence: `Server resolved ${returnedAliases.length}/${aliasCount} aliased fields in a single query`,
					confidence: 0.85,
					details: `The GraphQL endpoint allows a large number of aliased fields in a single query (${returnedAliases.length} resolved out of ${aliasCount} requested). This can be exploited for denial-of-service by aliasing expensive resolver operations, or to bypass rate limiting on sensitive queries by aliasing them under different names.`,
				});
			}
		}
	}

	// Test with a more aggressive batching DoS pattern using systemUpdate-style mutation aliases
	if (delayMs > 0) { await sleep(delayMs); }

	const mutationAliasCount = 20;
	const mutationAliases = Array.from({ length: mutationAliasCount }, (_, i) => `a${i}:__typename`).join(' ');
	const largeBatchPayload = JSON.stringify(
		Array.from({ length: 20 }, () => ({ query: `{ ${mutationAliases} }` }))
	);

	const largeBatchResponse = await sendGraphqlRequest(endpointUrl, largeBatchPayload, timeoutMs, headers, cookie);
	if (largeBatchResponse) {
		const largeBatchJson = parseJsonSafe(largeBatchResponse.bodyText);
		if (Array.isArray(largeBatchJson) && largeBatchJson.length >= 10) {
			findings.push({
				type: 'graphql',
				severity: 'high',
				title: 'GraphQL Batch + Alias Amplification (DoS)',
				url: endpointUrl,
				payload: `20 batched queries, each with ${mutationAliasCount} aliases`,
				evidence: `Server processed ${largeBatchJson.length} batched queries with aliased fields`,
				confidence: 0.85,
				details: `The GraphQL endpoint accepts both batching and aliasing simultaneously, allowing massive query amplification. An attacker can send ${largeBatchJson.length} queries in a single request, each containing ${mutationAliasCount} aliased fields, resulting in up to ${largeBatchJson.length * mutationAliasCount} resolver invocations per HTTP request. This significantly amplifies denial-of-service potential.`,
			});
		}
	}

	return findings;
}

async function testFieldEnumeration(
	endpointUrl: string,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<VulnFinding[]> {
	const findings: VulnFinding[] = [];
	const discoveredFields: string[] = [];

	for (const fieldName of COMMON_FIELD_NAMES) {
		// Test as a query field
		const queryBody = JSON.stringify({ query: `{ ${fieldName} }` });
		const queryResponse = await sendGraphqlRequest(endpointUrl, queryBody, timeoutMs, headers, cookie);

		if (queryResponse) {
			const json = parseJsonSafe(queryResponse.bodyText) as Record<string, unknown> | null;
			if (json && typeof json === 'object') {
				const errors = json.errors as Array<Record<string, unknown>> | undefined;
				const data = json.data as Record<string, unknown> | undefined;

				// Field exists if we get data back, or if error mentions field exists but needs args/subfields
				const hasData = data && fieldName in data;
				const needsSubfields = errors && Array.isArray(errors) && errors.some(e => {
					const msg = (e.message as string || '').toLowerCase();
					return msg.includes('subselection') || msg.includes('sub selection') || msg.includes('must have a selection');
				});
				const needsArgs = errors && Array.isArray(errors) && errors.some(e => {
					const msg = (e.message as string || '').toLowerCase();
					return msg.includes('argument') && !msg.includes('cannot query');
				});
				const fieldNotFound = errors && Array.isArray(errors) && errors.some(e => {
					const msg = (e.message as string || '').toLowerCase();
					return msg.includes('cannot query') || msg.includes('did you mean') || msg.includes('unknown field');
				});

				if (hasData || needsSubfields || needsArgs) {
					discoveredFields.push(fieldName);
				} else if (!fieldNotFound) {
					// Ambiguous - might exist but requires auth, etc.
					// Check if we got a non-error status and response has data key
					if (queryResponse.statusCode === 200 && data !== undefined) {
						discoveredFields.push(fieldName);
					}
				}
			}
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	if (discoveredFields.length > 0) {
		// Determine severity based on what was found
		const sensitiveFields = discoveredFields.filter(f =>
			['admin', 'config', 'settings', 'secret', 'flag', 'deleteUser', 'createUser'].includes(f)
		);
		const severity = sensitiveFields.length > 0 ? 'high' : 'medium';

		findings.push({
			type: 'graphql',
			severity,
			title: 'GraphQL Field Enumeration Successful',
			url: endpointUrl,
			payload: discoveredFields.join(', '),
			evidence: `Discovered ${discoveredFields.length} valid fields: ${discoveredFields.join(', ')}`,
			confidence: 0.8,
			details: `Field enumeration discovered ${discoveredFields.length} valid fields/queries on the GraphQL endpoint: ${discoveredFields.join(', ')}. ${sensitiveFields.length > 0 ? `Sensitive fields found: ${sensitiveFields.join(', ')}. ` : ''}Even with introspection disabled, attackers can enumerate the schema by brute-forcing common field names and analyzing error messages.`,
		});
	}

	return findings;
}

export async function scanGraphql(
	targetUrl: string,
	options: {
		attacks?: Array<'introspection' | 'injection' | 'batching' | 'field-enum'>;
		headers?: Record<string, string>;
		cookie?: string;
		timeoutMs?: number;
		delayMs?: number;
	} = {}
): Promise<GraphqlScanResult> {
	const attacks = options.attacks ?? ['introspection', 'injection', 'batching', 'field-enum'];
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const delayMs = options.delayMs ?? DEFAULT_DELAY_MS;

	const findings: VulnFinding[] = [];
	const start = Date.now();
	let introspectionEnabled = false;

	// Discover GraphQL endpoint
	const endpointUrl = await discoverEndpoint(targetUrl, timeoutMs, options.headers, options.cookie);
	if (!endpointUrl) {
		return {
			generatedAt: new Date().toISOString(),
			target: targetUrl,
			introspectionEnabled: false,
			findings: [{
				type: 'graphql',
				severity: 'info',
				title: 'GraphQL Endpoint Not Found',
				url: targetUrl,
				payload: SIMPLE_INTROSPECTION_QUERY,
				evidence: 'No GraphQL endpoint responded at target URL or common paths',
				confidence: 0.7,
				details: `No GraphQL endpoint was found at ${targetUrl} or common paths (${COMMON_GRAPHQL_PATHS.join(', ')}). The target may not expose a GraphQL API, or it may be at a non-standard path.`,
			}],
			elapsedMs: Date.now() - start,
		};
	}

	// 1. Introspection test
	if (attacks.includes('introspection')) {
		const introResult = await testIntrospection(endpointUrl, timeoutMs, delayMs, options.headers, options.cookie);
		introspectionEnabled = introResult.enabled;
		findings.push(...introResult.findings);

		if (delayMs > 0) { await sleep(delayMs); }
	}

	// 2. Injection test
	if (attacks.includes('injection')) {
		const injectionFindings = await testInjection(endpointUrl, timeoutMs, delayMs, options.headers, options.cookie);
		findings.push(...injectionFindings);

		if (delayMs > 0) { await sleep(delayMs); }
	}

	// 3. Batching & Aliasing DoS
	if (attacks.includes('batching')) {
		const batchFindings = await testBatchingAndAliasing(endpointUrl, timeoutMs, delayMs, options.headers, options.cookie);
		findings.push(...batchFindings);

		if (delayMs > 0) { await sleep(delayMs); }
	}

	// 4. Field enumeration (especially useful when introspection is disabled)
	if (attacks.includes('field-enum')) {
		const enumFindings = await testFieldEnumeration(endpointUrl, timeoutMs, delayMs, options.headers, options.cookie);
		findings.push(...enumFindings);
	}

	return {
		generatedAt: new Date().toISOString(),
		target: endpointUrl,
		introspectionEnabled,
		findings,
		elapsedMs: Date.now() - start,
	};
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateGraphqlReport(result: GraphqlScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - GraphQL Security Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Introspection Enabled:** ${result.introspectionEnabled ? 'Yes' : 'No'}`);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.findings.length === 0) {
		lines.push('No GraphQL security issues detected.');
	} else {
		for (const f of result.findings) {
			lines.push(`## ${f.title}`);
			lines.push('');
			lines.push(`- **Severity:** ${f.severity.toUpperCase()}`);
			if (f.parameter) {
				lines.push(`- **Parameter:** \`${f.parameter}\``);
			}
			lines.push(`- **Confidence:** ${Math.round(f.confidence * 100)}%`);
			lines.push(`- **Payload:** \`${f.payload}\``);
			lines.push(`- **Evidence:** ${f.evidence}`);
			lines.push('');
			lines.push(f.details);
			lines.push('');
		}
	}

	return lines.join('\n');
}
