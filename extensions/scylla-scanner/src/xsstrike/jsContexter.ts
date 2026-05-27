/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License for XSStrike-inspired logic.
 *--------------------------------------------------------------------------------------------*/

/**
 * JS Contexter
 * Analyzes unbalanced JavaScript syntax and generates an exact escape string.
 */
export class JsContexter {
	/**
	 * Takes the raw JavaScript source code immediately preceding our injection
	 * and returns the string needed to close all unbalanced contexts cleanly.
	 */
	public static generateBreaker(jsBeforeInjection: string): string {
		let inSingleQuote = false;
		let inDoubleQuote = false;
		let inTemplateQuote = false;
		let inLineComment = false;
		let inBlockComment = false;
		let escaped = false;

		const stack: string[] = [];

		for (let i = 0; i < jsBeforeInjection.length; i++) {
			const char = jsBeforeInjection[i];
			const nextChar = jsBeforeInjection[i + 1] || '';

			if (inLineComment) {
				if (char === '\n') { inLineComment = false; }
				continue;
			}

			if (inBlockComment) {
				if (char === '*' && nextChar === '/') {
					inBlockComment = false;
					i++;
				}
				continue;
			}

			if (escaped) {
				escaped = false;
				continue;
			}

			if (char === '\\') {
				escaped = true;
				continue;
			}

			// Strings
			if (!inSingleQuote && !inDoubleQuote && !inTemplateQuote) {
				if (char === "'") { inSingleQuote = true; continue; }
				if (char === '"') { inDoubleQuote = true; continue; }
				if (char === '`') { inTemplateQuote = true; continue; }

				// Comments
				if (char === '/' && nextChar === '/') { inLineComment = true; i++; continue; }
				if (char === '/' && nextChar === '*') { inBlockComment = true; i++; continue; }

				// Brackets
				if (char === '{' || char === '[' || char === '(') {
					stack.push(char);
				} else if (char === '}' || char === ']' || char === ')') {
					if (stack.length > 0) {
						const last = stack[stack.length - 1];
						if ((char === '}' && last === '{') ||
							(char === ']' && last === '[') ||
							(char === ')' && last === '(')) {
							stack.pop();
						}
					}
				}
			} else {
				// Inside a string
				if (char === "'" && inSingleQuote) { inSingleQuote = false; }
				else if (char === '"' && inDoubleQuote) { inDoubleQuote = false; }
				else if (char === '`' && inTemplateQuote) { inTemplateQuote = false; }
			}
		}

		// Now we build the breaker string
		let breaker = '';

		// 1. Close quotes
		if (inSingleQuote) { breaker += "'"; }
		if (inDoubleQuote) { breaker += '"'; }
		if (inTemplateQuote) { breaker += '`'; }

		// 2. Close brackets in reverse order
		while (stack.length > 0) {
			const openBracket = stack.pop()!;
			if (openBracket === '{') { breaker += '}'; }
			else if (openBracket === '[') { breaker += ']'; }
			else if (openBracket === '(') { breaker += ')'; }
		}

		return breaker;
	}
}
