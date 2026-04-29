/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface TechPattern {
	name: string;
	category: string;
	headerPatterns?: Array<{ header: string; pattern: RegExp; versionGroup?: number }>;
	bodyPatterns?: Array<{ pattern: RegExp; versionGroup?: number }>;
}

export const TECH_PATTERNS: TechPattern[] = [
	// Web Servers
	{
		name: 'Apache', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /Apache(?:\/(\d+\.\d+[\.\d]*))?/i, versionGroup: 1 }],
	},
	{
		name: 'Nginx', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /nginx(?:\/(\d+\.\d+[\.\d]*))?/i, versionGroup: 1 }],
	},
	{
		name: 'Microsoft IIS', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /Microsoft-IIS(?:\/(\d+\.\d+))?/i, versionGroup: 1 }],
	},
	{
		name: 'LiteSpeed', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /LiteSpeed/i }],
	},
	{
		name: 'Caddy', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /Caddy/i }],
	},
	{
		name: 'Tomcat', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /Apache-Coyote(?:\/(\d+\.\d+))?/i, versionGroup: 1 }],
		bodyPatterns: [{ pattern: /Apache Tomcat(?:\/(\d+\.\d+[\.\d]*))?/i, versionGroup: 1 }],
	},
	{
		name: 'Gunicorn', category: 'web-server',
		headerPatterns: [{ header: 'server', pattern: /gunicorn(?:\/(\d+\.\d+[\.\d]*))?/i, versionGroup: 1 }],
	},

	// Languages / Runtimes
	{
		name: 'PHP', category: 'language',
		headerPatterns: [
			{ header: 'x-powered-by', pattern: /PHP(?:\/(\d+\.\d+[\.\d]*))?/i, versionGroup: 1 },
			{ header: 'set-cookie', pattern: /PHPSESSID/i },
		],
		bodyPatterns: [{ pattern: /<\?php/i }],
	},
	{
		name: 'ASP.NET', category: 'language',
		headerPatterns: [
			{ header: 'x-powered-by', pattern: /ASP\.NET/i },
			{ header: 'x-aspnet-version', pattern: /(\d+\.\d+[\.\d]*)/, versionGroup: 1 },
			{ header: 'set-cookie', pattern: /ASP\.NET_SessionId/i },
		],
	},
	{
		name: 'Java', category: 'language',
		headerPatterns: [
			{ header: 'x-powered-by', pattern: /Servlet(?:\/(\d+\.\d+))?/i, versionGroup: 1 },
			{ header: 'set-cookie', pattern: /JSESSIONID/i },
		],
	},
	{
		name: 'Python', category: 'language',
		headerPatterns: [
			{ header: 'server', pattern: /Python(?:\/(\d+\.\d+))?/i, versionGroup: 1 },
			{ header: 'x-powered-by', pattern: /Python/i },
		],
	},
	{
		name: 'Node.js', category: 'language',
		headerPatterns: [
			{ header: 'x-powered-by', pattern: /Express/i },
		],
	},
	{
		name: 'Ruby', category: 'language',
		headerPatterns: [
			{ header: 'x-powered-by', pattern: /Phusion Passenger/i },
			{ header: 'server', pattern: /Passenger/i },
			{ header: 'set-cookie', pattern: /_session_id/i },
		],
	},

	// Frameworks
	{
		name: 'Express', category: 'framework',
		headerPatterns: [{ header: 'x-powered-by', pattern: /Express/i }],
	},
	{
		name: 'Django', category: 'framework',
		headerPatterns: [
			{ header: 'set-cookie', pattern: /csrftoken/i },
			{ header: 'x-frame-options', pattern: /DENY/i },
		],
		bodyPatterns: [{ pattern: /csrfmiddlewaretoken/i }],
	},
	{
		name: 'Flask', category: 'framework',
		headerPatterns: [{ header: 'server', pattern: /Werkzeug(?:\/(\d+\.\d+[\.\d]*))?/i, versionGroup: 1 }],
	},
	{
		name: 'Laravel', category: 'framework',
		headerPatterns: [
			{ header: 'set-cookie', pattern: /laravel_session/i },
			{ header: 'x-powered-by', pattern: /Laravel/i },
		],
		bodyPatterns: [{ pattern: /laravel[\/\\]framework/i }],
	},
	{
		name: 'Ruby on Rails', category: 'framework',
		headerPatterns: [
			{ header: 'x-powered-by', pattern: /Rails/i },
			{ header: 'x-runtime', pattern: /\d+\.\d+/ },
		],
		bodyPatterns: [{ pattern: /rails-ujs/i }],
	},
	{
		name: 'Spring', category: 'framework',
		headerPatterns: [
			{ header: 'x-application-context', pattern: /.+/ },
		],
		bodyPatterns: [
			{ pattern: /Whitelabel Error Page/i },
			{ pattern: /org\.springframework/i },
		],
	},
	{
		name: 'Next.js', category: 'framework',
		headerPatterns: [{ header: 'x-powered-by', pattern: /Next\.js/i }],
		bodyPatterns: [{ pattern: /__NEXT_DATA__/i }, { pattern: /_next\/static/i }],
	},
	{
		name: 'Nuxt.js', category: 'framework',
		bodyPatterns: [{ pattern: /__NUXT__/i }, { pattern: /_nuxt\//i }],
	},

	// CMS
	{
		name: 'WordPress', category: 'cms',
		bodyPatterns: [
			{ pattern: /wp-content/i },
			{ pattern: /wp-includes/i },
			{ pattern: /<meta name="generator" content="WordPress (\d+\.\d+[\.\d]*)"/i, versionGroup: 1 },
		],
	},
	{
		name: 'Drupal', category: 'cms',
		headerPatterns: [{ header: 'x-generator', pattern: /Drupal (\d+)/i, versionGroup: 1 }],
		bodyPatterns: [
			{ pattern: /Drupal\.settings/i },
			{ pattern: /sites\/default\/files/i },
		],
	},
	{
		name: 'Joomla', category: 'cms',
		bodyPatterns: [
			{ pattern: /<meta name="generator" content="Joomla/i },
			{ pattern: /\/media\/jui\//i },
		],
	},

	// Frontend Frameworks
	{
		name: 'React', category: 'frontend',
		bodyPatterns: [
			{ pattern: /react\.production\.min\.js/i },
			{ pattern: /data-reactroot/i },
			{ pattern: /__react/i },
		],
	},
	{
		name: 'Angular', category: 'frontend',
		bodyPatterns: [
			{ pattern: /ng-version="(\d+[\.\d]*)"/i, versionGroup: 1 },
			{ pattern: /angular\.min\.js/i },
			{ pattern: /ng-app/i },
		],
	},
	{
		name: 'Vue.js', category: 'frontend',
		bodyPatterns: [
			{ pattern: /vue\.min\.js/i },
			{ pattern: /data-v-[a-f0-9]+/i },
			{ pattern: /vue-router/i },
		],
	},
	{
		name: 'jQuery', category: 'frontend',
		bodyPatterns: [
			{ pattern: /jquery[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js/i, versionGroup: 1 },
		],
	},
	{
		name: 'Bootstrap', category: 'frontend',
		bodyPatterns: [
			{ pattern: /bootstrap[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.(?:css|js)/i, versionGroup: 1 },
		],
	},

	// CDN / WAF / Proxy
	{
		name: 'Cloudflare', category: 'cdn',
		headerPatterns: [
			{ header: 'server', pattern: /cloudflare/i },
			{ header: 'cf-ray', pattern: /.+/ },
		],
	},
	{
		name: 'Akamai', category: 'cdn',
		headerPatterns: [
			{ header: 'x-akamai-transformed', pattern: /.+/ },
			{ header: 'server', pattern: /AkamaiGHost/i },
		],
	},
	{
		name: 'Amazon CloudFront', category: 'cdn',
		headerPatterns: [
			{ header: 'x-amz-cf-id', pattern: /.+/ },
			{ header: 'via', pattern: /CloudFront/i },
		],
	},
	{
		name: 'Varnish', category: 'cache',
		headerPatterns: [
			{ header: 'via', pattern: /varnish/i },
			{ header: 'x-varnish', pattern: /.+/ },
		],
	},

	// Security / Auth
	{
		name: 'ModSecurity', category: 'waf',
		headerPatterns: [{ header: 'server', pattern: /mod_security/i }],
	},
	{
		name: 'AWS WAF', category: 'waf',
		headerPatterns: [
			{ header: 'x-amzn-waf', pattern: /.+/ },
		],
	},
];
