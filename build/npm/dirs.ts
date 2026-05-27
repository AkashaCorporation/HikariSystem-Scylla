/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { existsSync } from 'fs';
import * as path from 'path';

const root = path.join(import.meta.dirname, '../../');

/**
 * Complete list of directories where npm should be executed to install node modules
 */
const rawDirs = [
	'',
	'build',
	'build/vite',
	'extensions',
	
	// Retained HexCore utility extensions
	'extensions/hexcore-base64',
	'extensions/hexcore-common',
	'extensions/hexcore-filetype',
	'extensions/hexcore-hashcalc',
	'extensions/hexcore-ioc',
	'extensions/hexcore-strings',
	'extensions/hexcore-yara',

	// Scylla tensive extensions
	'extensions/scylla-auth',
	'extensions/scylla-export',
	'extensions/scylla-findings',
	'extensions/scylla-http',
	'extensions/scylla-jobs',
	'extensions/scylla-recon',
	'extensions/scylla-reporting',
	'extensions/scylla-scanner',
	'extensions/scylla-theme',
	'extensions/scylla-wordlists',

	// Built-in extensions
	'extensions/configuration-editing',
	'extensions/css-language-features',
	'extensions/css-language-features/server',
	'extensions/debug-auto-launch',
	'extensions/debug-server-ready',
	'extensions/emmet',
	'extensions/extension-editing',
	'extensions/git',
	'extensions/git-base',
	'extensions/github',
	'extensions/github-authentication',
	'extensions/grunt',
	'extensions/gulp',
	'extensions/html-language-features',
	'extensions/html-language-features/server',
	'extensions/ipynb',
	'extensions/jake',
	'extensions/json-language-features',
	'extensions/json-language-features/server',
	'extensions/markdown-language-features',
	'extensions/markdown-math',
	'extensions/media-preview',
	'extensions/merge-conflict',
	'extensions/mermaid-chat-features',
	'extensions/microsoft-authentication',
	'extensions/notebook-renderers',
	'extensions/npm',
	'extensions/php-language-features',
	'extensions/references-view',
	'extensions/search-result',
	'extensions/simple-browser',
	'extensions/tunnel-forwarding',
	'extensions/terminal-suggest',
	'extensions/typescript-language-features',
	'extensions/vscode-api-tests',
	'extensions/vscode-colorize-tests',
	'extensions/vscode-colorize-perf-tests',
	'extensions/vscode-test-resolver',

	'remote',
	'remote/web',
	'test/automation',
	'test/integration/browser',
	'test/monaco',
	'test/smoke',
	'test/mcp',
	'.vscode/extensions/vscode-selfhost-import-aid',
	'.vscode/extensions/vscode-selfhost-test-provider',
];

// Dynamically filter to ensure only directories that actually exist on disk are bootstrapped
export const dirs = rawDirs.filter(d => {
	if (d === '') {
		return true;
	}
	return existsSync(path.join(root, d));
});

if (existsSync(`${import.meta.dirname}/../../.build/distro/npm`)) {
	dirs.push('.build/distro/npm');
	dirs.push('.build/distro/npm/remote');
	dirs.push('.build/distro/npm/remote/web');
}

