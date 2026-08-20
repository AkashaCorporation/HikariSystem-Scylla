/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { engagementStore } from './store';
import type {
	AddIdentityOptions,
	CreateEngagementOptions,
	EngagementIdOptions,
	RecordTransactionOptions,
	RegisterResourceOptions,
	SetActiveEngagementOptions,
} from './types';

export function activate(context: vscode.ExtensionContext): void {
	context.subscriptions.push(
		vscode.commands.registerCommand('scylla.engagement.createHeadless', (arg?: CreateEngagementOptions) => {
			return engagementStore.createEngagement(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.getHeadless', (arg?: EngagementIdOptions) => {
			return engagementStore.getEngagement(arg?.engagementId);
		}),
		vscode.commands.registerCommand('scylla.engagement.listHeadless', () => {
			return engagementStore.listEngagements();
		}),
		vscode.commands.registerCommand('scylla.engagement.setActiveHeadless', (arg?: SetActiveEngagementOptions) => {
			if (!arg?.engagementId) {
				throw new Error('scylla.engagement.setActiveHeadless requires "engagementId".');
			}
			return engagementStore.setActiveEngagement(arg.engagementId);
		}),
		vscode.commands.registerCommand('scylla.engagement.addIdentityHeadless', (arg?: AddIdentityOptions) => {
			if (!arg) {
				throw new Error('scylla.engagement.addIdentityHeadless requires identity options.');
			}
			return engagementStore.addIdentity(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.registerResourceHeadless', (arg?: RegisterResourceOptions) => {
			if (!arg) {
				throw new Error('scylla.engagement.registerResourceHeadless requires resource options.');
			}
			return engagementStore.registerResource(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.recordTransactionHeadless', (arg?: RecordTransactionOptions) => {
			if (!arg) {
				throw new Error('scylla.engagement.recordTransactionHeadless requires transaction options.');
			}
			return engagementStore.recordTransaction(arg);
		}),
		vscode.commands.registerCommand('scylla.engagement.authorizationMatrixHeadless', (arg?: EngagementIdOptions) => {
			return engagementStore.authorizationMatrix(arg?.engagementId);
		}),
	);
}

export function deactivate(): void { }
