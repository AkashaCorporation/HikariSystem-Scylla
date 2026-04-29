/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the GPLv3 License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export class ConcurrencyPool {
	private running = 0;
	private readonly queue: Array<() => void> = [];

	constructor(private readonly limit: number) { }

	async run<T>(fn: () => Promise<T>): Promise<T> {
		await this.acquire();
		try {
			return await fn();
		} finally {
			this.release();
		}
	}

	private acquire(): Promise<void> {
		if (this.running < this.limit) {
			this.running++;
			return Promise.resolve();
		}
		return new Promise<void>(resolve => {
			this.queue.push(resolve);
		});
	}

	private release(): void {
		this.running--;
		const next = this.queue.shift();
		if (next) {
			this.running++;
			next();
		}
	}
}

export function delay(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}
