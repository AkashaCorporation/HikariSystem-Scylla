/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License for XSStrike-inspired logic.
 *--------------------------------------------------------------------------------------------*/

/**
 * Adaptive Rate Limiter
 * Provides exponential back-off capabilities for evading WAF rate-limiting rules.
 */
export class RateLimiter {
	private baseDelayMs: number;
	private maxRetries: number;
	private currentMultiplier: number = 1;
	
	constructor(baseDelayMs: number = 100, maxRetries: number = 3) {
		this.baseDelayMs = baseDelayMs;
		this.maxRetries = maxRetries;
	}

	/**
	 * Executes an asynchronous function with adaptive exponential back-off if WAF blocks are detected.
	 * Evaluates the success of the request via the `checkSuccess` predicate (e.g. status code != 403 or 429).
	 */
	public async executeWithBackoff<T>(
		task: () => Promise<T>,
		checkSuccess: (result: T) => boolean
	): Promise<T | null> {
		let attempts = 0;

		while (attempts <= this.maxRetries) {
			if (this.currentMultiplier > 1) {
				const delay = this.baseDelayMs * this.currentMultiplier;
				await this.sleep(delay);
			} else if (this.baseDelayMs > 0) {
				await this.sleep(this.baseDelayMs);
			}

			try {
				const result = await task();

				if (checkSuccess(result)) {
					// Request succeeded, slowly recover the multiplier to speed back up
					if (this.currentMultiplier > 1) {
						this.currentMultiplier = Math.max(1, this.currentMultiplier - 1);
					}
					return result;
				} else {
					// Request blocked by WAF (e.g. 403, 429, Connection Reset)
					attempts++;
					this.currentMultiplier *= 2; // Exponential backoff
				}
			} catch (err) {
				// Network error (timeout/reset)
				attempts++;
				this.currentMultiplier *= 2;
			}
		}

		// Failed after max retries
		return null;
	}

	private sleep(ms: number): Promise<void> {
		return new Promise(resolve => setTimeout(resolve, ms));
	}
}
