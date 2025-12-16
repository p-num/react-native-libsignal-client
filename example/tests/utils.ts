import { Chance } from 'chance';
import { log } from '../logger';

export const chance = Chance();

let registeredTestPromises: Promise<void>[] = [];

export function sleep(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export function test(
	title: string,
	t: () => Promise<void> | void,
	isInner = false
): Promise<void> {
	const promise = (async () => {
		try {
			if (isInner) {
				log.debug(`${title} is running...`);
			} else {
				log.info(`${title} is running...`);
			}
			await t();
			log.success(`${title} passed`);
		} catch (error) {
			log.error(`${title} failed`, error);
			throw error;
		}
	})();

	registeredTestPromises.push(promise);
	return promise;
}

export async function runTests(tests: (() => Promise<void> | void)[]) {
	log.rootInfo('Running tests');

	registeredTestPromises = [];
	const suiteResults = await Promise.allSettled(tests.map((t) => t()));
	const suiteFailures = suiteResults.filter(
		(result) => result.status === 'rejected'
	).length;

	// Wait for all registered tests, even if suites didn't await them.
	// Some suites may register tests after awaiting, so loop until stable.
	let lastCount = -1;
	while (lastCount !== registeredTestPromises.length) {
		lastCount = registeredTestPromises.length;
		await Promise.allSettled(registeredTestPromises);
	}

	const registeredResults = await Promise.allSettled(registeredTestPromises);
	const baseResults =
		registeredResults.length > 0 ? registeredResults : suiteResults;

	let failed = baseResults.filter(
		(result) => result.status === 'rejected'
	).length;
	const passed = baseResults.filter(
		(result) => result.status === 'fulfilled'
	).length;
	let ran = baseResults.length;

	// If suites rejected (setup errors, etc.), count them as failures too.
	if (registeredResults.length > 0 && suiteFailures > 0) {
		failed += suiteFailures;
		ran += suiteFailures;
	}

	if (passed > 0) {
		log.rootSuccess(`${passed}/${ran} test${ran !== 1 ? 's' : ''} passed`);
	}
	if (failed > 0) {
		log.rootError(`${failed}/${ran} test${ran !== 1 ? 's' : ''} failed`);
	}
	return {
		ranTests: ran,
		passedTests: passed,
		failedTests: failed,
	};
}
