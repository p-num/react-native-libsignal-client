import { Chance } from 'chance';
import { log } from '../logger';

export const chance = Chance();

export function sleep(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function test(
	title: string,
	t: () => Promise<void> | void,
	isInner = false
) {
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
}

export async function runTests(tests: (() => Promise<void> | void)[]) {
	log.rootInfo('Running tests');
	const testResults = await Promise.allSettled(tests.map((t) => t()));
	const failedTests = testResults.filter(
		(result) => result.status === 'rejected'
	);
	const passedTests = testResults.filter((result) => {
		return result.status === 'fulfilled';
	});
	if (passedTests.length > 0) {
		log.rootSuccess(
			`${passedTests.length}/${testResults.length} test${
				testResults.length !== 1 ? 's' : ''
			} passed`
		);
	}
	if (failedTests.length > 0) {
		log.rootError(
			`${failedTests.length}/${testResults.length} test${
				testResults.length !== 1 ? 's' : ''
			} failed`
		);
	}
	return {
		ranTests: testResults.length,
		passedTests: passedTests.length,
		failedTests: failedTests.length,
	};
}
