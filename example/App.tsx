import { useEffect, useState } from 'react';
import { log } from './logger';
import { TestFeedback } from './TestFeedback';
import { testKyberPreKeyRecord, testPreKeyRecord } from './tests/api-test';
import { runTests, sleep } from './tests/utils';
export type TestStatus = 'IDLE' | 'RUNNING' | 'SUCCESS' | 'ERROR';

export default function App() {
	const [testStatus, setTestStatus] = useState<TestStatus>('IDLE');
	const [msg, setMsg] = useState<string>('');

	useEffect(() => {
		(async () => {
			try {
				setTestStatus('RUNNING');
				await sleep(500);

				const { failedTests, passedTests, ranTests } = await runTests([
					testKyberPreKeyRecord,
					testPreKeyRecord
				]);

				if (failedTests === 0 && passedTests === ranTests) {
					setTestStatus('SUCCESS');
					setMsg('All tests passed!');
				} else {
					setTestStatus('ERROR');
					setMsg(
						`${failedTests}/${ranTests} tests failed! Check the logs for details.`
					);
				}
			} catch (error) {
				setTestStatus('ERROR');
				setMsg('An error occurred');
				log.error(error);
			}
		})();
	}, []);

	return <TestFeedback testStatus={testStatus} errorMessage={msg} />;

}
