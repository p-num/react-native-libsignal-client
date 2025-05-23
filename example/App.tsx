import { useEffect, useState } from 'react';
import { TestFeedback } from './TestFeedback';
import { log } from './logger';
import {
	testAesCbcWithLongInput,
	testAesCbcWithShortInput,
	testAesGcmWithLongInput,
	testAesGcmWithShortInput,
	testConstantTimeEqual,
	testGenerateRegistrationId,
	testHKDF,
	testKyberPreKeyRecord,
	testMessagingDuplicateWithKyber,
	testMessagingDuplicateWithoutKyber,
	testMessagingUnacknowledgedSessionsExpiryWithKyber,
	testMessagingUnacknowledgedSessionsExpiryWithoutKyber,
	testMessagingWithKyber,
	testMessagingWithoutKyber,
	testPreKeyRecord,
	testProtocolAddress,
	testServiceId,
	testSignHmacSha256,
	testSignedPreKeyRecord,
} from './tests/api-test';
import { testGroup } from './tests/group';
import { runTests, sleep } from './tests/utils';
import { testZkGroup } from './tests/zkgroup-test';
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
					testHKDF,
					testServiceId,
					testProtocolAddress,
					testKyberPreKeyRecord,
					testPreKeyRecord,
					testSignedPreKeyRecord,
					testMessagingWithoutKyber,
					testMessagingWithKyber,
					testMessagingDuplicateWithoutKyber,
					testMessagingDuplicateWithKyber,
					testMessagingUnacknowledgedSessionsExpiryWithoutKyber,
					testMessagingUnacknowledgedSessionsExpiryWithKyber,
					testGenerateRegistrationId,
					testZkGroup,
					testAesGcmWithShortInput,
					testAesGcmWithLongInput,
					testAesCbcWithShortInput,
					testAesCbcWithLongInput,
					testSignHmacSha256,
					testConstantTimeEqual,
					testGroup,
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
