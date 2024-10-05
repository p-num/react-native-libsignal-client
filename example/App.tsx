import { useEffect, useState } from "react";
import { log } from "./logger";
import { TestFeedback } from "./TestFeedback";
import {
  testAesCbc,
  testAesGcm,
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
  testSignedPreKeyRecord,
  testSignHmacSha256,
} from "./tests/api-test";
import { runTests, sleep } from "./tests/utils";
import { testZkGroup } from "./tests/zkgroup-test";
export type TestStatus = "IDLE" | "RUNNING" | "SUCCESS" | "ERROR";

export default function App() {
  const [testStatus, setTestStatus] = useState<TestStatus>("IDLE");
  const [msg, setMsg] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        setTestStatus("RUNNING");
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
          testAesGcm,
          testAesCbc,
          testSignHmacSha256,
          testConstantTimeEqual
        ]);

        if (failedTests === 0 && passedTests === ranTests) {
          setTestStatus("SUCCESS");
          setMsg("All tests passed!");
        } else {
          setTestStatus("ERROR");
          setMsg(
            `${failedTests}/${ranTests} tests failed! Check the logs for details.`
          );
        }
      } catch (error) {
        setTestStatus("ERROR");
        setMsg("An error occurred");
        log.error(error);
      }
    })();
  }, []);

  return <TestFeedback testStatus={testStatus} errorMessage={msg} />;
}
