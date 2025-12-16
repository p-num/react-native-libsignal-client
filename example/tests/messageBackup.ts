import { Buffer } from '@craftzdog/react-native-buffer';
import deepEqual from 'deep-eql';
import { Asset } from 'expo-asset';
import Constants from 'expo-constants';
import * as FileSystem from 'expo-file-system';
import { Aci, hkdf } from 'react-native-libsignal-client';
import {
	AccountEntropyPool,
	BackupKey,
} from 'react-native-libsignal-client/AccountKeys';
import * as MessageBackup from 'react-native-libsignal-client/MessageBackup';
import { Readable } from 'readable-stream';
import { assert } from 'typed-assert';
import { assertThrows } from './extentions';
import { test } from './utils';

export const testMessageBackup = () => {
	test('AccountEntropyPool', () => {
		test('isValid', () => {
			assert(
				AccountEntropyPool.isValid('invalid key') === false,
				'invalid key'
			);
			assert(
				AccountEntropyPool.isValid(
					'0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr'
				) === true,
				'valid key'
			);
		});
	});

	test('MessageBackup', () => {
		const accountEntropy = 'm'.repeat(64);
		const aci = Aci.fromUuidBytes(new Uint8Array(16).fill(0x11));
		const testKey = new MessageBackup.MessageBackupKey({ accountEntropy, aci });
		const purpose = MessageBackup.Purpose.RemoteBackup;
		const TEST_NEW_ACCOUNT_BINPROTO_ENCRYPTED = Asset.fromModule(
			require('../assets/new-account.binproto.encrypted')
		);
		const TEST_EMPTY_FILE = Asset.fromModule(
			require('../assets/emptyfile.binproto')
		);

		test('validate', () => {
			test('successfully validates a minimal backup', async () => {
				// const input = fs.readFileSync(
				// 	path.join(__dirname, '../../ts/test/new_account.binproto.encrypted')
				// );
				if (!Constants.expoConfig?.extra?.userDataPath) {
					throw new Error('userDataPath is not defined in app.config');
				}

				await TEST_NEW_ACCOUNT_BINPROTO_ENCRYPTED.downloadAsync();

				const info = await FileSystem.getInfoAsync(
					TEST_NEW_ACCOUNT_BINPROTO_ENCRYPTED.localUri!
				);
				if (!info.exists) {
					throw new Error('Failed to download asset');
				}

				const outcome = await MessageBackup.validate(
					testKey,
					purpose,
					TEST_NEW_ACCOUNT_BINPROTO_ENCRYPTED.localUri!,
					info.size
				);
				assert(outcome.errorMessage == null, `error: ${outcome.errorMessage}`);

				// If we manually derive the test key's backup key and ID, we should get the same outcome.
				const backupKey = hkdf(
					32,
					new Uint8Array(Buffer.from(accountEntropy, 'utf8')),
					new Uint8Array(Buffer.from('20240801_SIGNAL_BACKUP_KEY', 'utf8')),
					null
				);
				const backupId = hkdf(
					16,
					backupKey,
					new Uint8Array(
						Buffer.concat([
							new Uint8Array(Buffer.from('20241024_SIGNAL_BACKUP_ID:', 'utf8')),
							aci.getServiceIdBinary(),
						])
					),
					null
				);
				const testKeyFromBackupId = new MessageBackup.MessageBackupKey({
					backupKey: new BackupKey(backupKey),
					backupId,
				});

				const outcome2 = await MessageBackup.validate(
					testKeyFromBackupId,
					purpose,
					TEST_NEW_ACCOUNT_BINPROTO_ENCRYPTED.localUri!,
					info.size
				);
				assert(
					outcome2.errorMessage == null,
					`error2: ${outcome2.errorMessage}`
				);
			});

			test('provides its HMAC and AES keys', () => {
				// Just check some basic expectations.
				assert(32 === testKey.hmacKey.length, 'hmacKey length');
				assert(32 === testKey.aesKey.length, 'aesKey length');
				assert(testKey.hmacKey !== testKey.aesKey, 'keys are distinct');
			});

			test('produces an error message on empty input', async () => {
				if (!TEST_EMPTY_FILE.downloaded) {
					await TEST_EMPTY_FILE.downloadAsync();
				}

				const info = await FileSystem.getInfoAsync(TEST_EMPTY_FILE.localUri!);
				if (!info.exists) {
					throw new Error('Failed to download asset');
				}

				assertThrows(async () => {
					await MessageBackup.validate(
						testKey,
						purpose,
						TEST_EMPTY_FILE.localUri!,
						0
					);
				}, 'not enough bytes for an HMAC');
			});

			// it('throws a raised IO error', async () => {
			//     if (!TEST_EMPTY_FILE.downloaded) {
			//         await TEST_EMPTY_FILE.downloadAsync()
			//     }

			//     const info = await FileSystem.getInfoAsync(TEST_EMPTY_FILE.localUri!);
			//     if (!info.exists) {
			//         throw new Error("Failed to download asset");
			//     }
			// 	try {
			// 		await MessageBackup.validate(
			// 			testKey,
			// 			purpose,
			// 			() => new ErrorInputStream(),
			// 			234n
			// 		);
			// 		assert.fail('did not throw');
			// 	} catch (e) {
			// 		assert.instanceOf(e, ErrorInputStream.Error);
			// 	}
			// });

			// it('closes the streams it creates', async () => {
			// 	let openCount = 0;
			// 	let closeCount = 0;
			// 	class CloseCountingInputStream extends InputStream {
			// 		/* eslint-disable @typescript-eslint/require-await */
			// 		async close(): Promise<void> {
			// 			closeCount += 1;
			// 		}
			// 		async read(_amount: number): Promise<Buffer> {
			// 			return Buffer.of();
			// 		}
			// 		async skip(amount: number): Promise<void> {
			// 			if (amount > 0) {
			// 				throw Error("can't skip in an empty stream");
			// 			}
			// 		}
			// 		/* eslint-enable @typescript-eslint/require-await */
			// 	}

			// 	const outcome = await MessageBackup.validate(
			// 		testKey,
			// 		purpose,
			// 		() => {
			// 			openCount += 1;
			// 			return new CloseCountingInputStream();
			// 		},
			// 		0n
			// 	);
			// 	assert.equal(outcome.errorMessage, 'not enough bytes for an HMAC');
			// 	assert.isAbove(openCount, 0, 'never opened?');
			// 	assert.equal(openCount, closeCount, 'failed to close all streams');
			// });
		});
	});

	// const exampleBackup = fs.readFileSync(
	// 	path.join(__dirname, '../../ts/test/canonical-backup.binproto')
	// );

	const TEST_CANONICAL_BACKUP = Asset.fromModule(
		require('../assets/canonical-backup.binproto')
	);

	test('ComparableBackup', () => {
		test('exampleBackup', () => {
			test('stringifies to the expected value', async () => {
				if (!TEST_CANONICAL_BACKUP.downloaded) {
					await TEST_CANONICAL_BACKUP.downloadAsync();
				}

				const info = await FileSystem.getInfoAsync(
					TEST_CANONICAL_BACKUP.localUri!
				);
				if (!info.exists) {
					throw new Error('Failed to download asset');
				}

				const comparable = await MessageBackup.ComparableBackup.fromUnencrypted(
					MessageBackup.Purpose.RemoteBackup,
					TEST_CANONICAL_BACKUP.localUri!,
					info.size
				);

				const canonExpected = require('../assets/canonical-backup.expected.json');
				const output = comparable.comparableString();
				assert(deepEqual(JSON.parse(output), canonExpected));
			});
		});
	});

	test('OnlineBackupValidator', () => {
		test('can read frames from a valid file', async () => {
			if (!TEST_CANONICAL_BACKUP.downloaded) {
				await TEST_CANONICAL_BACKUP.downloadAsync();
			}

			const file = FileSystem.readAsStringAsync(
				TEST_CANONICAL_BACKUP.localUri!,
				{ encoding: FileSystem.EncodingType.Base64 }
			);
			const backupContent = new Uint8Array(Buffer.from(await file, 'base64'));
			// const input = new ReadableStream<Uint8Array>();
			// `Readable.read` normally returns `any`, because it supports settable encodings.
			// Here we override that `read` member with one that always produces a Buffer,
			// for more convenient use in the test. Note that this is unchecked.
			type ReadableUsingBuffer = Omit<Readable, 'read'> & {
				read(size: number): Buffer;
			};
			const input: ReadableUsingBuffer = new Readable();
			input.push(backupContent);
			input.push(null);

			const backupInfoLength = input.read(1)[0];
			assert(backupInfoLength < 0x80, 'single-byte varint');
			const backupInfo = input.read(backupInfoLength);
			assert(backupInfo.length === backupInfoLength, 'unexpected EOF');
			const backup = new MessageBackup.OnlineBackupValidator(
				new Uint8Array(backupInfo),
				MessageBackup.Purpose.RemoteBackup
			);

			let frameLengthBuf: Buffer | null;
			// biome-ignore lint/suspicious/noAssignInExpressions: <explanation>
			while ((frameLengthBuf = input.read(1))) {
				let frameLength = frameLengthBuf[0];
				// Tiny varint parser, only supports two bytes.
				if (frameLength >= 0x80) {
					const secondByte = input.read(1)[0];
					assert(secondByte < 0x80, 'at most a two-byte varint');
					frameLength -= 0x80;
					frameLength |= secondByte << 7;
				}
				const frame = input.read(frameLength);
				assert(deepEqual(frame.length, frameLength));
				backup.addFrame(new Uint8Array(frame));
			}

			backup.finalize();
		});

		test('rejects invalid BackupInfo', () => {
			assertThrows(
				() =>
					new MessageBackup.OnlineBackupValidator(
						new Uint8Array(),
						MessageBackup.Purpose.RemoteBackup
					)
			);
		});

		// The following payload was generated via protoscope.
		// % protoscope -s | base64
		// The fields are described by Backup.proto.
		//
		// 1: 1
		// 2: 1731715200000
		// 3: {`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`}
		const VALID_BACKUP_INFO: Uint8Array = new Uint8Array(
			Buffer.from(
				'CAEQgOiTkrMyGiAAESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaq7zN3u/w==',
				'base64'
			)
		);

		test('rejects invalid Frames', () => {
			const backup = new MessageBackup.OnlineBackupValidator(
				VALID_BACKUP_INFO,
				MessageBackup.Purpose.RemoteBackup
			);
			assertThrows(() => backup.addFrame(new Uint8Array()));
		});

		test('rejects invalid backups on finalize', () => {
			const backup = new MessageBackup.OnlineBackupValidator(
				VALID_BACKUP_INFO,
				MessageBackup.Purpose.RemoteBackup
			);
			assertThrows(() => backup.finalize());
		});
	});
};
