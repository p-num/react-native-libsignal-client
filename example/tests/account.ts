import { Buffer } from '@craftzdog/react-native-buffer';
import deepEqual from 'deep-eql';
import { Aci } from 'react-native-libsignal-client';
import { assert } from 'typed-assert';
import { v4 as generateUuid } from 'uuid';
import * as AccountKeys from '../../src/AccountKeys';
import { assertThrows } from './extentions';
import { test } from './utils';

export const testAccount = () => {
	test('BackupKey', () => {
		const aci = Aci.fromUuidBytes(new Uint8Array(16).fill(0x11));

		test('can be derived or randomly generated', () => {
			const pool = AccountKeys.AccountEntropyPool.generate();
			const backupKey = AccountKeys.AccountEntropyPool.deriveBackupKey(pool);
			assert(deepEqual(32, backupKey.serialized.length));

			const randomKey = AccountKeys.BackupKey.generateRandom();
			assert(
				Buffer.from(backupKey.serialized).toString('hex') !==
					Buffer.from(randomKey.serialized).toString('hex'),
				'Randomly generated key should not equal derived key'
			);
		});

		test('can generate derived keys', () => {
			const pool = AccountKeys.AccountEntropyPool.generate();
			const backupKey = AccountKeys.AccountEntropyPool.deriveBackupKey(pool);
			const randomKey = AccountKeys.BackupKey.generateRandom();
			const otherAci = Aci.fromUuid(generateUuid());

			const backupId = Buffer.from(backupKey.deriveBackupId(aci));
			assert(deepEqual(16, backupId.length));
			assert(
				backupId.toString('hex') !==
					Buffer.from(randomKey.deriveBackupId(aci)).toString('hex'),
				'Backup ID should differ for different backup keys'
			);
			assert(
				backupId.toString('hex') !==
					Buffer.from(backupKey.deriveBackupId(otherAci)).toString('hex'),
				'Backup ID should differ for different ACIs'
			);

			const ecKey = backupKey.deriveEcKey(aci);
			assert(
				Buffer.from(ecKey.serialized).toString('hex') !==
					Buffer.from(randomKey.deriveEcKey(aci).serialized).toString('hex'),
				'EC keys should differ for different backup keys'
			);
			assert(
				Buffer.from(ecKey.serialized).toString('hex') !==
					Buffer.from(backupKey.deriveEcKey(otherAci).serialized).toString(
						'hex'
					),
				'EC keys should differ for different ACIs'
			);

			const localMetadataKey = backupKey.deriveLocalBackupMetadataKey();
			assert(deepEqual(32, localMetadataKey.length));

			const mediaId = backupKey.deriveMediaId('example.jpg');
			assert(deepEqual(15, mediaId.length));

			const mediaKey = backupKey.deriveMediaEncryptionKey(mediaId);
			assert(deepEqual(32 + 32, mediaKey.length));

			assertThrows(() => backupKey.deriveMediaEncryptionKey(Buffer.of(0)));

			// This media ID wasn't for a thumbnail, but the API doesn't (can't) check that.
			const thumbnailKey =
				backupKey.deriveThumbnailTransitEncryptionKey(mediaId);
			assert(deepEqual(32 + 32, mediaKey.length));
			assert(
				Buffer.from(mediaKey).toString('hex') !==
					Buffer.from(thumbnailKey).toString('hex'),
				'Media and thumbnail keys should differ'
			);
		});
	});
};
