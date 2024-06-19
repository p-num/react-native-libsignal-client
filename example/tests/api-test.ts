import deepEql from 'deep-eql';
import { assert, isInstanceOf } from 'typed-assert';
import { KyberPreKeyRecord, PrivateKey } from "../../src";
import { test } from './utils';

export const testKyberPreKeyRecord = () =>
	test('KyberPreKeyRecord', async () => {
		const timestamp = 9000;
		const keyId = 23;
    const privateKey = PrivateKey.generate()
		const record = KyberPreKeyRecord.new(
			keyId,
			timestamp,
			privateKey.serialized
		);

		assert(
			deepEql(record.id(), keyId),
			`record id ${record.id()} is not the same as the the one it was created with ${keyId}`
		);
		assert(
			deepEql(record.timestamp(), timestamp),
			'timestamp is not the same as the the one it was created with'
		);
		isInstanceOf(record.publicKey().serialized, Uint8Array, 'public key does not exist')
		isInstanceOf(record.secretKey().serialized, Uint8Array, 'secret key does not exist')
		isInstanceOf(record.signature(), Uint8Array, 'signature does not exist')
	});
