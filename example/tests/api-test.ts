import deepEql from 'deep-eql';
import * as ReactNativeLibsignalClient from 'react-native-libsignal-client';
import { assert, isInstanceOf } from 'typed-assert';

import { test } from './utils';

export const testPreKeyRecord = () =>
	test('PreKeyRecord', async () => {
		const privKey = ReactNativeLibsignalClient.PrivateKey.generate();
		const pubKey = privKey.getPublicKey();
		const pkr = ReactNativeLibsignalClient.PreKeyRecord.new(23, pubKey, privKey);

		assert(
			deepEql(pkr.id(), 23),
			'id is not the same as the the one it was created with'
		);
		assert(
			deepEql(pkr.publicKey().serialized, pubKey.serialized),
			'publicKey is not the same as the the one it was created with'
		);
		assert(
			deepEql(pkr.privateKey().serialized, privKey.serialized),
			'privateKey is not the same as the the one it was created with'
		);
	});


export const testKyberPreKeyRecord = () =>
	test('KyberPreKeyRecord', async () => {
		const timestamp = 9000;
		const keyId = 23;
    const privateKey = ReactNativeLibsignalClient.PrivateKey.generate()
		const record = ReactNativeLibsignalClient.KyberPreKeyRecord.new(
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
