import { Buffer } from '@craftzdog/react-native-buffer';
import deepEql from 'deep-eql';
import * as ReactNativeLibsignalClient from 'react-native-libsignal-client';
import { ProtocolAddress } from 'react-native-libsignal-client/Address';
import { assert, isInstanceOf, isNotNull } from 'typed-assert';
import { sessionVersionTestCases } from './api-utils';
import { TestStores } from './mockStores';
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



const testMessaging = (index: 0 | 1) => {
	const testCase = sessionVersionTestCases[index];
	test(`test Messaging Session ${testCase.suffix}`, async () => {
		const aliceStores = new TestStores();
		const bobStores = new TestStores();

		const aAddress = new ProtocolAddress('+14151111111', 1);
		const bAddress = new ProtocolAddress('+19192222222', 1);

		await testCase.makeAndProcessBundle(bAddress, bobStores, aliceStores.session, aliceStores.identity);

		const aSession = await aliceStores.session.getSession(bAddress);
		
		isNotNull(aSession, 'session is null');
		assert(aSession.serialized.length > 0, 'session.serialize().length <= 0');
		assert(
			deepEql(aSession.localRegistrationId(), 5),
			'localRegistrationId is not the same as the the one it was created with'
		);
		assert(
			deepEql(aSession.remoteRegistrationId(), 5),
			'remoteRegistrationId is not the same as the the one it was created with'
		);
		assert(aSession.hasCurrentState(), 'session has no current state');
		assert(
			!aSession.currentRatchetKeyMatches(
				ReactNativeLibsignalClient.PrivateKey.generate().getPublicKey()
			),
			'currentRatchetKeyMatches is true'
		);

		const aMessage = new Uint8Array(Buffer.from('Greetings hoo-man', 'utf8'));

		const aCiphertext = await ReactNativeLibsignalClient.signalEncrypt(
			aMessage,
			bAddress,
			aliceStores.session,
			aliceStores.identity
		);
		assert(
			deepEql(
				aCiphertext.type(),
				ReactNativeLibsignalClient.CiphertextMessageType.PreKey
			),
			'CiphertextMessageType of aCiphertext is not the same as the the one it was created with'
		);

		const aCiphertextR = ReactNativeLibsignalClient.PreKeySignalMessage._fromSerialized(
			aCiphertext.serialized
		);
		const kyberKeyIds = bobStores.kyber._getAllKyberKeyIds();
		const bDPlaintext = await ReactNativeLibsignalClient.signalDecryptPreKey(
			aCiphertextR,
			aAddress,
			bobStores.session,
			bobStores.identity,
			bobStores.prekey,
			bobStores.signed,
			bobStores.kyber,
			kyberKeyIds
		);
		assert(deepEql(bDPlaintext, aMessage));

		const bMessage = new Uint8Array(
			Buffer.from(
				'Sometimes the only thing more dangerous than a question is an answer.',
				'utf8'
			)
		);
		const bCiphertext = await ReactNativeLibsignalClient.signalEncrypt(
			bMessage,
			aAddress,
			bobStores.session,
			bobStores.identity
		);
		assert(
			deepEql(
				bCiphertext.type(),
				ReactNativeLibsignalClient.CiphertextMessageType.Whisper
			),
			'CiphertextMessageType of bCiphertext is not the same as the the one it was created with'
		);

		const bCiphertextR = ReactNativeLibsignalClient.SignalMessage._fromSerialized(
			bCiphertext.serialized
		);

		const aDPlaintext = await ReactNativeLibsignalClient.signalDecrypt(
			bCiphertextR,
			bAddress,
			aliceStores.session,
			aliceStores.identity
		);
		assert(deepEql(aDPlaintext, bMessage), 'aDPlaintext !== bMessage');

		const bSession = await bobStores.session.getSession(aAddress);
		
		isNotNull(bSession, 'session is null');

		assert(bSession.serialized.length > 0, 'session.serialize().length <= 0');
		assert(
			deepEql(bSession.localRegistrationId(), 5),
			'localRegistrationId is not the same as the the one it was created with'
		);
		assert(
			deepEql(bSession.remoteRegistrationId(), 5),
			'remoteRegistrationId is not the same as the the one it was created with'
		);
		assert(bSession.hasCurrentState(), 'session has no current state');
		assert(
			!bSession.currentRatchetKeyMatches(
				ReactNativeLibsignalClient.PrivateKey.generate().getPublicKey()
			),
			'currentRatchetKeyMatches is true'
		);
		bSession.archiveCurrentState();
		assert(
			!bSession.hasCurrentState(),
			'session has current state after archiveCurrentState'
		);
		assert(
			!bSession.currentRatchetKeyMatches(
				ReactNativeLibsignalClient.PrivateKey.generate().getPublicKey()
			),
			'currentRatchetKeyMatches is true'
		);
	});
};

export const testMessagingWithoutKyber = () => testMessaging(0);

export const testMessagingWithKyber = () => testMessaging(1);