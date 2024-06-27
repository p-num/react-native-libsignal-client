import { Buffer } from '@craftzdog/react-native-buffer';
import deepEql from 'deep-eql';
import * as ReactNativeLibsignalClient from 'react-native-libsignal-client';
import { ProtocolAddress } from 'react-native-libsignal-client/Address';
import { assert, isInstanceOf, isNotNull } from 'typed-assert';
import { sessionVersionTestCases } from './api-utils';
import { throwsAsync, throwsSync } from './extentions';
import { TestStores } from './mockStores';
import { test } from './utils';



export const testHKDF = () =>
	test('HKDF', async () => {
		const secret = new Uint8Array(
			Buffer.from('0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B', 'hex')
		);
		const empty = new Uint8Array(Buffer.from('', 'hex'));

		assert(
			deepEql(
				Buffer.from(
					ReactNativeLibsignalClient.hkdf(42, secret, empty, empty)
				).toString('hex'),
				'8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
			)
		);

		assert(
			deepEql(
				Buffer.from(ReactNativeLibsignalClient.hkdf(42, secret, empty, null)).toString(
					'hex'
				),
				'8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
			)
		);

		const salt = new Uint8Array(
			Buffer.from('000102030405060708090A0B0C', 'hex')
		);
		const label = new Uint8Array(Buffer.from('F0F1F2F3F4F5F6F7F8F9', 'hex'));

		assert(
			deepEql(
				Buffer.from(ReactNativeLibsignalClient.hkdf(42, secret, label, salt)).toString(
					'hex'
				),
				'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
			)
		);
	});

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

const testMessagingDuplicate = (index: 0 | 1) => () => {
	const testCase = sessionVersionTestCases[index];

	return test(`test Messaging Session Duplicate ${testCase.suffix}`, async () => {
		const bobStores = new TestStores();
		const aliceStores = new TestStores();

		const aAddress = new ProtocolAddress('+14151111111', 1);
		const bAddress = new ProtocolAddress('+19192222222', 1);

		await testCase.makeAndProcessBundle(bAddress, bobStores, aliceStores.session, aliceStores.identity);

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

		await throwsAsync(() =>
			ReactNativeLibsignalClient.signalDecryptPreKey(
				aCiphertextR,
				aAddress,
				bobStores.session,
				bobStores.identity,
				bobStores.prekey,
				bobStores.signed,
				bobStores.kyber,
				kyberKeyIds
			)
		);
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

		assert(deepEql(aDPlaintext, bMessage));
		await throwsAsync(() =>
			ReactNativeLibsignalClient.signalDecrypt(
				bCiphertextR,
				bAddress,
				aliceStores.session,
				aliceStores.identity
			)
		);
	});
};

export const testMessagingDuplicateWithoutKyber = testMessagingDuplicate(0);

export const testMessagingDuplicateWithKyber = testMessagingDuplicate(1);

const testMessagingUnacknowledgedSessionsExpiry = (index: 0 | 1) => {
	const testCase = sessionVersionTestCases[index];

	return test(`test Messaging Session Unacknowledged Sessions Expiry ${testCase.suffix}`, async () => {
		const aliceStores = new TestStores();
		const bobStores = new TestStores();

		const bAddress = new ProtocolAddress('+19192222222', 1);

		await testCase.makeAndProcessBundle(bAddress, bobStores, aliceStores.session, aliceStores.identity);

		const initialSession = await aliceStores.session.getSession(bAddress);
		console.log("OOOOOOOOOO", {initialSession})
		assert(initialSession ? initialSession.hasCurrentState(new Date('2020-01-01')) : false);
		assert(initialSession? initialSession.hasCurrentState(new Date('2023-01-01')) : true);

		const aMessage = new Uint8Array(Buffer.from('Greetings hoo-man', 'utf8'));
		const aCiphertext = await ReactNativeLibsignalClient.signalEncrypt(
			aMessage,
			bAddress,
			aliceStores.session,
			aliceStores.identity,
			new Date('2020-01-01')
		);

		assert(
			deepEql(
				aCiphertext.type(),
				ReactNativeLibsignalClient.CiphertextMessageType.PreKey
			),
			'CiphertextMessageType of aCiphertext is not the same as the the one it was created with'
		);

		const updatedSession = await aliceStores.session.getSession(bAddress);
		assert(updatedSession ? updatedSession.hasCurrentState(new Date('2020-01-01')) : false);
		assert(updatedSession ? updatedSession.hasCurrentState(new Date('2023-01-01')) : true);

		throwsSync(() =>
			ReactNativeLibsignalClient.signalEncrypt(
				aMessage,
				bAddress,
				aliceStores.session,
				aliceStores.identity,
				new Date('2023-01-01')
			)
		);
	});
};

export const testMessagingUnacknowledgedSessionsExpiryWithoutKyber = () =>
	testMessagingUnacknowledgedSessionsExpiry(0);

export const testMessagingUnacknowledgedSessionsExpiryWithKyber = () =>
	testMessagingUnacknowledgedSessionsExpiry(1);

export const testSignedPreKeyRecord = () =>
	test('SignedPreKeyRecord', async () => {
		const privKey = ReactNativeLibsignalClient.PrivateKey.generate();
		const pubKey = privKey.getPublicKey();
		const timestamp = 9000;
		const keyId = 23;
		const signature = new Uint8Array(Buffer.alloc(64, 64));
		const spkr = ReactNativeLibsignalClient.SignedPreKeyRecord.new(
			keyId,
			timestamp,
			pubKey,
			privKey,
			signature
		);

		assert(
			deepEql(spkr.id(), keyId),
			'id is not the same as the the one it was created with'
		);
		assert(
			deepEql(spkr.timestamp(), timestamp),
			'timestamp is not the same as the the one it was created with'
		);
		assert(
			deepEql(spkr.publicKey().serialized, pubKey.serialized),
			'publicKey is not the same as the the one it was created with'
		);
		assert(
			deepEql(spkr.privateKey().serialized, privKey.serialized),
			'privateKey is not the same as the the one it was created with'
		);
		assert(
			deepEql(spkr.signature(), signature),
			'signature is not the same as the the one it was created with'
		);
	});

// export const testSenderKeyMessage = () =>
// 	test('Sender Key Message', async () => {
// 		const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
// 		const chainId = 9;
// 		const iteration = 101;
// 		const ciphertext = new Uint8Array(Buffer.alloc(32, 0xfe));
// 		const pk = ReactNativeLibsignalClient.PrivateKey.generate();

// 		const skm = ReactNativeLibsignalClient.SenderKeyMessage._new(
// 			3,
// 			distributionId,
// 			chainId,
// 			iteration,
// 			ciphertext,
// 			pk
// 		);
// 		assert(
// 			deepEql(skm.distributionId(), distributionId),
// 			'distributionId is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(skm.chainId(), chainId),
// 			'chainId is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(skm.iteration(), iteration),
// 			'iteration is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(skm.ciphertext(), ciphertext),
// 			'ciphertext is not the same as the the one it was created with'
// 		);

// 		assert(skm.verifySignature(pk.getPublicKey()), 'verifySignature is false');

// 		const skmFromBytes = ReactNativeLibsignalClient.SenderKeyMessage._fromSerialized(
// 			skm.serialize()
// 		);
// 		assert(
// 			deepEql(skm.serialize(), skmFromBytes.serialized),
// 			'skm is not the same as the the one it was created with'
// 		);
// 	});

// export const testSenderKeyDistributionMessage = () =>
// 	test('Sender Key Distribution Message', async () => {
// 		const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
// 		const chainId = 9;
// 		const iteration = 101;
// 		const chainKey = new Uint8Array(Buffer.alloc(32, 0xfe));
// 		const pk = ReactNativeLibsignalClient.PrivateKey.generate();

// 		const skdm = ReactNativeLibsignalClient.SenderKeyDistributionMessage._new(
// 			3,
// 			distributionId,
// 			chainId,
// 			iteration,
// 			chainKey,
// 			pk.getPublicKey()
// 		);
// 		assert(
// 			deepEql(skdm.distributionId(), distributionId),
// 			'distributionId is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(skdm.chainId(), chainId),
// 			'chainId is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(skdm.iteration(), iteration),
// 			'iteration is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(skdm.chainKey(), chainKey),
// 			'chainKey is not the same as the the one it was created with'
// 		);
// 	});


// export const testSenderCertificate = () =>
// 	test('Sender Certificate', async () => {
// 		const trustRoot = ReactNativeLibsignalClient.PrivateKey.generate();
// 		const serverKey = ReactNativeLibsignalClient.PrivateKey.generate();

// 		const keyId = 23;

// 		const serverCert = ReactNativeLibsignalClient.ServerCertificate.new(
// 			keyId,
// 			serverKey.getPublicKey(),
// 			trustRoot
// 		);
// 		assert(
// 			deepEql(serverCert.keyId(), keyId),
// 			'keyId is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(
// 				serverCert.key().serialize(),
// 				serverKey.getPublicKey().serialized
// 			),
// 			'key is not the same as the the one it was created with'
// 		);

// 		const serverCertFromBytes =
// 			ReactNativeLibsignalClient.ServerCertificate._fromSerialized(serverCert.serialize());
// 		assert(
// 			deepEql(serverCert.serialize(), serverCertFromBytes.serialized),
// 			'serverCert is not the same as the the one it was created with'
// 		);

// 		const senderUuid = 'fedfe51e-2b91-4156-8710-7cc1bdd57cd8';
// 		const senderE164 = '555-123-4567';
// 		const senderDeviceId = 9;
// 		const senderKey = ReactNativeLibsignalClient.PrivateKey.generate();
// 		const expiration = 2114398800; // Jan 1, 2037

// 		const senderCert = ReactNativeLibsignalClient.SenderCertificate.new(
// 			senderUuid,
// 			senderE164,
// 			senderDeviceId,
// 			senderKey.getPublicKey(),
// 			expiration,
// 			serverCert,
// 			serverKey
// 		);

// 		assert(
// 			deepEql(
// 				senderCert.serverCertificate().serialize(),
// 				serverCert.serialize()
// 			),
// 			'serverCertificate is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(senderCert.senderUuid(), senderUuid),
// 			'senderUuid is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(senderCert.senderAci()?.getRawUuid(), senderUuid),
// 			'senderAci is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(senderCert.senderE164(), senderE164),
// 			'senderE164 is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(senderCert.senderDeviceId(), senderDeviceId),
// 			'senderDeviceId is not the same as the the one it was created with'
// 		);

// 		const senderCertFromBytes =
// 			ReactNativeLibsignalClient.SenderCertificate._fromSerialized(senderCert.serialize());
// 		assert(
// 			deepEql(senderCert.serialize(), senderCertFromBytes.serialized),
// 			'senderCert is not the same as the the one it was created with'
// 		);

// 		assert(
// 			senderCert.validate(trustRoot.getPublicKey(), expiration - 1000),
// 			'validate is false'
// 		);
// 		assert(
// 			!senderCert.validate(trustRoot.getPublicKey(), expiration + 10),
// 			'validate is true'
// 		);

// 		const senderCertWithoutE164 = ReactNativeLibsignalClient.SenderCertificate.new(
// 			senderUuid,
// 			null,
// 			senderDeviceId,
// 			senderKey.getPublicKey(),
// 			expiration,
// 			serverCert,
// 			serverKey
// 		);

// 		assert(
// 			deepEql(
// 				senderCertWithoutE164.serverCertificate().serialize(),
// 				serverCert.serialize()
// 			),
// 			'serverCertificate is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(senderCertWithoutE164.senderUuid(), senderUuid),
// 			'senderUuid is not the same as the the one it was created with'
// 		);
// 		assert(
// 			deepEql(senderCertWithoutE164.senderAci()?.getRawUuid(), senderUuid),
// 			'senderAci is not the same as the the one it was created with'
// 		);
// 		// TODO: Fix
// 		// assert(
// 		// 	deepEql(senderCertWithoutE164.senderE164(), null),
// 		// 	'senderE164 is not the same as the the one it was created with'
// 		// );
// 		assert(
// 			deepEql(senderCertWithoutE164.senderDeviceId(), senderDeviceId),
// 			'senderDeviceId is not the same as the the one it was created with'
// 		);
// 	});
