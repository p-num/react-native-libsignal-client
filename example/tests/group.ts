import { Buffer } from '@craftzdog/react-native-buffer';
import deepEqual from 'deep-eql';
import { assert, isInstanceOf } from 'typed-assert';

import {
	ContentHint,
	ErrorCode,
	type LibSignalError,
	LibSignalErrorBase,
	PreKeyRecord,
	PrivateKey,
	ProtocolAddress,
	SenderCertificate,
	SenderKeyDistributionMessage,
	ServerCertificate,
	ServiceId,
	SignedPreKeyRecord,
	UnidentifiedSenderMessageContent,
	createAndProcessPreKeyBundle,
	groupDecrypt,
	groupEncrypt,
	processSenderKeyDistributionMessage,
	sealedSenderDecryptMessage,
	sealedSenderDecryptToUsmc,
	sealedSenderEncrypt,
	sealedSenderEncryptMessage,
	sealedSenderMultiRecipientEncrypt,
	sealedSenderMultiRecipientMessageForSingleRecipient,
	signalEncrypt,
} from '../../src';
import { TestStores } from './mockStores';
import { test } from './utils';

export const testGroup = () => {
	test('can encrypt and decrypt group', async () => {
		const aliceStores = new TestStores();
		const bobStores = new TestStores();
		const sender = ProtocolAddress.new('sender.1');
		const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
		const aSenderKeyStore = aliceStores.sender;
		const skdm = await SenderKeyDistributionMessage.create(
			sender,
			distributionId,
			aSenderKeyStore
		);
		assert(deepEqual(distributionId, skdm.distributionId()));
		assert(deepEqual(0, skdm.iteration()));

		const bSenderKeyStore = bobStores.sender;
		await processSenderKeyDistributionMessage(sender, skdm, bSenderKeyStore);

		const message = new Uint8Array(Buffer.from('0a0b0c', 'hex'));

		const aCtext = await groupEncrypt(
			sender,
			distributionId,
			aSenderKeyStore,
			new Uint8Array(message)
		);

		const bPtext = await groupDecrypt(
			sender,
			bSenderKeyStore,
			aCtext.serialized
		);

		assert(deepEqual(message, bPtext));

		const anotherSkdm = await SenderKeyDistributionMessage.create(
			sender,
			distributionId,
			aSenderKeyStore
		);
		assert(deepEqual(skdm.chainId(), anotherSkdm.chainId()));
		assert(deepEqual(1, anotherSkdm.iteration()));
	});

	test('can encrypt/decrypt group messages', async () => {
		const aliceStores = new TestStores();
		const bobStores = new TestStores();
		const aKeys = aliceStores.identity;
		const bKeys = bobStores.identity;

		const aSess = aliceStores.session;

		const bPreK = bobStores.prekey;
		const bSPreK = bobStores.signed;

		const bPreKey = PrivateKey.generate();
		const bSPreKey = PrivateKey.generate();

		const aIdentityKey = await aKeys.getIdentityKey();
		const bIdentityKey = await bKeys.getIdentityKey();

		const aE164 = '+14151111111';

		const aDeviceId = 1;
		const bDeviceId = 3;

		const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
		const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

		const trustRoot = PrivateKey.generate();
		const serverKey = PrivateKey.generate();

		const serverCert = ServerCertificate.new(
			1,
			serverKey.getPublicKey(),
			trustRoot
		);

		const expires = 1605722925;
		const senderCert = SenderCertificate.new(
			aUuid,
			aE164,
			aDeviceId,
			aIdentityKey.getPublicKey(),
			expires,
			serverCert,
			serverKey
		);

		const bRegistrationId = await bKeys.getLocalRegistrationId();
		const bPreKeyId = 31337;
		const bSignedPreKeyId = 22;

		const bSignedPreKeySig = bIdentityKey.sign(
			bSPreKey.getPublicKey().serialized
		);
		const bAddress = ProtocolAddress.new(`${bUuid}.${bDeviceId}`);

		const bPreKeyRecord = PreKeyRecord.new(
			bPreKeyId,
			bPreKey.getPublicKey(),
			bPreKey
		);
		await bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

		const bSPreKeyRecord = SignedPreKeyRecord.new(
			bSignedPreKeyId,
			42,
			bSPreKey.getPublicKey(),
			bSPreKey,
			bSignedPreKeySig
		);
		await bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

		createAndProcessPreKeyBundle(
			bRegistrationId,
			bAddress,
			bPreKeyId,
			bPreKey.getPublicKey(),
			bSignedPreKeyId,
			bSPreKey.getPublicKey(),
			bSignedPreKeySig,
			bIdentityKey.getPublicKey(),
			aSess,
			aKeys,
			null
		);

		const aAddress = ProtocolAddress.new(`${aUuid}.${aDeviceId}`);

		const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
		const aSenderKeyStore = aliceStores.sender;
		const skdm = await SenderKeyDistributionMessage.create(
			aAddress,
			distributionId,
			aSenderKeyStore
		);

		const bSenderKeyStore = bobStores.sender;
		await processSenderKeyDistributionMessage(aAddress, skdm, bSenderKeyStore);

		const message = new Uint8Array(Buffer.from('0a0b0c', 'hex'));

		const aCtext = await groupEncrypt(
			aAddress,
			distributionId,
			aSenderKeyStore,
			new Uint8Array(message)
		);

		const aUsmc = UnidentifiedSenderMessageContent.new(
			aCtext,
			senderCert,
			ContentHint.Implicit,
			new Uint8Array(Buffer.from([42]))
		);

		const aSealedSenderMessage = await sealedSenderMultiRecipientEncrypt(
			aUsmc,
			[bAddress],
			aKeys,
			aSess
		);

		const bSealedSenderMessage =
			sealedSenderMultiRecipientMessageForSingleRecipient(aSealedSenderMessage);

		const bUsmc = await sealedSenderDecryptToUsmc(bSealedSenderMessage, bKeys);

		assert(
			deepEqual(bUsmc.senderCertificate().senderE164(), aE164),
			'sender E164 an calculated certificate E164 were not equal.'
		);
		assert(
			deepEqual(bUsmc.senderCertificate().senderUuid(), aUuid),
			'sender certificate uuid is not equal to expected uuid'
		);
		assert(
			deepEqual(bUsmc.senderCertificate().senderDeviceId(), aDeviceId),
			'sender certificate device id is not equal to expected device id'
		);
		assert(
			deepEqual(bUsmc.contentHint(), ContentHint.Implicit),
			'decrypted content hint is not implicit'
		);
		assert(
			deepEqual(bUsmc.groupId(), new Uint8Array(Buffer.from([42]))),
			'group id    missmatch'
		);

		const bPtext = await groupDecrypt(
			aAddress,
			bSenderKeyStore,
			bUsmc.contents()
		);

		assert(deepEqual(message, bPtext));

		// Make sure the option-based syntax does the same thing.
		const aSealedSenderMessageViaOptions =
			await sealedSenderMultiRecipientEncrypt({
				content: aUsmc,
				recipients: [bAddress],
				identityStore: aKeys,
				sessionStore: aSess,
			});

		const bSealedSenderMessageViaOptions =
			sealedSenderMultiRecipientMessageForSingleRecipient(
				aSealedSenderMessageViaOptions
			);

		const bUsmcViaOptions = await sealedSenderDecryptToUsmc(
			bSealedSenderMessageViaOptions,
			bKeys
		);

		assert(deepEqual(bUsmcViaOptions, bUsmc));
	});

	test('rejects invalid registration IDs', async () => {
		const aliceStores = new TestStores();
		const bobStores = new TestStores();

		const aSess = new TestStores();

		const bPreKey = PrivateKey.generate();
		const bSPreKey = PrivateKey.generate();

		const aIdentityKey = await aliceStores.identity.getIdentityKey();
		const bIdentityKey = await bobStores.identity.getIdentityKey();

		const aE164 = '+14151111111';

		const aDeviceId = 1;
		const bDeviceId = 3;

		const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
		const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

		const trustRoot = PrivateKey.generate();
		const serverKey = PrivateKey.generate();

		const serverCert = ServerCertificate.new(
			1,
			serverKey.getPublicKey(),
			trustRoot
		);

		const expires = 1605722925;
		const senderCert = SenderCertificate.new(
			aUuid,
			aE164,
			aDeviceId,
			aIdentityKey.getPublicKey(),
			expires,
			serverCert,
			serverKey
		);

		const bPreKeyId = 31337;
		const bSignedPreKeyId = 22;

		const bSignedPreKeySig = bIdentityKey.sign(
			bSPreKey.getPublicKey().serialized
		);

		const bAddress = ProtocolAddress.new(`${bUuid}.${bDeviceId}`);
		createAndProcessPreKeyBundle(
			0x4000,
			bAddress,
			bPreKeyId,
			bPreKey.getPublicKey(),
			bSignedPreKeyId,
			bSPreKey.getPublicKey(),
			bSignedPreKeySig,
			bIdentityKey.getPublicKey(),
			aliceStores.session,
			aliceStores.identity,
			null
		);

		const aAddress = ProtocolAddress.new(`${aUuid}.${aDeviceId}`);

		const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
		const aSenderKeyStore = aliceStores.sender;
		await SenderKeyDistributionMessage.create(
			aAddress,
			distributionId,
			aSenderKeyStore
		);

		const message = new Uint8Array(Buffer.from('0a0b0c', 'hex'));

		const aCtext = await groupEncrypt(
			aAddress,
			distributionId,
			aSenderKeyStore,
			new Uint8Array(message)
		);

		const aUsmc = UnidentifiedSenderMessageContent.new(
			aCtext,
			senderCert,
			ContentHint.Implicit,
			new Uint8Array(Buffer.from([42]))
		);

		try {
			await sealedSenderMultiRecipientEncrypt(
				aUsmc,
				[bAddress],
				aliceStores.identity,
				aliceStores.session
			);
			assert(fail('should have thrown'));
		} catch (e) {
			isInstanceOf(e, Error);
		}
	});

	test('can have excluded recipients', async () => {
		const aliceStores = new TestStores();
		const bobStores = new TestStores();
		const aKeys = aliceStores.identity;
		const bKeys = bobStores.identity;

		const aSess = aliceStores.session;

		const bPreKey = PrivateKey.generate();
		const bSPreKey = PrivateKey.generate();

		const aIdentityKey = await aKeys.getIdentityKey();
		const bIdentityKey = await bKeys.getIdentityKey();

		const aE164 = '+14151111111';

		const aDeviceId = 1;
		const bDeviceId = 3;

		const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
		const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';
		const eUuid = '3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7';
		const mUuid = '5d088142-6fd7-4dbd-af00-fdda1b3ce988';

		const trustRoot = PrivateKey.generate();
		const serverKey = PrivateKey.generate();

		const serverCert = ServerCertificate.new(
			1,
			serverKey.getPublicKey(),
			trustRoot
		);

		const expires = 1605722925;
		const senderCert = SenderCertificate.new(
			aUuid,
			aE164,
			aDeviceId,
			aIdentityKey.getPublicKey(),
			expires,
			serverCert,
			serverKey
		);

		const bPreKeyId = 31337;
		const bSignedPreKeyId = 22;

		const bSignedPreKeySig = bIdentityKey.sign(
			bSPreKey.getPublicKey().serialized
		);

		const bAddress = ProtocolAddress.new(`${bUuid}.${bDeviceId}`);
		createAndProcessPreKeyBundle(
			0x2000,
			bAddress,
			bPreKeyId,
			bPreKey.getPublicKey(),
			bSignedPreKeyId,
			bSPreKey.getPublicKey(),
			bSignedPreKeySig,
			bIdentityKey.getPublicKey(),
			aSess,
			aKeys,
			null
		);

		const aAddress = ProtocolAddress.new(`${aUuid}.${aDeviceId}`);

		const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
		const aSenderKeyStore = aliceStores.sender;
		await SenderKeyDistributionMessage.create(
			aAddress,
			distributionId,
			aSenderKeyStore
		);

		const message = new Uint8Array(Buffer.from('0a0b0c', 'hex'));

		const aCtext = await groupEncrypt(
			aAddress,
			distributionId,
			aSenderKeyStore,
			new Uint8Array(message)
		);

		const aUsmc = UnidentifiedSenderMessageContent.new(
			aCtext,
			senderCert,
			ContentHint.Implicit,
			new Uint8Array(Buffer.from([42]))
		);

		const aSentMessage = await sealedSenderMultiRecipientEncrypt({
			content: aUsmc,
			recipients: [bAddress],
			excludedRecipients: [
				ServiceId.parseFromServiceIdString(eUuid),
				ServiceId.parseFromServiceIdString(mUuid),
			],
			identityStore: aKeys,
			sessionStore: aSess,
		});

		// Clients can't directly parse arbitrary SSv2 SentMessages, so just check that it contains
		// the excluded recipient service IDs followed by a device ID of 0.
		const hexEncodedSentMessage = Buffer.from(aSentMessage).toString('hex');

		const indexOfE = hexEncodedSentMessage.indexOf(
			Buffer.from(
				ServiceId.parseFromServiceIdString(eUuid).getServiceIdFixedWidthBinary()
			).toString('hex')
		);
		assert(!deepEqual(indexOfE, -1), '1');
		assert(deepEqual(aSentMessage[indexOfE / 2 + 17], 0), '2');

		const indexOfM = hexEncodedSentMessage.indexOf(
			Buffer.from(
				ServiceId.parseFromServiceIdString(mUuid).getServiceIdFixedWidthBinary()
			).toString('hex')
		);
		assert(!deepEqual(indexOfM, -1), '3');
		assert(deepEqual(aSentMessage[indexOfM / 2 + 17], 0), '4');
	});

	test('can encrypt/decrypt 1-1 messages', async () => {
		const aStore = new TestStores();
		const bStore = new TestStores();

		const aKeys = aStore.identity;
		const bKeys = bStore.identity;

		const aSess = aStore.session;
		const bSess = bStore.session;

		const bPreK = bStore.prekey;
		const bSPreK = bStore.signed;
		const kyberStore = bStore.kyber;

		const bPreKey = PrivateKey.generate();
		const bSPreKey = PrivateKey.generate();

		const aIdentityKey = await aKeys.getIdentityKey();
		const bIdentityKey = await bKeys.getIdentityKey();

		const aE164 = '+14151111111';
		const bE164 = '+19192222222';

		const aDeviceId = 1;
		const bDeviceId = 3;

		const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
		const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

		const trustRoot = PrivateKey.generate();
		const serverKey = PrivateKey.generate();

		const serverCert = ServerCertificate.new(
			1,
			serverKey.getPublicKey(),
			trustRoot
		);

		const expires = 1605722925;
		const senderCert = SenderCertificate.new(
			aUuid,
			aE164,
			aDeviceId,
			aIdentityKey.getPublicKey(),
			expires,
			serverCert,
			serverKey
		);

		const bRegistrationId = await bKeys.getLocalRegistrationId();
		const bPreKeyId = 31337;
		const bSignedPreKeyId = 22;

		const bSignedPreKeySig = bIdentityKey.sign(
			bSPreKey.getPublicKey().serialized
		);

		const bPreKeyRecord = PreKeyRecord.new(
			bPreKeyId,
			bPreKey.getPublicKey(),
			bPreKey
		);
		await bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

		const bSPreKeyRecord = SignedPreKeyRecord.new(
			bSignedPreKeyId,
			42, // timestamp
			bSPreKey.getPublicKey(),
			bSPreKey,
			bSignedPreKeySig
		);
		await bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

		const bAddress = new ProtocolAddress(bUuid, bDeviceId);
		await createAndProcessPreKeyBundle(
			bRegistrationId,
			bAddress,
			bPreKeyId,
			bPreKey.getPublicKey(),
			bSignedPreKeyId,
			bSPreKey.getPublicKey(),
			bSignedPreKeySig,
			bIdentityKey.getPublicKey(),
			aSess,
			aKeys,
			null
		);

		const aPlaintext = Buffer.from('hi there', 'utf8');

		const aCiphertext = await sealedSenderEncryptMessage(
			aPlaintext,
			bAddress,
			senderCert,
			aSess,
			aKeys
		);

		const kyberKeyIds = kyberStore._getAllKyberKeyIds();
		const bPlaintext = await sealedSenderDecryptMessage(
			aCiphertext,
			trustRoot.getPublicKey(),
			43, // timestamp,
			bE164,
			bUuid,
			bDeviceId,
			bSess,
			bKeys,
			bPreK,
			bSPreK,
			kyberStore,
			kyberKeyIds
		);

		assert(bPlaintext != null);
		deepEqual(bPlaintext.message(), aPlaintext);
		deepEqual(bPlaintext.senderE164(), aE164);
		deepEqual(bPlaintext.senderUuid(), aUuid);
		deepEqual(bPlaintext.senderAci()?.getServiceIdString(), aUuid);
		deepEqual(bPlaintext.deviceId(), aDeviceId);

		const innerMessage = await signalEncrypt(
			aPlaintext,
			bAddress,
			aSess,
			aKeys
		);

		for (const hint of [
			200,
			ContentHint.Default,
			ContentHint.Resendable,
			ContentHint.Implicit,
		]) {
			const content = UnidentifiedSenderMessageContent.new(
				innerMessage,
				senderCert,
				hint,
				null
			);
			const ciphertext = await sealedSenderEncrypt(content, bAddress, aKeys);
			const decryptedContent = await sealedSenderDecryptToUsmc(
				ciphertext,
				bKeys
			);
			deepEqual(decryptedContent.contentHint(), hint);
		}
	});

	test('rejects self-sent messages', async () => {
		const aStore = new TestStores();
		const bStore = new TestStores();
		const sharedKeys = aStore.identity;

		const aSess = aStore.session;
		const bSess = bStore.session;

		const bPreK = bStore.prekey;
		const bSPreK = bStore.signed;
		const kyberStore = bStore.kyber;

		const bPreKey = PrivateKey.generate();
		const bSPreKey = PrivateKey.generate();

		const sharedIdentityKey = await sharedKeys.getIdentityKey();

		const aE164 = '+14151111111';

		const sharedDeviceId = 1;

		const sharedUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';

		const trustRoot = PrivateKey.generate();
		const serverKey = PrivateKey.generate();

		const serverCert = ServerCertificate.new(
			1,
			serverKey.getPublicKey(),
			trustRoot
		);

		const expires = 1605722925;
		const senderCert = SenderCertificate.new(
			sharedUuid,
			aE164,
			sharedDeviceId,
			sharedIdentityKey.getPublicKey(),
			expires,
			serverCert,
			serverKey
		);

		const sharedRegistrationId = await sharedKeys.getLocalRegistrationId();
		const bPreKeyId = 31337;
		const bSignedPreKeyId = 22;

		const bSignedPreKeySig = sharedIdentityKey.sign(
			bSPreKey.getPublicKey().serialized
		);

		const bPreKeyRecord = PreKeyRecord.new(
			bPreKeyId,
			bPreKey.getPublicKey(),
			bPreKey
		);
		await bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

		const bSPreKeyRecord = SignedPreKeyRecord.new(
			bSignedPreKeyId,
			42, // timestamp
			bSPreKey.getPublicKey(),
			bSPreKey,
			bSignedPreKeySig
		);
		await bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

		const sharedAddress = new ProtocolAddress(sharedUuid, sharedDeviceId);
		await createAndProcessPreKeyBundle(
			sharedRegistrationId,
			sharedAddress,
			bPreKeyId,
			bPreKey.getPublicKey(),
			bSignedPreKeyId,
			bSPreKey.getPublicKey(),
			bSignedPreKeySig,
			sharedIdentityKey.getPublicKey(),
			aSess,
			sharedKeys,
			null
		);

		const aPlaintext = Buffer.from('hi there', 'utf8');

		const aCiphertext = await sealedSenderEncryptMessage(
			aPlaintext,
			sharedAddress,
			senderCert,
			aSess,
			sharedKeys
		);

		try {
			await sealedSenderDecryptMessage(
				aCiphertext,
				trustRoot.getPublicKey(),
				43, // timestamp,
				null,
				sharedUuid,
				sharedDeviceId,
				bSess,
				sharedKeys,
				bPreK,
				bSPreK,
				kyberStore,
				kyberStore._getAllKyberKeyIds()
			);
			fail('should have thrown');
		} catch (e) {
			assert(e instanceof Error);
			assert(e instanceof LibSignalErrorBase);
			const err = e as LibSignalError;
			deepEqual(err.name, 'SealedSenderSelfSend');
			deepEqual(err.code, ErrorCode.SealedSenderSelfSend);
			deepEqual(err.operation, 'SealedSender_DecryptMessage'); // the Rust entry point
			assert(err.stack !== undefined); // Make sure we're still getting the benefits of Error.
		}
	});
};
