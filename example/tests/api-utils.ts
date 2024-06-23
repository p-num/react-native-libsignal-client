import * as ReactNativeLibsignalClient from 'react-native-libsignal-client';
import { ProtocolAddress } from 'react-native-libsignal-client/Address';
import { TestStores } from './mockStores';
import { chance } from './utils';

async function makePQXDHBundleAndProcess(
	address: ProtocolAddress,
	stores: TestStores
) {
	const identityKey = await stores.identity.getIdentityKey();
	const prekeyId = chance.natural({ max: 10000 });
	const prekey = ReactNativeLibsignalClient.PrivateKey.generate();
	const signedPrekeyId = chance.natural({ max: 10000 });
	const signedPrekey = ReactNativeLibsignalClient.PrivateKey.generate();
	const signedPrekeySignature = identityKey.sign(
		signedPrekey.getPublicKey().serialized
	);
	const kyberPrekeyId = chance.natural({ max: 10000 });

	await stores.prekey.savePreKey(
		prekeyId,
		ReactNativeLibsignalClient.PreKeyRecord.new(
			prekeyId,
			prekey.getPublicKey(),
			prekey
		)
	);
	await stores.signed.saveSignedPreKey(
		signedPrekeyId,
		ReactNativeLibsignalClient.SignedPreKeyRecord.new(
			signedPrekeyId,
			chance.timestamp(),
			signedPrekey.getPublicKey(),
			signedPrekey,
			signedPrekeySignature
		)
	);

	const rec = ReactNativeLibsignalClient.KyberPreKeyRecord.new(
		kyberPrekeyId,
		chance.timestamp(),
		identityKey.serialized
	);

	await stores.kyber.saveKyberPreKey(kyberPrekeyId, rec);

	 await ReactNativeLibsignalClient.createAndProcessPreKeyBundle(
		await stores.identity.getLocalRegistrationId(),
		address,
		prekeyId,
		prekey.getPublicKey(),
		signedPrekeyId,
		signedPrekey.getPublicKey(),
		signedPrekeySignature,
		identityKey.getPublicKey(),
		stores.session,
		stores.identity,
		{
			kyber_prekey_id: kyberPrekeyId,
			kyber_prekey: rec.publicKey(),
			kyber_prekey_signature: rec.signature(),
		}
	);
}

export const sessionVersionTestCases = [
	{ suffix: 'v3', makeAndProcessBundle: makeX3DHBundleAndProcess, expectedVersion: 3 },
	{ suffix: 'v4', makeAndProcessBundle: makePQXDHBundleAndProcess, expectedVersion: 4 },
];

//TODo: uncomment after making the kyber args optional
async function makeX3DHBundleAndProcess(
	address: ProtocolAddress,
	stores: TestStores
) {
	const identityKey = await stores.identity.getIdentityKey();
	const prekeyId = chance.natural({ max: 10000 });
	const prekey = ReactNativeLibsignalClient.PrivateKey.generate();
	const signedPrekeyId = chance.natural({ max: 10000 });
	const signedPrekey = ReactNativeLibsignalClient.PrivateKey.generate();
	const signedPrekeySignature = identityKey.sign(
		signedPrekey.getPublicKey().serialized
	);

	await stores.prekey.savePreKey(
		prekeyId,
		ReactNativeLibsignalClient.PreKeyRecord.new(
			prekeyId,
			prekey.getPublicKey(),
			prekey
		)
	);

	await stores.signed.saveSignedPreKey(
		signedPrekeyId,
		ReactNativeLibsignalClient.SignedPreKeyRecord.new(
			signedPrekeyId,
			chance.timestamp(),
			signedPrekey.getPublicKey(),
			signedPrekey,
			signedPrekeySignature
		)
	);

	await ReactNativeLibsignalClient.createAndProcessPreKeyBundle(
		await stores.identity.getLocalRegistrationId(),
		address,
		prekeyId,
		prekey.getPublicKey(),
		signedPrekeyId,
		signedPrekey.getPublicKey(),
		signedPrekeySignature,
		identityKey.getPublicKey(),
		stores.session,
		stores.identity,
		null
	);
}
