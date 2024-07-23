import * as ReactNativeLibsignalClient from "../../src";
import { ProtocolAddress } from "../../src/Address";
import { TestStores } from "./mockStores";
import { chance } from "./utils";
import { Buffer } from "@craftzdog/react-native-buffer";

async function makePQXDHBundleAndProcess(
  address: ProtocolAddress,
  remoteStores: TestStores,
  senderSessionStore: ReactNativeLibsignalClient.SessionStore,
  senderIdentityStore: ReactNativeLibsignalClient.IdentityKeyStore
) {
  const identityKey = await remoteStores.identity.getIdentityKey();
  const prekeyId = chance.natural({ max: 10000 });
  const prekey = ReactNativeLibsignalClient.PrivateKey.generate();
  const signedPrekeyId = chance.natural({ max: 10000 });
  const signedPrekey = ReactNativeLibsignalClient.PrivateKey.generate();
  const signedPrekeySignature = identityKey.sign(
    signedPrekey.getPublicKey().serialized
  );
  const kyberPrekeyId = chance.natural({ max: 10000 });

  await remoteStores.prekey.savePreKey(
    prekeyId,
    ReactNativeLibsignalClient.PreKeyRecord.new(
      prekeyId,
      prekey.getPublicKey(),
      prekey
    )
  );
  await remoteStores.signed.saveSignedPreKey(
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

  await remoteStores.kyber.saveKyberPreKey(kyberPrekeyId, rec);

  await ReactNativeLibsignalClient.createAndProcessPreKeyBundle(
    await remoteStores.identity.getLocalRegistrationId(),
    address,
    prekeyId,
    prekey.getPublicKey(),
    signedPrekeyId,
    signedPrekey.getPublicKey(),
    signedPrekeySignature,
    identityKey.getPublicKey(),
    senderSessionStore,
    senderIdentityStore,
    {
      kyber_prekey_id: kyberPrekeyId,
      kyber_prekey: rec.publicKey(),
      kyber_prekey_signature: rec.signature(),
    }
  );
}

export function isUint32(number: number): boolean {
  return Number.isInteger(number) && number >= 0 && number <= 0xffffffff;
}

export const sessionVersionTestCases = [
  {
    suffix: "v3",
    makeAndProcessBundle: makeX3DHBundleAndProcess,
    expectedVersion: 3,
  },
  {
    suffix: "v4",
    makeAndProcessBundle: makePQXDHBundleAndProcess,
    expectedVersion: 4,
  },
];

//TODo: uncomment after making the kyber args optional
async function makeX3DHBundleAndProcess(
  address: ProtocolAddress,
  remoteStores: TestStores,
  senderSessionStore: ReactNativeLibsignalClient.SessionStore,
  senderIdentityStore: ReactNativeLibsignalClient.IdentityKeyStore
) {
  const identityKey = await remoteStores.identity.getIdentityKey();
  const prekeyId = chance.natural({ max: 10000 });
  const prekey = ReactNativeLibsignalClient.PrivateKey.generate();
  const signedPrekeyId = chance.natural({ max: 10000 });
  const signedPrekey = ReactNativeLibsignalClient.PrivateKey.generate();
  const signedPrekeySignature = identityKey.sign(
    signedPrekey.getPublicKey().serialized
  );

  await remoteStores.prekey.savePreKey(
    prekeyId,
    ReactNativeLibsignalClient.PreKeyRecord.new(
      prekeyId,
      prekey.getPublicKey(),
      prekey
    )
  );

  await remoteStores.signed.saveSignedPreKey(
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
    await remoteStores.identity.getLocalRegistrationId(),
    address,
    prekeyId,
    prekey.getPublicKey(),
    signedPrekeyId,
    signedPrekey.getPublicKey(),
    signedPrekeySignature,
    identityKey.getPublicKey(),
    senderSessionStore,
    senderIdentityStore,
    null
  );
}
