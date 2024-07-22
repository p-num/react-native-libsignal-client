import { fromByteArray, toByteArray } from "react-native-quick-base64";
import {
  IdentityKeyPair,
  IdentityKeyStore,
  KyberPreKeyRecord,
  KyberPreKeyStore,
  PreKeyStore,
  PublicKey,
  SessionRecord,
  SessionStore,
  SignedPreKeyRecord,
  SignedPreKeyStore,
} from ".";
import { ProtocolAddress } from "./Address";
import { PreKeyRecord } from "./index";

export type KeyObject = { [protocolAddress: string]: string };

export async function updateSessionStoreFromObject(
  sessionStore: SessionStore,
  updatedSessionStoreState: KeyObject
) {
  for (const key in updatedSessionStoreState) {
    const protoAddress = ProtocolAddress.new(key);
    await sessionStore.saveSession(
      protoAddress,
      SessionRecord._fromSerialized(toByteArray(updatedSessionStoreState[key]))
    );
  }
}

export async function updatedPrekeyStoreFromObject(
  preKeyStore: PreKeyStore,
  preKeyStoreState: KeyObject
) {
  for (const key in preKeyStoreState) {
    await preKeyStore.savePreKey(
      Number(key),
      PreKeyRecord._fromSerialized(toByteArray(preKeyStoreState[key]))
    );
  }
}

export async function updateSignedPrekeyStoreFromObject(
  signedPreKeyStore: SignedPreKeyStore,
  signedPreKeyStoreState: KeyObject
) {
  for (const key in signedPreKeyStoreState) {
    await signedPreKeyStore.saveSignedPreKey(
      Number(key),
      SignedPreKeyRecord._fromSerialized(
        toByteArray(signedPreKeyStoreState[key])
      )
    );
  }
}

export async function updateKyberPrekeyStoreFromObject(
  kyberPreKeyStore: KyberPreKeyStore,
  kyberPreKeyStoreState: KeyObject
) {
  for (const key in kyberPreKeyStoreState) {
    await kyberPreKeyStore.saveKyberPreKey(
      Number(key),
      KyberPreKeyRecord._fromSerialized(toByteArray(kyberPreKeyStoreState[key]))
    );
  }
}

export async function updateIdentityStoreFromObject(
  identityStore: IdentityKeyStore,
  identityStoreState: KeyObject
) {
  for (const key in identityStoreState) {
    const protoAddress = ProtocolAddress.new(key);
    const d = PublicKey._fromSerialized(toByteArray(identityStoreState[key]));
    await identityStore.saveIdentity(protoAddress, d);
  }
}

export async function getSessionStoreObject(
  sessionStore: SessionStore,
  address: ProtocolAddress
): Promise<KeyObject> {
  const sessionStoreState: KeyObject = {};
  const sessionRecords = await sessionStore.getExistingSessions([address]);
  for (const record of sessionRecords) {
    sessionStoreState[address.toString()] = fromByteArray(record.serialized);
  }
  return sessionStoreState;
}

export async function getIdentityStoreObject(
  identityStore: IdentityKeyStore,
  address: ProtocolAddress
): Promise<[identityKey: string, [ownerKeyPair: string, regId: number]]> {
  const privateKey = await identityStore.getIdentityKey();
  const publicKey = privateKey.getPublicKey();
  const pair = new IdentityKeyPair(publicKey, privateKey);
  const regId = await identityStore.getLocalRegistrationId();
  const pubKey = await identityStore.getIdentity(address);
  if (!pubKey) {
    throw new Error("No Identity Key associated with the address!");
  }
  return [
    fromByteArray(pubKey.serialized),
    [fromByteArray(pair.serialize()), regId],
  ];
}

export async function getIdentityStoreInitializer(
  identityStore: IdentityKeyStore
): Promise<[ownerKeyPair: string, regId: number]> {
  const privateKey = await identityStore.getIdentityKey();
  const publicKey = privateKey.getPublicKey();
  const pair = new IdentityKeyPair(publicKey, privateKey);
  const regId = await identityStore.getLocalRegistrationId();
  return [fromByteArray(pair.serialize()), regId];
}

export async function getSignedPrekeyStoreState(
  signedPreKeyStore: SignedPreKeyStore,
  signedPrekeyId: number
): Promise<KeyObject> {
  const signedPreKey = await signedPreKeyStore.getSignedPreKey(signedPrekeyId);
  return {
    [signedPrekeyId.toString()]: fromByteArray(signedPreKey.serialized),
  };
}

export async function getKyberPrekeyStoreState(
  kyberPreKeyStore: KyberPreKeyStore,
  kyberPrekeyIds: number[]
): Promise<KeyObject> {
  const keyObject: KeyObject = {};
  for (const kyberPrekeyId of kyberPrekeyIds) {
    const kyberPreKey = await kyberPreKeyStore.getKyberPreKey(kyberPrekeyId);
    keyObject[kyberPrekeyId.toString()] = fromByteArray(kyberPreKey.serialized);
  }

  return keyObject;
}

export async function getPrekeyStoreState(
  preKeyStore: PreKeyStore,
  preKeyId: number
): Promise<KeyObject> {
  const preKey = await preKeyStore.getPreKey(preKeyId);
  return {
    [preKeyId.toString()]: fromByteArray(preKey.serialized),
  };
}
