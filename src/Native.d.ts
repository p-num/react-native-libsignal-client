type Uuid = Uint8Array;

type MessageBackupValidationOutcome = {
  errorMessage: string | null;
  unknownFieldMessages: Array<string>;
};

export abstract class IdentityKeyStore {
	_getIdentityKey(): Promise<PrivateKey>;
	_getLocalRegistrationId(): Promise<number>;
	_saveIdentity(name: ProtocolAddress, key: Uint8Array): Promise<boolean>;
	_isTrustedIdentity(
		name: string,
		key: Uint8Array,
		sending: boolean
	): Promise<boolean>;
	_getIdentity(name: ProtocolAddress): Promise<Uint8Array | null>;
}

export abstract class SessionStore {
	_saveSession(addr: string, record: Uint8Array): Promise<void>;
	_getSession(addr: string): Promise<Uint8Array | null>;
}

export abstract class PreKeyStore {
	_savePreKey(preKeyId: number, record: Uint8Array): Promise<void>;
	_getPreKey(preKeyId: number): Promise<Uint8Array>;
	_removePreKey(preKeyId: number): Promise<void>;
}

export abstract class SignedPreKeyStore {
	_saveSignedPreKey(
		signedPreKeyId: number,
		record: Uint8Array
	): Promise<void>;
	_getSignedPreKey(signedPreKeyId: number): Promise<Uint8Array>;
}

export abstract class KyberPreKeyStore {
	_saveKyberPreKey(
		kyberPreKeyId: number,
		record: Uint8Array
	): Promise<void>;
	_getKyberPreKey(kyberPreKeyId: number): Promise<Uint8Array>;
	_markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void>;
}

export abstract class SenderKeyStore {
	_saveSenderKey(
		sender: string,
		distributionId: Uuid,
		record: Uint8Array
	): Promise<void>;
	_getSenderKey(
		sender: string,
		distributionId: Uuid
	): Promise<Uint8Array | null>;
}