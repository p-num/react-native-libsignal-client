import 'react-native-get-random-values';
import { fromByteArray } from 'react-native-quick-base64';
import * as uuid from 'uuid';
import { ProtocolAddress } from './Address';
import * as Native from './Native.d';
import { Direction } from './ReactNativeLibsignalClient.types';
import ReactNativeLibsignalClientModule from './ReactNativeLibsignalClientModule';
import { getIdentityStoreInitializer, updateIdentityStoreFromObject, updateSessionStoreFromObject } from './stores';

export class PrivateKey {
	readonly serialized: Uint8Array

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static generate() : PrivateKey {
		return new PrivateKey(ReactNativeLibsignalClientModule.generatePrivateKey());
	}

	sign(msg: Uint8Array): Uint8Array {
		return ReactNativeLibsignalClientModule.privateKeySign(this.serialized, msg);
	}

	agree(other_key: PublicKey): Uint8Array {
		return ReactNativeLibsignalClientModule.privateKeyAgree(
			this.serialized,
			other_key.serialized
		);
	}

	getPublicKey(): PublicKey {
		return PublicKey._fromSerialized(ReactNativeLibsignalClientModule.privateKeyGetPublicKey(this.serialized))
	}

	static _fromSerialized(
		serialized: Uint8Array
	): PrivateKey {
		return new PrivateKey(serialized);
	}
}

export class PublicKey {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	/// Returns -1, 0, or 1
	compare(other: PublicKey): number {
		return ReactNativeLibsignalClientModule.publicKeyCompare(
			this.serialized,
			other.serialized
		);
	}

	getPublicKeyBytes(): Uint8Array {
		return ReactNativeLibsignalClientModule.publicKeyGetPublicKeyBytes(
			this.serialized
		);
	}

	verify(msg: Uint8Array, sig: Uint8Array): boolean {
		return ReactNativeLibsignalClientModule.publicKeyVerify(
			this.serialized,
			msg,
			sig
		);
	}

	verifyAlternateIdentity(other: PublicKey, signature: Uint8Array): boolean {
		return ReactNativeLibsignalClientModule.identityKeyVerifyAlternateIdentity(
			this.serialized,
			other.serialized,
			signature
		);
	}

	static _fromSerialized(
		serialized: Uint8Array
	): PublicKey {
		return new PublicKey(serialized);
	}
}


export class IdentityKeyPair {
	readonly publicKey: PublicKey;
	readonly privateKey: PrivateKey;

	constructor(publicKey: PublicKey, privateKey: PrivateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	static generate(): IdentityKeyPair {
		const [privateKey, publicKey] = ReactNativeLibsignalClientModule.generateIdentityKeyPair();
		return new IdentityKeyPair(PublicKey._fromSerialized(publicKey), PrivateKey._fromSerialized(privateKey));
	}

	signAlternateIdentity(other: PublicKey): Uint8Array {
		return ReactNativeLibsignalClientModule.identityKeyPairSignAlternateIdentity(
			this.publicKey.serialized,
			this.privateKey.serialized,
			other.serialized
		);
	}

	serialize(): Uint8Array {
		return ReactNativeLibsignalClientModule.identityKeyPairSerialize(
			this.publicKey.serialized,
			this.privateKey.serialized
		);
	}
}

export class KEMKeyPair {
	readonly publicKey: KEMPublicKey;
	readonly secretKey: KEMSecretKey;

	private constructor(publicKey :KEMPublicKey, secretKey: KEMSecretKey) {
    this.secretKey = secretKey;
    this.publicKey = publicKey;
  }

	static generate(): KEMKeyPair {
    const [prv, pub] = ReactNativeLibsignalClientModule.generateKyberKeyPair()
		return new KEMKeyPair(prv, pub);
	}

	getPublicKey(): KEMPublicKey {
		return this.publicKey;
	}

	getSecretKey(): KEMSecretKey {
		return this.secretKey
	}
}

export class KEMPublicKey {
	readonly serialized: Uint8Array;

	private constructor(handle: Uint8Array) {
		this.serialized = handle;
	}

	static _fromSerialized(serialized: Uint8Array): KEMPublicKey {
		return new KEMPublicKey(serialized);
	}
}

export class KEMSecretKey {
	readonly serialized: Uint8Array;

	private constructor(handle: Uint8Array) {
		this.serialized = handle;
	}

	static _fromSerialized(serialized: Uint8Array): KEMSecretKey {
		return new KEMSecretKey(serialized);
	}
}


export class KyberPreKeyRecord {
	readonly serialized: Uint8Array

	private constructor(handle: Uint8Array) {
		this.serialized = handle;
	}

	static new(
		id: number,
		timestamp: number,
		privateIdentityKey: Uint8Array
	): KyberPreKeyRecord {
		return new KyberPreKeyRecord(ReactNativeLibsignalClientModule.generateKyberRecord(
      id,
      timestamp,
      privateIdentityKey
    ))
	}

	id(): number {
		return ReactNativeLibsignalClientModule.kyberPreKeyRecordGetId(
			this.serialized
		);
	}

	publicKey(): KEMPublicKey {
		return KEMPublicKey._fromSerialized(
			ReactNativeLibsignalClientModule.kyberPreKeyRecordGetPublicKey(
				this.serialized
			)
		);
	}

	secretKey(): KEMSecretKey {
		return KEMSecretKey._fromSerialized(
			ReactNativeLibsignalClientModule.kyberPreKeyRecordGetSecretKey(
				this.serialized
			)
		);
	}

	signature(): Uint8Array {
		return ReactNativeLibsignalClientModule.kyberPreKeyRecordGetSignature(
			this.serialized
		);
	}

	timestamp(): number {
		return ReactNativeLibsignalClientModule.kyberPreKeyRecordGetTimestamp(
			this.serialized
		);
	}

	static _fromSerialized(serialized: Uint8Array): KyberPreKeyRecord {
		return new KyberPreKeyRecord(serialized);
	}
}


export class SignedPreKeyRecord {
	readonly serialized: Uint8Array;

	private constructor(handle: Uint8Array) {
		this.serialized = handle;
	}

	static new(
		id: number,
		timestamp: number,
		pubKey: PublicKey,
		privKey: PrivateKey,
		signature: Uint8Array
	): SignedPreKeyRecord {
		return new SignedPreKeyRecord(
			ReactNativeLibsignalClientModule.signedPreKeyRecordNew(
				id,
				timestamp,
				pubKey.serialized,
				privKey.serialized,
				signature
			)
		);
	}

	id(): number {
		return ReactNativeLibsignalClientModule.signedPreKeyRecordGetId(
			this.serialized
		);
	}

	privateKey(): PrivateKey {
		return PrivateKey._fromSerialized(
			ReactNativeLibsignalClientModule.signedPreKeyRecordGetPrivateKey(
				this.serialized
			)
		);
	}

	publicKey(): PublicKey {
		return PublicKey._fromSerialized(
			ReactNativeLibsignalClientModule.signedPreKeyRecordGetPublicKey(
				this.serialized
			)
		);
	}

	signature(): Uint8Array {
		return ReactNativeLibsignalClientModule.signedPreKeyRecordGetSignature(
			this.serialized
		);
	}

	timestamp(): number {
		return ReactNativeLibsignalClientModule.signedPreKeyRecordGetTimestamp(
			this.serialized
		);
	}

	static _fromSerialized(serialized: Uint8Array): SignedPreKeyRecord {
		return new SignedPreKeyRecord(serialized);
	}
}

export class PreKeyRecord {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord {
		return new PreKeyRecord(
			ReactNativeLibsignalClientModule.preKeyRecordNew(
				id,
				pubKey.serialized,
				privKey.serialized
			)
		);
	}

	id(): number {
		return ReactNativeLibsignalClientModule.preKeyRecordGetId(this.serialized);
	}

	privateKey(): PrivateKey {
		return PrivateKey._fromSerialized(
			ReactNativeLibsignalClientModule.preKeyRecordGetPrivateKey(this.serialized)
		);
	}

	publicKey(): PublicKey {
		return PublicKey._fromSerialized(
			ReactNativeLibsignalClientModule.preKeyRecordGetPublicKey(this.serialized)
		);
	}
	
	static _fromSerialized(serialized: Uint8Array): PreKeyRecord {
		return new PreKeyRecord(serialized);
	}
}

export class SenderKeyRecord {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static _fromSerialized(serialized: Uint8Array): SenderKeyRecord {
		return new SenderKeyRecord(serialized);
	}
}


export class SessionRecord {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	archiveCurrentState(): void {
		ReactNativeLibsignalClientModule.sessionRecordArchiveCurrentState(
			this.serialized
		);
	}

	localRegistrationId(): number {
		return ReactNativeLibsignalClientModule.sessionRecordGetLocalRegistrationId(
			this.serialized
		);
	}

	remoteRegistrationId(): number {
		return ReactNativeLibsignalClientModule.sessionRecordGetRemoteRegistrationId(
			this.serialized
		);
	}

	/**
	 * Returns whether the current session can be used to send messages.
	 *
	 * If there is no current session, returns false.
	 */
	hasCurrentState(now: Date = new Date()): boolean {
		return ReactNativeLibsignalClientModule.sessionRecordHasUsableSenderChain(
			this.serialized,
			now.getTime()
		);
	}

	currentRatchetKeyMatches(key: PublicKey): boolean {
		return ReactNativeLibsignalClientModule.sessionRecordCurrentRatchetKeyMatches(
			this.serialized,
			key.serialized
		);
	}

	static _fromSerialized(serialized: Uint8Array): SessionRecord {
		return new SessionRecord(serialized);
	}
}


export abstract class SessionStore implements Native.SessionStore {
	async _saveSession(
		address: string,
		record: Uint8Array
	): Promise<void> {
		return this.saveSession(
			ProtocolAddress.new(address),
			SessionRecord._fromSerialized(record)
		);
	}
	async _getSession(
		address: string
	): Promise<Uint8Array | null> {
		const session = await this.getSession(ProtocolAddress.new(address));
		if (session == null) {
			return null;
		}
		return session.serialized;
	}

	abstract saveSession(
		name: ProtocolAddress,
		record: SessionRecord
	): Promise<void>;
	abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>;
	abstract getExistingSessions(
		addresses: ProtocolAddress[]
	): Promise<SessionRecord[]>;
}

export abstract class IdentityKeyStore implements Native.IdentityKeyStore {
	async _getIdentityKey(): Promise<Uint8Array> {
		const key = await this.getIdentityKey();
		return key.serialized;
	}

	async _getLocalRegistrationId(): Promise<number> {
		return this.getLocalRegistrationId();
	}
	async _saveIdentity(
		address: string,
		key: Uint8Array
	): Promise<boolean> {
		return this.saveIdentity(
			ProtocolAddress.new(address),
			PublicKey._fromSerialized(key)
		);
	}
	async _isTrustedIdentity(
		address: string,
		key: Uint8Array,
		sending: boolean
	): Promise<boolean> {
		const direction = sending ? Direction.Sending : Direction.Receiving;

		return this.isTrustedIdentity(
			ProtocolAddress.new(address),
			PublicKey._fromSerialized(key),
			direction
		);
	}
	async _getIdentity(
		name: string
	): Promise<Uint8Array | null> {
		const key = await this.getIdentity(ProtocolAddress.new(name));
		if (key == null) {
			return Promise.resolve(null);
		}
		return key.serialized;
	}

	abstract getIdentityKey(): Promise<PrivateKey>;
	abstract getLocalRegistrationId(): Promise<number>;
	abstract saveIdentity(
		name: ProtocolAddress,
		key: PublicKey
	): Promise<boolean>;
	abstract isTrustedIdentity(
		name: ProtocolAddress,
		key: PublicKey,
		direction: Direction
	): Promise<boolean>;
	abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}

export abstract class PreKeyStore implements Native.PreKeyStore {
	async _savePreKey(id: number, record: Uint8Array): Promise<void> {
		return this.savePreKey(id, PreKeyRecord._fromSerialized(record));
	}
	async _getPreKey(id: number): Promise<Uint8Array> {
		const pk = await this.getPreKey(id);
		return pk.serialized;
	}
	async _removePreKey(id: number): Promise<void> {
		return this.removePreKey(id);
	}

	abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>;
	abstract getPreKey(id: number): Promise<PreKeyRecord>;
	abstract removePreKey(id: number): Promise<void>;
}

export abstract class SignedPreKeyStore implements Native.SignedPreKeyStore {
	async _saveSignedPreKey(
		id: number,
		record: Uint8Array
	): Promise<void> {
		return this.saveSignedPreKey(
			id,
			SignedPreKeyRecord._fromSerialized(record)
		);
	}
	async _getSignedPreKey(id: number): Promise<Uint8Array> {
		const pk = await this.getSignedPreKey(id);
		return pk.serialized;
	}

	abstract saveSignedPreKey(
		id: number,
		record: SignedPreKeyRecord
	): Promise<void>;
	abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>;
}

export abstract class KyberPreKeyStore implements Native.KyberPreKeyStore {
	async _saveKyberPreKey(
		kyberPreKeyId: number,
		record: Uint8Array
	): Promise<void> {
		return this.saveKyberPreKey(
			kyberPreKeyId,
			KyberPreKeyRecord._fromSerialized(record)
		);
	}
	async _getKyberPreKey(
		kyberPreKeyId: number
	): Promise<Uint8Array> {
		const prekey = await this.getKyberPreKey(kyberPreKeyId);
		return prekey.serialized;
	}

	async _markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void> {
		return this.markKyberPreKeyUsed(kyberPreKeyId);
	}

	abstract saveKyberPreKey(
		kyberPreKeyId: number,
		record: KyberPreKeyRecord
	): Promise<void>;
	abstract getKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord>;
	abstract markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void>;
}

export abstract class SenderKeyStore implements Native.SenderKeyStore {
	async _saveSenderKey(
		sender: string,
		distributionId: Native.Uuid,
		record: Uint8Array
	): Promise<void> {
		return this.saveSenderKey(
			ProtocolAddress.new(sender),
			uuid.stringify(distributionId),
			SenderKeyRecord._fromSerialized(record)
		);
	}
	async _getSenderKey(
		sender: string,
		distributionId: Native.Uuid
	): Promise<Uint8Array | null> {
		const skr = await this.getSenderKey(
			ProtocolAddress.new(sender),
			uuid.stringify(distributionId)
		);
		if (skr == null) {
			return null;
		}
		return skr.serialized;
	}

	abstract saveSenderKey(
		sender: ProtocolAddress,
		distributionId: string,
		record: SenderKeyRecord
	): Promise<void>;
	abstract getSenderKey(
		sender: ProtocolAddress,
		distributionId: string
	): Promise<SenderKeyRecord | null>;
}

export async function createAndProcessPreKeyBundle(
	registration_id: number,
	address: ProtocolAddress,
	prekey_id: number,
	prekey: PublicKey,
	signed_prekey_id: number,
	signed_prekey: PublicKey,
	signed_prekey_signature: Uint8Array,
	identity_key: PublicKey,
	sessionStore: SessionStore,
	identityStore: IdentityKeyStore,
	kyberData: {
		kyber_prekey_id: number;
		kyber_prekey: KEMPublicKey;
		kyber_prekey_signature: Uint8Array;
	} | null,

) {
	const identityStoreInitializer =
	await getIdentityStoreInitializer(identityStore);
	const [updatedSessionStoreState, updatedIdentityStoreState] = ReactNativeLibsignalClientModule.createAndProcessPreKeyBundle(
		[address.toString(),
		registration_id],
		[prekey_id,
		fromByteArray(prekey.serialized)],
		[signed_prekey_id,
		fromByteArray(signed_prekey.serialized)],
		fromByteArray(signed_prekey_signature),
		fromByteArray(identity_key.serialized),
		identityStoreInitializer,
		kyberData
		? [
				kyberData.kyber_prekey_id,
				fromByteArray(kyberData.kyber_prekey.serialized)
			]
		: null,
		kyberData ? fromByteArray(kyberData.kyber_prekey_signature) : null
	);
	await updateSessionStoreFromObject(sessionStore, updatedSessionStoreState);
	await updateIdentityStoreFromObject(identityStore, updatedIdentityStoreState);
}


export { Direction };
