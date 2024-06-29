import 'react-native-get-random-values';
import { fromByteArray } from 'react-native-quick-base64';
import * as uuid from 'uuid';
import { Aci, ProtocolAddress, ServiceId } from './Address';
import * as Native from './Native.d';
import { CiphertextMessageType, ContentHint, Direction } from './ReactNativeLibsignalClient.types';
import ReactNativeLibsignalClientModule from './ReactNativeLibsignalClientModule';
import { getIdentityStoreInitializer, getIdentityStoreObject, getKyberPrekeyStoreState, getPrekeyStoreState, getSessionStoreObject, getSignedPrekeyStoreState, KeyObject, updatedPrekeyStoreFromObject, updateIdentityStoreFromObject, updateSessionStoreFromObject, updateSignedPrekeyStoreFromObject } from './stores';
export * from './Address';
export * from './Errors';

export class HKDF {
	/**
	 * @deprecated Use the top-level 'hkdf' function for standard HKDF behavior
	 */
	static new(version: number): HKDF {
		if (version !== 3) {
			throw new Error('HKDF versions other than 3 are no longer supported');
		}
		return new HKDF();
	}

	deriveSecrets(
		outputLength: number,
		keyMaterial: Uint8Array,
		label: Uint8Array,
		salt: Uint8Array | null
	): Uint8Array {
		return hkdf(outputLength, keyMaterial, label, salt);
	}
}

export function hkdf(
	outputLength: number,
	keyMaterial: Uint8Array,
	label: Uint8Array,
	salt: Uint8Array | null
): Uint8Array {
	return ReactNativeLibsignalClientModule.hkdfDeriveSecrets(
		outputLength,
		keyMaterial,
		label,
		salt
	);
}

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

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static _fromSerialized(serialized: Uint8Array): KEMPublicKey {
		return new KEMPublicKey(serialized);
	}
}

export class KEMSecretKey {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static _fromSerialized(serialized: Uint8Array): KEMSecretKey {
		return new KEMSecretKey(serialized);
	}
}


export class KyberPreKeyRecord {
	readonly serialized: Uint8Array

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
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

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
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

export class SenderCertificate {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static _fromSerialized(
		serialized: Uint8Array
	): SenderCertificate {
		return new SenderCertificate(serialized);
	}

  // this is not used anywhere and needs use of native method so is ignored
	// static new(
	// 	senderUuid: string | Aci,
	// 	senderE164: string | null,
	// 	senderDeviceId: number,
	// 	senderKey: PublicKey,
	// 	expiration: number,
	// 	signerCert: ServerCertificate,
	// 	signerKey: PrivateKey
	// ): SenderCertificate {
	// 	let localSenderUuid = senderUuid;
	// 	if (typeof senderUuid !== 'string') {
	// 		localSenderUuid = senderUuid.getServiceIdString();
	// 	}
	// 	return new SenderCertificate(
	// 		ReactNativeLibsignalClientModule.senderCertificateNew(
	// 			localSenderUuid,
	// 			senderE164,
	// 			senderDeviceId,
	// 			senderKey.serialized,
	// 			expiration,
	// 			signerCert.serialized,
	// 			signerKey.serialized
	// 		)
	// 	);
	// }

	certificate(): Uint8Array {
		return ReactNativeLibsignalClientModule.senderCertificateGetCertificate(
			this.serialized
		);
	}
	expiration(): number {
		return ReactNativeLibsignalClientModule.senderCertificateGetExpiration(
			this.serialized
		);
	}
	key(): PublicKey {
		return PublicKey._fromSerialized(
			ReactNativeLibsignalClientModule.senderCertificateGetKey(this.serialized)
		);
	}
	senderE164(): string | null {
		return ReactNativeLibsignalClientModule.senderCertificateGetSenderE164(
			this.serialized
		);
	}
	senderUuid(): string {
		return ReactNativeLibsignalClientModule.senderCertificateGetSenderUuid(
			this.serialized
		);
	}
	/**
	 * Returns an ACI if the sender is a valid UUID, `null` otherwise.
	 *
	 * In a future release SenderCertificate will *only* support ACIs.
	 */
	senderAci(): Aci | null {
		try {
			return Aci.parseFromServiceIdString(this.senderUuid());
		} catch {
			return null;
		}
	}
	senderDeviceId(): number {
		return ReactNativeLibsignalClientModule.senderCertificateGetDeviceId(
			this.serialized
		);
	}
	serverCertificate(): ServerCertificate {
		return ServerCertificate._fromSerialized(
			ReactNativeLibsignalClientModule.senderCertificateGetServerCertificate(
				this.serialized
			)
		);
	}
	signature(): Uint8Array {
		return ReactNativeLibsignalClientModule.senderCertificateGetSignature(
			this.serialized
		);
	}
	validate(trustRoot: PublicKey, time: number): boolean {
		return ReactNativeLibsignalClientModule.senderCertificateValidate(
			this.serialized,
			trustRoot.serialized,
			time
		);
	}
}

export class ServerCertificate {
	readonly serialized: Uint8Array;

	static _fromSerialized(
		serialized: Uint8Array
	): ServerCertificate {
		return new ServerCertificate(serialized);
	}

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

  // this is not used anywhere and needs use of native method so is ignored
	// static new(
	// 	keyId: number,
	// 	serverKey: PublicKey,
	// 	trustRoot: PrivateKey
	// ): ServerCertificate {
	// 	return new ServerCertificate(
	// 		ReactNativeLibsignalClientModule.serverCertificateNew(
	// 			keyId,
	// 			serverKey.serialized,
	// 			trustRoot.serialized
	// 		)
	// 	);
	// }

	certificateData(): Uint8Array {
		return ReactNativeLibsignalClientModule.serverCertificateGetCertificate(
			this.serialized
		);
	}

	key(): PublicKey {
		return PublicKey._fromSerialized(
			ReactNativeLibsignalClientModule.serverCertificateGetKey(this.serialized)
		);
	}

	keyId(): number {
		return ReactNativeLibsignalClientModule.serverCertificateGetKeyId(
			this.serialized
		);
	}

	signature(): Uint8Array {
		return ReactNativeLibsignalClientModule.serverCertificateGetSignature(
			this.serialized
		);
	}
}

export class SessionRecord {
	serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	archiveCurrentState(): void {
		const serialized = ReactNativeLibsignalClientModule.sessionRecordArchiveCurrentState(
			this.serialized,
		);
		this.serialized = serialized;
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


export class SenderKeyDistributionMessage {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static async create(
		sender: ProtocolAddress,
		distributionId: string,
		store: SenderKeyStore
	): Promise<SenderKeyDistributionMessage> {
		const handle =
			await ReactNativeLibsignalClientModule.senderKeyDistributionMessageCreate(
				sender.toString(),
				Uint8Array.from(uuid.parse(distributionId) as Uint8Array),
				getCurrentKeyHandle(sender, distributionId, store)
			);
		return new SenderKeyDistributionMessage(handle);
	}

	static _fromSerialized(
		serialized: Uint8Array
	): SenderKeyDistributionMessage {
		return new SenderKeyDistributionMessage(serialized);
	}

	// static _new(
	// 	messageVersion: number,
	// 	distributionId: string,
	// 	chainId: number,
	// 	iteration: number,
	// 	chainKey: Uint8Array,
	// 	pk: PublicKey
	// ): SenderKeyDistributionMessage {
	// 	return new SenderKeyDistributionMessage(
	// 		ReactNativeLibsignalClientModule.senderKeyDistributionMessageNew(
	// 			messageVersion,
	// 			Uint8Array.from(uuid.parse(distributionId) as Uint8Array),
	// 			chainId,
	// 			iteration,
	// 			chainKey,
	// 			pk.serialized
	// 		)
	// 	);
	// }

	chainKey(): Uint8Array {
		return ReactNativeLibsignalClientModule.senderKeyDistributionMessageGetChainKey(
			this.serialized
		);
	}

	iteration(): number {
		return ReactNativeLibsignalClientModule.senderKeyDistributionMessageGetIteration(
			this.serialized
		);
	}

	chainId(): number {
		return ReactNativeLibsignalClientModule.senderKeyDistributionMessageGetChainId(
			this.serialized
		);
	}

	distributionId(): string {
		// the distributionId is already stringified in the native side
		return ReactNativeLibsignalClientModule.senderKeyDistributionMessageGetDistributionId(
			this.serialized
		);
	}
}

async function getCurrentKeyHandle(
	sender: ProtocolAddress,
	distributionId: string,
	store: SenderKeyStore
) {
	const key = await store.getSenderKey(sender, distributionId);
	if (!key) {
		throw new Error('No key found for sender');
	}
	return key.serialized;
}

export async function processSenderKeyDistributionMessage(
	sender: ProtocolAddress,
	message: SenderKeyDistributionMessage,
	store: SenderKeyStore
): Promise<void> {
	const distributionId = message.distributionId();
	const newSenderKeyRecord =
		await ReactNativeLibsignalClientModule.senderKeyDistributionMessageProcess(
			sender.toString(),
			message.serialized,
			await getCurrentKeyHandle(sender, distributionId, store)
		);
	store.saveSenderKey(sender, distributionId, newSenderKeyRecord);
}


export class UnidentifiedSenderMessageContent {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static _fromSerialized(
		serialized: Uint8Array
	): UnidentifiedSenderMessageContent {
		return new UnidentifiedSenderMessageContent(serialized);
	}

	static new(
		// message: CiphertextMessage,
		// sender: SenderCertificate,
		// contentHint: number,
		// groupId: Uint8Array | null
	): UnidentifiedSenderMessageContent {
		// TODO: find a solution for this!
		throw new Error(
			"Not implemented because we can't initialize a new CiphertextMessage on java side"
		);
	}

	static deserialize(buffer: Uint8Array): UnidentifiedSenderMessageContent {
		return new UnidentifiedSenderMessageContent(
			ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentDeserialize(
				buffer
			)
		);
	}

	serialize(): Uint8Array {
		return ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentSerialize(
			this.serialized
		);
	}

	contents(): Uint8Array {
		return ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentGetContents(
			this.serialized
		);
	}

	msgType(): number {
		return ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentGetMsgType(
			this.serialized
		);
	}

	senderCertificate(): SenderCertificate {
		return SenderCertificate._fromSerialized(
			ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentGetSenderCert(
				this.serialized
			)
		);
	}

	contentHint(): number {
		return ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentGetContentHint(
			this.serialized
		);
	}

	groupId(): Uint8Array | null {
		return ReactNativeLibsignalClientModule.unidentifiedSenderMessageContentGetGroupId(
			this.serialized
		);
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

export interface CipherTextMessage {
	serialized: Uint8Array;
	type(): CiphertextMessageType;
}

export class PlaintextContent implements CipherTextMessage {
	// removed this because it is not implemented in java
	// implements CiphertextMessageConvertible
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static from(message: DecryptionErrorMessage): PlaintextContent {
		return new PlaintextContent(
			ReactNativeLibsignalClientModule.plaintextContentFromDecryptionErrorMessage(
				message.serialized
			)
		);
	}

	static _fromSerialized(
		serialized: Uint8Array
	): PlaintextContent {
		return new PlaintextContent(serialized);
	}

	type(): CiphertextMessageType {
		return CiphertextMessageType.Plaintext;
	}

	body(): Uint8Array {
		return ReactNativeLibsignalClientModule.plaintextContentGetBody(
			this.serialized
		);
	}

	// asCiphertextMessage(): CiphertextMessage {
	// 	return CiphertextMessage._fromNativeserialized(
	// 		ReactNativeLibsignalClientModule.CiphertextMessage_FromPlaintextContent(
	// 			this.serialize()
	// 		)
	// 	);
	// }
}

export class DecryptionErrorMessage {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static _fromSerialized(
		serialized: Uint8Array
	): DecryptionErrorMessage {
		return new DecryptionErrorMessage(serialized);
	}

	static forOriginal(
		bytes: Uint8Array,
		type: CiphertextMessageType,
		timestamp: number,
		originalSenderDeviceId: number
	): DecryptionErrorMessage {
		return new DecryptionErrorMessage(
			ReactNativeLibsignalClientModule.decryptionErrorMessageForOriginalMessage(
				bytes,
				type,
				timestamp,
				originalSenderDeviceId
			)
		);
	}

	static extractFromSerializedBody(buffer: Uint8Array): DecryptionErrorMessage {
		return new DecryptionErrorMessage(
			ReactNativeLibsignalClientModule.decryptionErrorMessageExtractFromSerializedContent(
				buffer
			)
		);
	}

	timestamp(): number {
		return ReactNativeLibsignalClientModule.decryptionErrorMessageGetTimestamp(
			this.serialized
		);
	}

	deviceId(): number {
		return ReactNativeLibsignalClientModule.decryptionErrorMessageGetDeviceId(
			this.serialized
		);
	}

	ratchetKey(): PublicKey | undefined {
		const serializedPublicKey =
			ReactNativeLibsignalClientModule.decryptionErrorMessageGetRatchetKey(
				this.serialized
			);
		if (serializedPublicKey) {
			return PublicKey._fromSerialized(serializedPublicKey);
		}
		return undefined;
	}
}

export class SignalMessage implements CipherTextMessage {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	// static _new(
	// 	messageVersion: number,
	// 	macKey: Uint8Array,
	// 	senderRatchetKey: PublicKey,
	// 	counter: number,
	// 	previousCounter: number,
	// 	ciphertext: Uint8Array,
	// 	senderIdentityKey: PublicKey,
	// 	receiverIdentityKey: PublicKey
	// ): SignalMessage {
	// 	return new SignalMessage(
	// 		ReactNativeLibsignalClientModule.SignalMessageNew(
	// 			messageVersion,
	// 			macKey,
	// 			senderRatchetKey.serialized,
	// 			counter,
	// 			previousCounter,
	// 			ciphertext,
	// 			senderIdentityKey.serialized,
	// 			receiverIdentityKey.serialized
	// 		)
	// 	);
	// }

	static _fromSerialized(serialized: Uint8Array): SignalMessage {
		return new SignalMessage(serialized);
	}

	body(): Uint8Array {
		return ReactNativeLibsignalClientModule.SignalMessageGetBody(this.serialized);
	}

	counter(): number {
		return ReactNativeLibsignalClientModule.SignalMessageGetCounter(
			this.serialized
		);
	}

	messageVersion(): number {
		return ReactNativeLibsignalClientModule.SignalMessageGetMessageVersion(
			this.serialized
		);
	}

	type(): CiphertextMessageType {
		return CiphertextMessageType.Whisper;
	}

	verifyMac(
		senderIdentityKey: PublicKey,
		recevierIdentityKey: PublicKey,
		macKey: Uint8Array
	): boolean {
		return ReactNativeLibsignalClientModule.SignalMessageVerifyMac(
			this.serialized,
			senderIdentityKey.serialized,
			recevierIdentityKey.serialized,
			macKey
		);
	}
}

export class PreKeySignalMessage implements CipherTextMessage {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

  // this is not used anywhere in app but is useful for testing things separately, currently commented out because it's not implemented in java wrapper and needs to be used using Native. methods. there is a commented-out (so we don't import Native for no reason) example of it for SignalMessage_New in kotlin file
	// static _new(
	// 	messageVersion: number,
	// 	registrationId: number,
	// 	preKeyId: number | null,
	// 	signedPreKeyId: number,
	// 	baseKey: PublicKey,
	// 	identityKey: PublicKey,
	// 	signalMessage: SignalMessage
	// ): PreKeySignalMessage {
	// 	return new PreKeySignalMessage(
	// 		ReactNativeLibsignalClientModule.PreKeySignalMessage_New(
	// 			messageVersion,
	// 			registrationId,
	// 			preKeyId,
	// 			signedPreKeyId,
	// 			baseKey.serialized,
	// 			identityKey.serialized,
	// 			signalMessage.serialized
	// 		)
	// 	);
	// }

	preKeyId(): number | null {
		return ReactNativeLibsignalClientModule.preKeySignalMessageGetPreKeyId(
			this.serialized
		);
	}

	registrationId(): number {
		return ReactNativeLibsignalClientModule.preKeySignalMessageGetRegistrationId(
			this.serialized
		);
	}

	signedPreKeyId(): number {
		return ReactNativeLibsignalClientModule.preKeySignalMessageGetSignedPreKeyId(
			this.serialized
		);
	}

	version(): number {
		return ReactNativeLibsignalClientModule.preKeySignalMessageGetVersion(
			this.serialized
		);
	}

	type(): CiphertextMessageType {
		return CiphertextMessageType.PreKey;
	}

	static _fromSerialized(
		serialized: Uint8Array
	): PreKeySignalMessage {
		return new PreKeySignalMessage(serialized);
	}


	// asCiphertextMessage(): CiphertextMessage {
	// 	return CiphertextMessage._fromNativeserialized(
	// 		ReactNativeLibsignalClientModule.CiphertextMessage_FromPlaintextContent(
	// 			this.serialize()
	// 		)
	// 	);
	// }
}

export class SenderKeyMessage implements CipherTextMessage {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	// this is not used anywhere in app but is useful for testing things separately, currently commented out because it's not implemented in java wrapper and needs to be used using Native. methods. there is a commented-out (so we don't import Native for no reason) example of it for SignalMessage_New in kotlin file
	// static _new(
	// 	messageVersion: number,
	// 	distributionId: string,
	// 	chainId: number,
	// 	iteration: number,
	// 	ciphertext: Uint8Array,
	// 	pk: PrivateKey
	// ): SenderKeyMessage {
	// 	return new SenderKeyMessage(
	// 		ReactNativeLibsignalClientModule.SenderKeyMessage_New(
	// 			messageVersion,
	// 			Uint8Array.from(uuid.parse(distributionId) as Uint8Array),
	// 			chainId,
	// 			iteration,
	// 			ciphertext,
	// 			pk.serialized
	// 		)
	// 	);
	// }

	static _fromSerialized(
		serialized: Uint8Array
	): SenderKeyMessage {
		return new SenderKeyMessage(serialized);
	}

	type(): CiphertextMessageType {
		return CiphertextMessageType.SenderKey;
	}

	ciphertext(): Uint8Array {
		return ReactNativeLibsignalClientModule.senderKeyMessageGetCipherText(
			this.serialized
		);
	}

	iteration(): number {
		return ReactNativeLibsignalClientModule.senderKeyMessageGetIteration(
			this.serialized
		);
	}

	chainId(): number {
		return ReactNativeLibsignalClientModule.senderKeyMessageGetChainId(
			this.serialized
		);
	}

	distributionId(): string {
		//it's already stringified in the native side
		return ReactNativeLibsignalClientModule.senderKeyMessageGetDistributionId(
			this.serialized
		);
	}

	verifySignature(key: PublicKey): boolean {
		return ReactNativeLibsignalClientModule.senderKeyMessageVerifySignature(
			this.serialized,
			key.serialized
		);
	}
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


export async function signalEncrypt(
	message: Uint8Array,
	address: ProtocolAddress,
	sessionStore: SessionStore,
	identityStore: IdentityKeyStore,
	now: Date = new Date()
): Promise<CipherTextMessage> {
	const sessionStoreState = await getSessionStoreObject(sessionStore, address);
	const identityStoreState = await getIdentityStoreObject(
		identityStore,
		address
	);
	const [
		[cipher_serialized, cipherType],
		[updatedSessionStoreState, updatedIdentityStoreState],
	] = ReactNativeLibsignalClientModule.sessionCipherEncryptMessage(
		fromByteArray(message),
		address.toString(),
		sessionStoreState,
		identityStoreState,
		now.getTime()
	);
	await updateSessionStoreFromObject(sessionStore, updatedSessionStoreState);
	await updateIdentityStoreFromObject(identityStore, updatedIdentityStoreState);
	return bufferToCipherText(cipher_serialized, cipherType);
}

export async function signalDecrypt(
	message: SignalMessage,
	address: ProtocolAddress,
	sessionStore: SessionStore,
	identityStore: IdentityKeyStore
): Promise<Uint8Array> {
	const currentSessionStoreState = await getSessionStoreObject(
		sessionStore,
		address
	);
	const identityStoreState = await getIdentityStoreObject(
		identityStore,
		address
	);
	const [cipher, [updatedSessionStore, updatedIdentityStore]] =
		ReactNativeLibsignalClientModule.sessionCipherDecryptSignalMessage(
			message.serialized,
			address.toString(),
			currentSessionStoreState,
			identityStoreState
		);
	await updateSessionStoreFromObject(sessionStore, updatedSessionStore);
	await updateIdentityStoreFromObject(identityStore, updatedIdentityStore);
	return cipher;
}

export async function signalDecryptPreKey(
	message: PreKeySignalMessage,
	address: ProtocolAddress,
	sessionStore: SessionStore,
	identityStore: IdentityKeyStore,
	prekeyStore: PreKeyStore,
	signedPrekeyStore: SignedPreKeyStore,
	kyberPrekeyStore: KyberPreKeyStore,
	kyberPrekeyIds: number[]
): Promise<Uint8Array> {
	const identityStoreInitializer =
		await getIdentityStoreInitializer(identityStore);
	const signedPrekeyId = message.signedPreKeyId();
	if (signedPrekeyId === null) {
		throw new Error('PreKeySignalMessage does not have a preKeyId');
	}
	const signedPrekeyStoreState = await getSignedPrekeyStoreState(
		signedPrekeyStore,
		signedPrekeyId
	);

	const preKeyId = message.preKeyId();
	if (preKeyId === null) {
		throw new Error('PreKeySignalMessage does not have a preKeyId');
	}
	const prekeyStoreState = await getPrekeyStoreState(prekeyStore, preKeyId);
	let kyberPrekeyStoreState: KeyObject = {};
	if (!kyberPrekeyIds.includes(-1)) {
		kyberPrekeyStoreState = await getKyberPrekeyStoreState(
			kyberPrekeyStore,
			kyberPrekeyIds
		);
	}
	const [
		msg,
		[
			updatedSessionStore,
			updatedIdentityStore,
			updatedPrekeyStore,
			updatedSignedPrekeyStore,
		],
	] = ReactNativeLibsignalClientModule.sessionCipherDecryptPreKeySignalMessage(
		message.serialized,
		address.toString(),
		identityStoreInitializer,
		prekeyStoreState,
		signedPrekeyStoreState,
		kyberPrekeyStoreState
	);

	await updateSessionStoreFromObject(sessionStore, updatedSessionStore);
	await updateIdentityStoreFromObject(identityStore, updatedIdentityStore);
	await updateSignedPrekeyStoreFromObject(
		signedPrekeyStore,
		updatedSignedPrekeyStore
	);
	//TODO: probably need to comment this line too because the function only marks them as used, no need to update the store
	await updatedPrekeyStoreFromObject(prekeyStore, updatedPrekeyStore);
	// it only marks them as used, no need to update the store
	// await updateKyberPrekeyStoreFromObject(
	// 	kyberPrekeyStore,
	// 	updatedKyberPrekeyStore
	// );
	return msg;
}

function bufferToCipherText(
	cipher_serialized: Uint8Array,
	type: number
): CipherTextMessage {
	switch (type) {
		case CiphertextMessageType.Plaintext:
			return PlaintextContent._fromSerialized(
				cipher_serialized
			);
		case CiphertextMessageType.PreKey:
			return PreKeySignalMessage._fromSerialized(
				cipher_serialized
			);
		case CiphertextMessageType.SenderKey:
			return SenderKeyMessage._fromSerialized(
				cipher_serialized
			);
		case CiphertextMessageType.Whisper:
			return SignalMessage._fromSerialized(
				cipher_serialized
			);
	}

	throw new Error('invalid cipher text type');
}

export function sealedSenderEncrypt(
	content: UnidentifiedSenderMessageContent,
	address: ProtocolAddress,
	identityStore: IdentityKeyStore
): Promise<Uint8Array> {
	const identityStoreState = getIdentityStoreObject(identityStore, address);
	return ReactNativeLibsignalClientModule.sealedSenderEncrypt(
		address.toString(),
		content.serialized,
		identityStoreState
	);
}

type SealedSenderMultiRecipientEncryptOptions = {
	content: UnidentifiedSenderMessageContent;
	recipients: ProtocolAddress[];
	excludedRecipients?: ServiceId[];
	identityStore: IdentityKeyStore;
	sessionStore: SessionStore;
};

export async function sealedSenderMultiRecipientEncrypt(
	options: SealedSenderMultiRecipientEncryptOptions
): Promise<Uint8Array>;
export async function sealedSenderMultiRecipientEncrypt(
	content: UnidentifiedSenderMessageContent,
	recipients: ProtocolAddress[],
	identityStore: IdentityKeyStore,
	sessionStore: SessionStore
): Promise<Uint8Array>;

export async function sealedSenderMultiRecipientEncrypt(
	contentOrOptions:
		| UnidentifiedSenderMessageContent
		| SealedSenderMultiRecipientEncryptOptions,
	recipients?: ProtocolAddress[],
	identityStore?: IdentityKeyStore,
	sessionStore?: SessionStore
): Promise<Uint8Array> {
	let excludedRecipients: ServiceId[] | undefined = undefined;
	if (contentOrOptions instanceof UnidentifiedSenderMessageContent) {
		if (!recipients || !identityStore || !sessionStore) {
			throw Error('missing arguments for sealedSenderMultiRecipientEncrypt');
		}
	} else {
		({
			// biome-ignore lint/style/noParameterAssign: <explanation>
			content: contentOrOptions,
			// biome-ignore lint/style/noParameterAssign: <explanation>
			recipients,
			excludedRecipients,
			// biome-ignore lint/style/noParameterAssign: <explanation>
			identityStore,
			// biome-ignore lint/style/noParameterAssign: <explanation>
			sessionStore,
		} = contentOrOptions);
	}

	const recipientSessions = await sessionStore.getExistingSessions(recipients);
	return await ReactNativeLibsignalClientModule.sealedSenderMultiRecipientEncrypt(
		recipients.map((r) => r.toString()),
		recipientSessions.map((r) => r.serialized),
		ServiceId.toConcatenatedFixedWidthBinary(excludedRecipients ?? []),
		contentOrOptions.serialized,
		identityStore
	);
}

// For testing only
export function sealedSenderMultiRecipientMessageForSingleRecipient(
	message: Uint8Array
): Uint8Array {
	return ReactNativeLibsignalClientModule.sealedSenderMultiRecipientMessageForSingleRecipient(
		message
	);
}

export async function sealedSenderDecryptToUsmc(
	message: Uint8Array,
	identityStore: IdentityKeyStore,
	sender: ProtocolAddress
): Promise<UnidentifiedSenderMessageContent> {
	const identityStoreState = await getIdentityStoreObject(
		identityStore,
		sender
	);
	const [usmc, updatedIdState] =
		await ReactNativeLibsignalClientModule.sealedSenderDecryptToUsmc(
			fromByteArray(message),
			identityStoreState,
			sender.toString()
		);
	await updateIdentityStoreFromObject(identityStore, updatedIdState);
	return UnidentifiedSenderMessageContent._fromSerialized(usmc);
}

export function generateRegistrationID(): number {
	return ReactNativeLibsignalClientModule.GenerateRegistrationID();
}

export { CiphertextMessageType, ContentHint, Direction };

