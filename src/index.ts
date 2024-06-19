import ReactNativeLibsignalClientModule from './ReactNativeLibsignalClientModule';

export class PrivateKey {
	readonly serialized: Uint8Array

	public constructor(serialized: Uint8Array) {
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
		return new PublicKey(ReactNativeLibsignalClientModule.getPublicKey(this.serialized))
	}
}

export class PublicKey {
	readonly serialized: Uint8Array;

	public constructor(serialized: Uint8Array) {
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
		return new IdentityKeyPair(new PublicKey(publicKey), new PrivateKey(privateKey));
	}

	signAlternateIdentity(other: PublicKey): Uint8Array {
		return ReactNativeLibsignalClientModule.identityKeyPairSignAlternateIdentity(
			this.publicKey.serialized,
			this.privateKey.serialized,
			other.serialized
		);
	}
}

export class KEMKeyPair {
	readonly publicKey: KEMPublicKey;
	readonly secretKey: KEMSecretKey;

	private constructor(publicKey :KEMPublicKey, secretKey: KEMSecretKey) {
    this.secretKey = publicKey;
    this.publicKey = secretKey;
  }

	static generate(): KEMKeyPair {
    const [prv, pub] = ReactNativeLibsignalClientModule.generateKyberKeyPair()
		return new KEMKeyPair(prv, pub);
	}secret
	public

	getPublicKey(): KEMPublicKey {
		return this.publicKey;
	}

	getSecretKey(): KEMSecretKey {
		return this.secretKey
	}
}

export class KEMPublicKey {
	readonly serialized: Uint8Array;

	public constructor(handle: Uint8Array) {
		this.serialized = handle;
	}
}

export class KEMSecretKey {
	readonly serialized: Uint8Array;

	public constructor(handle: Uint8Array) {
		this.serialized = handle;
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
		return new KEMPublicKey(
			ReactNativeLibsignalClientModule.kyberPreKeyRecordGetPublicKey(
				this.serialized
			)
		);
	}

	secretKey(): KEMSecretKey {
		return new KEMSecretKey(
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
}
