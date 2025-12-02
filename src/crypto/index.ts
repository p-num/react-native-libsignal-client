import ElasticCipher from '../ElasticCipherModule';
import {
	CipherType,
	EncryptionOptions,
} from '../ReactNativeLibsignalClient.types';
import ReactNativeLibsignalClientModule from '../ReactNativeLibsignalClientModule';

export class Aes256Gcm {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static new(key: Uint8Array): Aes256Gcm {
		return new Aes256Gcm(key);
	}

	encrypt(
		message: Uint8Array,
		nonce: Uint8Array,
		associated_data?: Uint8Array
	): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.Aes256GcmEncrypt(
				new Uint8Array(this.serialized),
				new Uint8Array(nonce),
				new Uint8Array(message),
				associated_data ? new Uint8Array(associated_data) : undefined
			)
		);
	}

	decrypt(
		message: Uint8Array,
		nonce: Uint8Array,
		associated_data?: Uint8Array
	): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.Aes256GcmDecrypt(
				new Uint8Array(this.serialized),
				new Uint8Array(nonce),
				new Uint8Array(message),
				associated_data ? new Uint8Array(associated_data) : undefined
			)
		);
	}
}

export class Aes256Cbc {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static new(key: Uint8Array): Aes256Cbc {
		return new Aes256Cbc(key);
	}

	encrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.Aes256CbcEncrypt(
				new Uint8Array(this.serialized),
				new Uint8Array(iv),
				new Uint8Array(data)
			)
		);
	}

	decrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.Aes256CbcDecrypt(
				new Uint8Array(this.serialized),
				new Uint8Array(iv),
				new Uint8Array(data)
			)
		);
	}
}

export function encrypt(
	cipherType: CipherType,
	options: EncryptionOptions
): Uint8Array {
	switch (cipherType) {
		case CipherType.AES256GCM:
			return Aes256Gcm.new(options.key).encrypt(
				new Uint8Array(options.text),
				new Uint8Array(options.iv),
				options.aad ? new Uint8Array(options.aad) : new Uint8Array()
			);
		case CipherType.AES256CBC:
			return Aes256Cbc.new(options.key).encrypt(options.text, options.iv);
		case CipherType.AES256CTR:
			return Aes256Ctr.new(options.key).encrypt(options.text, options.iv);
	}
}

export function signHmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
	return new Uint8Array(
		ReactNativeLibsignalClientModule.HmacSHA256(
			new Uint8Array(key),
			new Uint8Array(data)
		)
	);
}

export function decrypt(
	cipherType: CipherType,
	options: EncryptionOptions
): Uint8Array {
	switch (cipherType) {
		case CipherType.AES256GCM:
			return Aes256Gcm.new(options.key).decrypt(
				new Uint8Array(options.text),
				new Uint8Array(options.iv),
				options.aad ? new Uint8Array(options.aad) : new Uint8Array()
			);
		case CipherType.AES256CBC:
			return Aes256Cbc.new(options.key).decrypt(options.text, options.iv);
		case CipherType.AES256CTR:
			return Aes256Ctr.new(options.key).decrypt(options.text, options.iv);
	}
}

export function constantTimeEqual(
	left: Uint8Array,
	right: Uint8Array
): boolean {
	return ReactNativeLibsignalClientModule.ConstantTimeEqual(
		new Uint8Array(left),
		new Uint8Array(right)
	);
}

class Aes256Ctr {
	readonly serialized: Uint8Array;

	private constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	static new(key: Uint8Array): Aes256Ctr {
		return new Aes256Ctr(key);
	}

	encrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.Aes256CtrEncrypt(
				new Uint8Array(this.serialized),
				new Uint8Array(iv),
				new Uint8Array(data)
			)
		);
	}

	decrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.Aes256CtrDecrypt(
				new Uint8Array(this.serialized),
				new Uint8Array(iv),
				new Uint8Array(data)
			)
		);
	}
}

export enum HashType {
	SHA256 = 'sha256',
	SHA512 = 'sha512',
}

export class CalculatingMac {
	private readonly bridgeHandle: string;
	private readonly _type: HashType;

	private constructor(type: HashType, key: Uint8Array) {
		this._type = type;
		switch (type) {
			case HashType.SHA256:
				this.bridgeHandle = ElasticCipher.IncrementalHmacInit(
					type as string,
					new Uint8Array(key)
				);
				break;
			case HashType.SHA512:
				this.bridgeHandle = ElasticCipher.IncrementalHmacInit(
					type as string,
					new Uint8Array(key)
				);
				break;
		}
	}

	static new(type: HashType, key: Uint8Array): CalculatingMac {
		return new CalculatingMac(type, key);
	}

	update(data: Uint8Array): void {
		switch (this._type) {
			case HashType.SHA256:
				ElasticCipher.HmacSha256Update(this.bridgeHandle, new Uint8Array(data));
				break;
			case HashType.SHA512:
				ElasticCipher.HmacSha512Update(this.bridgeHandle, new Uint8Array(data));
				break;
		}
	}

	digest(): Uint8Array {
		switch (this._type) {
			case HashType.SHA256:
				return new Uint8Array(
					ElasticCipher.HmacSha256Digest(this.bridgeHandle)
				);
			case HashType.SHA512:
				return new Uint8Array(
					ElasticCipher.HmacSha512Digest(this.bridgeHandle)
				);
		}
	}
}

export class IncrementalHash {
	private readonly bridgeHandle: string;
	private readonly _type: HashType;

	private constructor(type: HashType) {
		this._type = type;
		this.bridgeHandle = ElasticCipher.IncrementalHashInit(type as string);
	}

	static new(type: HashType): IncrementalHash {
		return new IncrementalHash(type);
	}

	update(data: Uint8Array): void {
		switch (this._type) {
			case HashType.SHA256:
				ElasticCipher.HashSha256Update(this.bridgeHandle, new Uint8Array(data));
				break;
			case HashType.SHA512:
				ElasticCipher.HashSha512Update(this.bridgeHandle, new Uint8Array(data));
				break;
		}
	}

	digest(): Uint8Array {
		switch (this._type) {
			case HashType.SHA256:
				return new Uint8Array(
					ElasticCipher.HashSha256Digest(this.bridgeHandle)
				);
			case HashType.SHA512:
				return new Uint8Array(
					ElasticCipher.HashSha512Digest(this.bridgeHandle)
				);
		}
	}
}

export function createHmac(type: HashType, key: Uint8Array): CalculatingMac {
	return CalculatingMac.new(type, key);
}

export function createHash(type: HashType): IncrementalHash {
	return IncrementalHash.new(type);
}

export class ValidatingMac {
	private readonly bridgeHandle: string;

	constructor(
		key: Uint8Array,
		sizeChoice: ChunkSizeChoice,
		digest: Uint8Array
	) {
		this.bridgeHandle = ElasticCipher.ValidatingMacInit(
			new Uint8Array(key),
			chunkSizeInBytes(sizeChoice),
			new Uint8Array(digest)
		);
	}

	update(data: Uint8Array): number {
		return ElasticCipher.ValidatingMacUpdate(
			this.bridgeHandle,
			new Uint8Array(data)
		);
	}

	finalize(): number {
		return ElasticCipher.ValidatingMacFinalize(this.bridgeHandle);
	}
}

export class IncrementalMac {
	private readonly bridgeHandle: string;

	constructor(key: Uint8Array, sizeChoice: ChunkSizeChoice) {
		this.bridgeHandle = ElasticCipher.IncrementalMacInit(
			new Uint8Array(key),
			chunkSizeInBytes(sizeChoice)
		);
	}

	update(data: Uint8Array): Uint8Array {
		return new Uint8Array(
			ElasticCipher.IncrementalMacUpdate(
				this.bridgeHandle,
				new Uint8Array(data)
			)
		);
	}

	finalize(): Uint8Array {
		return new Uint8Array(
			ElasticCipher.IncrementalMacFinalize(this.bridgeHandle)
		);
	}
}

export type ChunkSizeChoice =
	| { kind: 'everyN'; n: number }
	| { kind: 'chunksOf'; dataSize: number };

export { Aes256Ctr as Aes256CCtr, CipherType, EncryptionOptions };

export function chunkSizeInBytes(sizeChoice: ChunkSizeChoice): number {
	switch (sizeChoice.kind) {
		case 'everyN':
			return sizeChoice.n;
		case 'chunksOf':
			return ElasticCipher.IncrementalMacCalculateChunkSize(
				sizeChoice.dataSize
			);
	}
}
