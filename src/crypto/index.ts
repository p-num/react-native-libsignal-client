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
		return ReactNativeLibsignalClientModule.Aes256CbcEncrypt(
			new Uint8Array(this.serialized),
			new Uint8Array(iv),
			new Uint8Array(data)
		);
	}

	decrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
		return ReactNativeLibsignalClientModule.Aes256CbcDecrypt(
			new Uint8Array(this.serialized),
			new Uint8Array(iv),
			new Uint8Array(data)
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
		return ReactNativeLibsignalClientModule.Aes256CtrEncrypt(
			new Uint8Array(this.serialized),
			new Uint8Array(iv),
			new Uint8Array(data)
		);
	}

	decrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
		return ReactNativeLibsignalClientModule.Aes256CtrDecrypt(
			new Uint8Array(this.serialized),
			new Uint8Array(iv),
			new Uint8Array(data)
		);
	}
}

export { Aes256Ctr as Aes256CCtr, CipherType, EncryptionOptions };
