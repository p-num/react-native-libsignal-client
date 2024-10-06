import {
  CipherType,
  EncryptionOptions,
} from "../ReactNativeLibsignalClient.types";
import ReactNativeLibsignalClientModule from "../ReactNativeLibsignalClientModule";

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
        this.serialized,
        nonce,
        message,
        associated_data
      )
    );
  }

  decrypt(
    message: Uint8Array,
    nonce: Uint8Array,
    associated_data?: Uint8Array
  ): Uint8Array {
    console.error(message, "decrypt message");
    return new Uint8Array(
      ReactNativeLibsignalClientModule.Aes256GcmDecrypt(
        this.serialized,
        nonce,
        message,
        associated_data
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
      this.serialized,
      iv,
      data
    );
  }

  decrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
    return ReactNativeLibsignalClientModule.Aes256CbcDecrypt(
      this.serialized,
      iv,
      data
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
        options.text,
        options.iv,
        options.aad ?? new Uint8Array()
      );
    case CipherType.AES256CBC:
      return Aes256Cbc.new(options.key).encrypt(options.text, options.iv);
  }
}

export function signHmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return ReactNativeLibsignalClientModule.HmacSHA256(key, data);
}

export function decrypt(
  cipherType: CipherType,
  options: EncryptionOptions
): Uint8Array {
  switch (cipherType) {
    case CipherType.AES256GCM:
      return Aes256Gcm.new(options.key).decrypt(
        options.text,
        options.iv,
        options.aad ?? new Uint8Array()
      );
    case CipherType.AES256CBC:
      return Aes256Cbc.new(options.key).decrypt(options.text, options.iv);
  }
}

export function constantTimeEqual(
  left: Uint8Array,
  right: Uint8Array
): boolean {
  return ReactNativeLibsignalClientModule.ConstantTimeEqual(left, right);
}

export { CipherType, EncryptionOptions };
