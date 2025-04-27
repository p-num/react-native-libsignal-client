export default class UuidCiphertext {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  static serializeAndConcatenate(ciphertexts: UuidCiphertext[]): Uint8Array {
    if (ciphertexts.length === 0) {
      return new Uint8Array(0);
    }

    const uuidCiphertextLen = ciphertexts[0].serialized.length;
    // const concatenated = Buffer.alloc(ciphertexts.length * uuidCiphertextLen);
    const concatenated = new Uint8Array(ciphertexts.length * uuidCiphertextLen);
    let offset = 0;
    for (const next of ciphertexts) {
      if (next.serialized.length !== uuidCiphertextLen) {
        throw TypeError('UuidCiphertext with unexpected length');
      }
      concatenated.set(next.serialized, offset);
      offset += uuidCiphertextLen;
    }

    return concatenated;
  }
}
