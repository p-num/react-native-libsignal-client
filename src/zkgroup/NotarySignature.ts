export default class NotarySignature {
  readonly serialized: Uint8Array;
  static SIZE = 64;

  constructor(serialized: Uint8Array) {
    if (serialized.length !== NotarySignature.SIZE) {
      throw new Error(`Length of array supplied was ${serialized.length} expected ${NotarySignature.SIZE}`);
    }

    this.serialized = serialized;
  }
}
