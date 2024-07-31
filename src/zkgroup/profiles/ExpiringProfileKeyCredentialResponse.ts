export default class ExpiringProfileKeyCredentialResponse {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }
}
