import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";

export default class ExpiringProfileKeyCredential {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getExpirationTime(): Date {
    return new Date(
      1000 *
        ReactNativeLibsignalClientModule.expiringProfileKeyCredentialGetExpirationTime(
            this.serialized,
        )
    );
  }
}
