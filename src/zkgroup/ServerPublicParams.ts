import ReactNativeLibsignalClientModule from "../ReactNativeLibsignalClientModule";
import NotarySignature from "./NotarySignature";

export default class ServerPublicParams {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  verifySignature(message: Uint8Array, notarySignature: NotarySignature): void {
    if (!ReactNativeLibsignalClientModule.serverPublicParamsVerifySignature(this.serialized, message, notarySignature.contents)) {
      throw new Error("ServerPublicParams.verifySignature failed");
    }
  }
}
