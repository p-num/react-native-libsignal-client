import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import UuidCiphertext from "../groups/UuidCiphertext";

export default class AuthCredentialPresentation {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      ReactNativeLibsignalClientModule.authCredentialPresentationGetUuidCiphertext(
        this.serialized,
      ),
    );
  }

  getPniCiphertext(): UuidCiphertext | null {
    const ciphertextBytes =
      ReactNativeLibsignalClientModule.authCredentialPresentationGetPniCiphertext(
        this.serialized,
      );
    if (ciphertextBytes === null) {
      return null;
    }
    return new UuidCiphertext(ciphertextBytes);
  }

  getRedemptionTime(): Date {
    return new Date(
      1000 *
        ReactNativeLibsignalClientModule.authCredentialPresentationGetRedemptionTime(
          this.serialized,
        ),
    );
  }
}
