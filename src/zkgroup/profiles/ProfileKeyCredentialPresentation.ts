import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import ProfileKeyCiphertext from "../groups/ProfileKeyCiphertext";
import UuidCiphertext from "../groups/UuidCiphertext";

export default class ProfileKeyCredentialPresentation {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      ReactNativeLibsignalClientModule.profileKeyCredentialPresentationGetUuidCiphertext(
        this.serialized,
      ),
    );
  }

  getProfileKeyCiphertext(): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      ReactNativeLibsignalClientModule.profileKeyCredentialPresentationGetProfileKeyCiphertext(
        this.serialized,
      ),
    );
  }
}
