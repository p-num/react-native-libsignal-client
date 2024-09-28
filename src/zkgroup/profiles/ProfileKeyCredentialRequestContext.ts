import ProfileKeyCredentialRequest from "./ProfileKeyCredentialRequest";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";

export default class ProfileKeyCredentialRequestContext {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getRequest(): ProfileKeyCredentialRequest {
    return new ProfileKeyCredentialRequest(
      new Uint8Array(
        ReactNativeLibsignalClientModule.profileKeyCredentialRequestContextGetRequest(
          this.serialized
        )
      )
    );
  }
}
