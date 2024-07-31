import { RANDOM_LENGTH } from "../internal/Constants";

import ServerPublicParams from "../ServerPublicParams";
import AuthCredentialPresentation from "./AuthCredentialPresentation";
import AuthCredentialWithPni from "./AuthCredentialWithPni";
import AuthCredentialWithPniResponse from "./AuthCredentialWithPniResponse";
import GroupSecretParams from "../groups/GroupSecretParams";
import { Aci, Pni } from "../../Address";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import { randomBytes } from "../../randomBytes";

export default class ClientZkAuthOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  /**
   * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
   *
   * @param redemptionTime - This is provided by the server as an integer, and should be passed through directly.
   */
  receiveAuthCredentialWithPniAsServiceId(
    aci: Aci,
    pni: Pni,
    redemptionTime: number,
    authCredentialResponse: AuthCredentialWithPniResponse,
  ): AuthCredentialWithPni {
    return new AuthCredentialWithPni(
      ReactNativeLibsignalClientModule.serverPublicParamsReceiveAuthCredentialWithPniAsServiceId(
        this.serverPublicParams.serialized,
        aci.getServiceIdFixedWidthBinary(),
        pni.getServiceIdFixedWidthBinary(),
        redemptionTime,
        authCredentialResponse.serialized,
      ),
    );
  }

  createAuthCredentialWithPniPresentation(
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredentialWithPni,
  ): AuthCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createAuthCredentialWithPniPresentationWithRandom(
      random,
      groupSecretParams,
      authCredential,
    );
  }

  createAuthCredentialWithPniPresentationWithRandom(
    random: Uint8Array,
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredentialWithPni,
  ): AuthCredentialPresentation {
    return new AuthCredentialPresentation(
      ReactNativeLibsignalClientModule.serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic(
        this.serverPublicParams.serialized,
        random,
        groupSecretParams.serialized,
        authCredential.serialized,
      ),
    );
  }
}
