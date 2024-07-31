import ExpiringProfileKeyCredential from "./ExpiringProfileKeyCredential";
import ExpiringProfileKeyCredentialResponse from "./ExpiringProfileKeyCredentialResponse";
import ProfileKey from "./ProfileKey";
import ProfileKeyCredentialPresentation from "./ProfileKeyCredentialPresentation";
import ProfileKeyCredentialRequestContext from "./ProfileKeyCredentialRequestContext";
import { Aci } from "../../Address";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import ServerPublicParams from "../ServerPublicParams";
import GroupSecretParams from "../groups/GroupSecretParams";
import { RANDOM_LENGTH } from "../internal/Constants";

export default class ClientZkProfileOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  createProfileKeyCredentialRequestContext(
    userId: Aci,
    profileKey: ProfileKey,
  ): ProfileKeyCredentialRequestContext {
    const random =
      ReactNativeLibsignalClientModule.generateRandomBytes(RANDOM_LENGTH);

    return this.createProfileKeyCredentialRequestContextWithRandom(
      random,
      userId,
      profileKey,
    );
  }

  createProfileKeyCredentialRequestContextWithRandom(
    random: Uint8Array,
    userId: Aci,
    profileKey: ProfileKey,
  ): ProfileKeyCredentialRequestContext {
    return new ProfileKeyCredentialRequestContext(
      ReactNativeLibsignalClientModule.serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic(
        this.serverPublicParams.serialized,
        random,
        userId.getServiceIdFixedWidthBinary(),
        profileKey.serialized,
      ),
    );
  }

  receiveExpiringProfileKeyCredential(
    profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext,
    profileKeyCredentialResponse: ExpiringProfileKeyCredentialResponse,
    now: Date = new Date(),
  ): ExpiringProfileKeyCredential {
    return new ExpiringProfileKeyCredential(
      ReactNativeLibsignalClientModule.serverPublicParamsReceiveExpiringProfileKeyCredential(
        this.serverPublicParams.serialized,
        profileKeyCredentialRequestContext.serialized,
        profileKeyCredentialResponse.serialized,
        Math.floor(now.getTime() / 1000),
      ),
    );
  }

  createExpiringProfileKeyCredentialPresentation(
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ExpiringProfileKeyCredential,
  ): ProfileKeyCredentialPresentation {
    const random = ReactNativeLibsignalClientModule.generateRandomBytes(RANDOM_LENGTH);

    return this.createExpiringProfileKeyCredentialPresentationWithRandom(
      random,
      groupSecretParams,
      profileKeyCredential,
    );
  }

  createExpiringProfileKeyCredentialPresentationWithRandom(
    random: Uint8Array,
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ExpiringProfileKeyCredential,
  ): ProfileKeyCredentialPresentation {
    return new ProfileKeyCredentialPresentation(
      ReactNativeLibsignalClientModule.serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic(
        this.serverPublicParams.serialized,
        random,
        groupSecretParams.serialized,
        profileKeyCredential.serialized,
      ),
    );
  }
}
