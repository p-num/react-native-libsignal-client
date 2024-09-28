//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RANDOM_LENGTH } from "../internal/Constants";

import GroupPublicParams from "../groups/GroupPublicParams";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import ExpiringProfileKeyCredentialResponse from "./ExpiringProfileKeyCredentialResponse";
import ProfileKeyCommitment from "./ProfileKeyCommitment";
import ProfileKeyCredentialPresentation from "./ProfileKeyCredentialPresentation";
import ProfileKeyCredentialRequest from "./ProfileKeyCredentialRequest";
import { Aci } from "../../Address";
import { randomBytes } from "../../randomBytes";
import ServerSecretParams from "../ServerSecretParams";

export default class ServerZkProfileOperations {
  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueExpiringProfileKeyCredential(
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    userId: Aci,
    profileKeyCommitment: ProfileKeyCommitment,
    expirationInSeconds: number
  ): ExpiringProfileKeyCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueExpiringProfileKeyCredentialWithRandom(
      random,
      profileKeyCredentialRequest,
      userId,
      profileKeyCommitment,
      expirationInSeconds
    );
  }

  issueExpiringProfileKeyCredentialWithRandom(
    random: Uint8Array,
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    userId: Aci,
    profileKeyCommitment: ProfileKeyCommitment,
    expirationInSeconds: number
  ): ExpiringProfileKeyCredentialResponse {
    return new ExpiringProfileKeyCredentialResponse(
      new Uint8Array(
        ReactNativeLibsignalClientModule.serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic(
          this.serverSecretParams.serialized,
          random,
          profileKeyCredentialRequest.serialized,
          userId.getServiceIdFixedWidthBinary(),
          profileKeyCommitment.serialized,
          expirationInSeconds
        )
      )
    );
  }

  verifyProfileKeyCredentialPresentation(
    groupPublicParams: GroupPublicParams,
    profileKeyCredentialPresentation: ProfileKeyCredentialPresentation,
    now: Date = new Date()
  ): void {
    ReactNativeLibsignalClientModule.serverSecretParamsVerifyProfileKeyCredentialPresentation(
      this.serverSecretParams.serialized,
      groupPublicParams.serialized,
      profileKeyCredentialPresentation.serialized,
      Math.floor(now.getTime() / 1000)
    );
  }
}
