//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RANDOM_LENGTH } from '../internal/Constants';

import type { Aci } from '../../Address';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import type ServerSecretParams from '../ServerSecretParams';
import type GroupPublicParams from '../groups/GroupPublicParams';
import ExpiringProfileKeyCredentialResponse from './ExpiringProfileKeyCredentialResponse';
import type ProfileKeyCommitment from './ProfileKeyCommitment';
import type ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import type ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';

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
					new Uint8Array(this.serverSecretParams.serialized),
					random,
					new Uint8Array(profileKeyCredentialRequest.serialized),
					userId.getServiceIdFixedWidthBinary(),
					new Uint8Array(profileKeyCommitment.serialized),
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
			new Uint8Array(this.serverSecretParams.serialized),
			new Uint8Array(groupPublicParams.serialized),
			new Uint8Array(profileKeyCredentialPresentation.serialized),
			Math.floor(now.getTime() / 1000)
		);
	}
}
