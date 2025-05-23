//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RANDOM_LENGTH } from '../internal/Constants';

import type { Aci, Pni } from '../../Address';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import type ServerSecretParams from '../ServerSecretParams';
import type GroupPublicParams from '../groups/GroupPublicParams';
import type AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse';

export default class ServerZkAuthOperations {
	serverSecretParams: ServerSecretParams;

	constructor(serverSecretParams: ServerSecretParams) {
		this.serverSecretParams = serverSecretParams;
	}

	issueAuthCredentialWithPniAsServiceId(
		aci: Aci,
		pni: Pni,
		redemptionTime: number
	): AuthCredentialWithPniResponse {
		const random = randomBytes(RANDOM_LENGTH);

		return this.issueAuthCredentialWithPniAsServiceIdWithRandom(
			random,
			aci,
			pni,
			redemptionTime
		);
	}

	issueAuthCredentialWithPniAsServiceIdWithRandom(
		random: Uint8Array,
		aci: Aci,
		pni: Pni,
		redemptionTime: number
	): AuthCredentialWithPniResponse {
		return new AuthCredentialWithPniResponse(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic(
					this.serverSecretParams.serialized,
					random,
					aci.getServiceIdFixedWidthBinary(),
					pni.getServiceIdFixedWidthBinary(),
					redemptionTime
				)
			)
		);
	}

	issueAuthCredentialWithPniZkc(
		aci: Aci,
		pni: Pni,
		redemptionTime: number
	): AuthCredentialWithPniResponse {
		const random = randomBytes(RANDOM_LENGTH);

		return this.issueAuthCredentialWithPniZkcWithRandom(
			random,
			aci,
			pni,
			redemptionTime
		);
	}

	issueAuthCredentialWithPniZkcWithRandom(
		random: Uint8Array,
		aci: Aci,
		pni: Pni,
		redemptionTime: number
	): AuthCredentialWithPniResponse {
		return new AuthCredentialWithPniResponse(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic(
					this.serverSecretParams.serialized,
					random,
					aci.getServiceIdFixedWidthBinary(),
					pni.getServiceIdFixedWidthBinary(),
					redemptionTime
				)
			)
		);
	}

	verifyAuthCredentialPresentation(
		groupPublicParams: GroupPublicParams,
		authCredentialPresentation: AuthCredentialPresentation,
		now: Date = new Date()
	): void {
		ReactNativeLibsignalClientModule.serverSecretParamsVerifyAuthCredentialPresentation(
			this.serverSecretParams.serialized,
			groupPublicParams.serialized,
			authCredentialPresentation.serialized,
			Math.floor(now.getTime() / 1000)
		);
	}
}
