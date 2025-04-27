import { RANDOM_LENGTH } from '../internal/Constants';

import type { Aci, Pni } from '../../Address';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import type ServerPublicParams from '../ServerPublicParams';
import type GroupSecretParams from '../groups/GroupSecretParams';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialWithPni from './AuthCredentialWithPni';
import type AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse';

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
		authCredentialResponse: AuthCredentialWithPniResponse
	): AuthCredentialWithPni {
		return new AuthCredentialWithPni(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverPublicParamsReceiveAuthCredentialWithPniAsServiceId(
					this.serverPublicParams.serialized,
					aci.getServiceIdFixedWidthBinary(),
					pni.getServiceIdFixedWidthBinary(),
					redemptionTime,
					authCredentialResponse.serialized
				)
			)
		);
	}

	createAuthCredentialWithPniPresentation(
		groupSecretParams: GroupSecretParams,
		authCredential: AuthCredentialWithPni
	): AuthCredentialPresentation {
		const random = randomBytes(RANDOM_LENGTH);

		return this.createAuthCredentialWithPniPresentationWithRandom(
			random,
			groupSecretParams,
			authCredential
		);
	}

	createAuthCredentialWithPniPresentationWithRandom(
		random: Uint8Array,
		groupSecretParams: GroupSecretParams,
		authCredential: AuthCredentialWithPni
	): AuthCredentialPresentation {
		return new AuthCredentialPresentation(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic(
					this.serverPublicParams.serialized,
					random,
					groupSecretParams.serialized,
					authCredential.serialized
				)
			)
		);
	}
}
