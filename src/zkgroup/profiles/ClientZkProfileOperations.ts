import type { Aci } from '../../Address';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import type ServerPublicParams from '../ServerPublicParams';
import type GroupSecretParams from '../groups/GroupSecretParams';
import { RANDOM_LENGTH } from '../internal/Constants';
import ExpiringProfileKeyCredential from './ExpiringProfileKeyCredential';
import type ExpiringProfileKeyCredentialResponse from './ExpiringProfileKeyCredentialResponse';
import type ProfileKey from './ProfileKey';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import ProfileKeyCredentialRequestContext from './ProfileKeyCredentialRequestContext';

export default class ClientZkProfileOperations {
	serverPublicParams: ServerPublicParams;

	constructor(serverPublicParams: ServerPublicParams) {
		this.serverPublicParams = serverPublicParams;
	}

	createProfileKeyCredentialRequestContext(
		userId: Aci,
		profileKey: ProfileKey
	): ProfileKeyCredentialRequestContext {
		const random = new Uint8Array(
			ReactNativeLibsignalClientModule.generateRandomBytes(RANDOM_LENGTH)
		);

		return this.createProfileKeyCredentialRequestContextWithRandom(
			random,
			userId,
			profileKey
		);
	}

	createProfileKeyCredentialRequestContextWithRandom(
		random: Uint8Array,
		userId: Aci,
		profileKey: ProfileKey
	): ProfileKeyCredentialRequestContext {
		return new ProfileKeyCredentialRequestContext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic(
					new Uint8Array(this.serverPublicParams.serialized),
					random,
					userId.getServiceIdFixedWidthBinary(),
					new Uint8Array(profileKey.serialized)
				)
			)
		);
	}

	receiveExpiringProfileKeyCredential(
		profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext,
		profileKeyCredentialResponse: ExpiringProfileKeyCredentialResponse,
		now: Date = new Date()
	): ExpiringProfileKeyCredential {
		return new ExpiringProfileKeyCredential(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverPublicParamsReceiveExpiringProfileKeyCredential(
					new Uint8Array(this.serverPublicParams.serialized),
					new Uint8Array(profileKeyCredentialRequestContext.serialized),
					new Uint8Array(profileKeyCredentialResponse.serialized),
					Math.floor(now.getTime() / 1000)
				)
			)
		);
	}

	createExpiringProfileKeyCredentialPresentation(
		groupSecretParams: GroupSecretParams,
		profileKeyCredential: ExpiringProfileKeyCredential
	): ProfileKeyCredentialPresentation {
		const random = new Uint8Array(
			ReactNativeLibsignalClientModule.generateRandomBytes(RANDOM_LENGTH)
		);

		return this.createExpiringProfileKeyCredentialPresentationWithRandom(
			random,
			groupSecretParams,
			profileKeyCredential
		);
	}

	createExpiringProfileKeyCredentialPresentationWithRandom(
		random: Uint8Array,
		groupSecretParams: GroupSecretParams,
		profileKeyCredential: ExpiringProfileKeyCredential
	): ProfileKeyCredentialPresentation {
		return new ProfileKeyCredentialPresentation(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic(
					new Uint8Array(this.serverPublicParams.serialized),
					random,
					new Uint8Array(groupSecretParams.serialized),
					new Uint8Array(profileKeyCredential.serialized)
				)
			)
		);
	}
}
