import ReactNativeLibsignalClientModule from '../ReactNativeLibsignalClientModule';
import { randomBytes } from '../randomBytes';
import GenericServerPublicParams from './GenericServerPublicParams';
import { RANDOM_LENGTH } from './internal/Constants';

export default class GenericServerSecretParams {
	serialized: Uint8Array;

	static generate(): GenericServerSecretParams {
		const random = randomBytes(RANDOM_LENGTH);

		return GenericServerSecretParams.generateWithRandom(random);
	}

	static generateWithRandom(random: Uint8Array): GenericServerSecretParams {
		return new GenericServerSecretParams(
			new Uint8Array(
				ReactNativeLibsignalClientModule.genericServerSecretParamsGenerateDeterministic(
					random
				)
			)
		);
	}

	constructor(contents: Uint8Array) {
		this.serialized = contents;
	}

	getPublicParams(): GenericServerPublicParams {
		return new GenericServerPublicParams(
			new Uint8Array(
				ReactNativeLibsignalClientModule.genericServerSecretParamsGetPublicParams(
					this.serialized
				)
			)
		);
	}
}
