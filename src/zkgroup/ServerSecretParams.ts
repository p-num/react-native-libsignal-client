//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ReactNativeLibsignalClientModule from '../ReactNativeLibsignalClientModule';
import { randomBytes } from '../randomBytes';
import NotarySignature from './NotarySignature';
import ServerPublicParams from './ServerPublicParams';
import { RANDOM_LENGTH } from './internal/Constants';

export default class ServerSecretParams {
	readonly serialized: Uint8Array;

	static generate(): ServerSecretParams {
		const random = randomBytes(RANDOM_LENGTH);

		return ServerSecretParams.generateWithRandom(random);
	}

	static generateWithRandom(random: Uint8Array): ServerSecretParams {
		return new ServerSecretParams(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverSecretParamsGenerateDeterministic(
					random
				)
			)
		);
	}

	constructor(contents: Uint8Array | ServerSecretParams) {
		if (contents instanceof Uint8Array) {
			this.serialized = contents;
		} else {
			this.serialized = contents.serialized;
		}
	}

	getPublicParams(): ServerPublicParams {
		return new ServerPublicParams(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverSecretParamsGetPublicParams(
					this.serialized
				)
			)
		);
	}

	sign(message: Uint8Array): NotarySignature {
		const random = randomBytes(RANDOM_LENGTH);

		return this.signWithRandom(random, message);
	}

	signWithRandom(random: Uint8Array, message: Uint8Array): NotarySignature {
		return new NotarySignature(
			new Uint8Array(
				ReactNativeLibsignalClientModule.serverSecretParamsSignDeterministic(
					this.serialized,
					random,
					message
				)
			)
		);
	}
}
