import ReactNativeLibsignalClient from '../src/ReactNativeLibsignalClientModule';
import type { CipherType } from './ReactNativeLibsignalClient.types';

export class ElasticCipher {
	private bridgeHandle: string;

	constructor(type: CipherType, iv: Uint8Array, key: Uint8Array) {
		this.bridgeHandle = ReactNativeLibsignalClient.initiateElasticCipher(
			type as string,
			key,
			iv
		);
	}

	update(data: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClient.updateElasticCipher(this.bridgeHandle, data)
		);
	}

	finalize(): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClient.finalizeElasticCipher(this.bridgeHandle)
		);
	}
}
