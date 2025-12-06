import ReactNativeLibsignalClient from '../src/ReactNativeLibsignalClientModule';
import ElasticCipherModule from './ElasticCipherModule';
import type { CipherType } from './ReactNativeLibsignalClient.types';

export type ElasticCipherMode = 'encrypt' | 'decrypt';
export class ElasticCipher {
	private bridgeHandle: string;

	constructor(
		type: CipherType,
		iv: Uint8Array,
		key: Uint8Array,
		mode?: ElasticCipherMode
	) {
		this.bridgeHandle = ElasticCipherModule.initiateElasticCipher(
			type as string,
			key,
			iv,
			mode ?? 'encrypt'
		);
	}

	update(data: Uint8Array): Uint8Array {
		return new Uint8Array(
			ElasticCipherModule.updateElasticCipher(this.bridgeHandle, data)
		);
	}

	finalize(data?: Uint8Array): Uint8Array {
		return new Uint8Array(
			ElasticCipherModule.finalizeElasticCipher(
				this.bridgeHandle,
				data ?? new Uint8Array()
			)
		);
	}

	destroy() {
		ElasticCipherModule.destroyElasticCipher(this.bridgeHandle);
	}
}
