import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class AuthCredentialPresentation {
	readonly serialized: Uint8Array;

	constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	getUuidCiphertext(): UuidCiphertext {
		return new UuidCiphertext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.authCredentialPresentationGetUuidCiphertext(
					new Uint8Array(this.serialized)
				)
			)
		);
	}

	getPniCiphertext(): UuidCiphertext | null {
		const ciphertextBytes = new Uint8Array(
			ReactNativeLibsignalClientModule.authCredentialPresentationGetPniCiphertext(
				new Uint8Array(this.serialized)
			)
		);
		if (ciphertextBytes === null) {
			return null;
		}
		return new UuidCiphertext(ciphertextBytes);
	}

	getRedemptionTime(): Date {
		return new Date(
			1000 *
				ReactNativeLibsignalClientModule.authCredentialPresentationGetRedemptionTime(
					new Uint8Array(this.serialized)
				)
		);
	}
}
