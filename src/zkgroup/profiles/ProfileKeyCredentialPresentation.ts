import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import ProfileKeyCiphertext from '../groups/ProfileKeyCiphertext';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class ProfileKeyCredentialPresentation {
	readonly serialized: Uint8Array;

	constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}

	getUuidCiphertext(): UuidCiphertext {
		return new UuidCiphertext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.profileKeyCredentialPresentationGetUuidCiphertext(
					new Uint8Array(this.serialized)
				)
			)
		);
	}

	getProfileKeyCiphertext(): ProfileKeyCiphertext {
		return new ProfileKeyCiphertext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.profileKeyCredentialPresentationGetProfileKeyCiphertext(
					new Uint8Array(this.serialized)
				)
			)
		);
	}
}
