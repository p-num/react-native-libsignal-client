import type { Aci } from '../../Address';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import ProfileKeyVersion from './ProfileKeyVersion';

export default class ProfileKey {
	readonly serialized: Uint8Array;
	static SIZE = 32;

	constructor(serialized: Uint8Array) {
		if (serialized.length !== ProfileKey.SIZE) {
			throw new Error(
				`ProfileKey must be ${ProfileKey.SIZE} bytes, but was ${serialized.length}`
			);
		}

		this.serialized = serialized;
	}

	getCommitment(userId: Aci): ProfileKeyCommitment {
		return new ProfileKeyCommitment(
			new Uint8Array(
				ReactNativeLibsignalClientModule.profileKeyGetCommitment(
					new Uint8Array(this.serialized),
					userId.getServiceIdFixedWidthBinary()
				)
			)
		);
	}

	getProfileKeyVersion(userId: Aci): ProfileKeyVersion {
		return new ProfileKeyVersion(
			ReactNativeLibsignalClientModule.profileKeyGetVersion(
				new Uint8Array(this.serialized),
				userId.getServiceIdFixedWidthBinary()
			)
		);
	}

	deriveAccessKey(): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.profileKeyDeriveAccessKey(
				new Uint8Array(this.serialized)
			)
		);
	}
}
