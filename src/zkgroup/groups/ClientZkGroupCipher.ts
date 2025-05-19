import { type Aci, ServiceId } from '../../Address';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import { RANDOM_LENGTH } from '../internal/Constants';
import ProfileKey from '../profiles/ProfileKey';
import type GroupSecretParams from './GroupSecretParams';
import ProfileKeyCiphertext from './ProfileKeyCiphertext';
import UuidCiphertext from './UuidCiphertext';

export default class ClientZkGroupCipher {
	groupSecretParams: GroupSecretParams;

	constructor(groupSecretParams: GroupSecretParams) {
		this.groupSecretParams = groupSecretParams;
	}

	encryptServiceId(serviceId: ServiceId): UuidCiphertext {
		return new UuidCiphertext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.groupSecretParamsEncryptCiphertext(
					this.groupSecretParams.serialized,
					serviceId.getServiceIdFixedWidthBinary()
				)
			)
		);
	}

	decryptServiceId(ciphertext: UuidCiphertext): ServiceId {
		return ServiceId.parseFromServiceIdFixedWidthBinary(
			ReactNativeLibsignalClientModule.groupSecretParamsDecryptServiceId(
				this.groupSecretParams.serialized,
				ciphertext.serialized
			)
		);
	}

	encryptProfileKey(profileKey: ProfileKey, userId: Aci): ProfileKeyCiphertext {
		return new ProfileKeyCiphertext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.groupSecretParamsEncryptProfileKey(
					this.groupSecretParams.serialized,
					profileKey.serialized,
					userId.getServiceIdFixedWidthBinary()
				)
			)
		);
	}

	decryptProfileKey(
		profileKeyCiphertext: ProfileKeyCiphertext,
		userId: Aci
	): ProfileKey {
		return new ProfileKey(
			new Uint8Array(
				ReactNativeLibsignalClientModule.groupSecretParamsDecryptProfileKey(
					this.groupSecretParams.serialized,
					profileKeyCiphertext.serialized,
					userId.getServiceIdFixedWidthBinary()
				)
			)
		);
	}

	encryptBlob(plaintext: Uint8Array): Uint8Array {
		const random = randomBytes(RANDOM_LENGTH);

		return this.encryptBlobWithRandom(
			new Uint8Array(random),
			new Uint8Array(plaintext)
		);
	}

	encryptBlobWithRandom(random: Uint8Array, plaintext: Uint8Array): Uint8Array {
		return ReactNativeLibsignalClientModule.groupSecretParamsEncryptBlobWithPaddingDeterministic(
			this.groupSecretParams.serialized,
			random,
			plaintext,
			0
		);
	}

	decryptBlob(blobCiphertext: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.groupSecretParamsDecryptBlobWithPadding(
				new Uint8Array(this.groupSecretParams.serialized),
				new Uint8Array(blobCiphertext)
			)
		);
	}
}
