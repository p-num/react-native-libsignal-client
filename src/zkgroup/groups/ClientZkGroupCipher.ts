import GroupSecretParams from "./GroupSecretParams";
import ProfileKeyCiphertext from "./ProfileKeyCiphertext";
import UuidCiphertext from "./UuidCiphertext";
import { Aci, ServiceId } from "../../Address";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import { RANDOM_LENGTH } from "../internal/Constants";
import ProfileKey from "../profiles/ProfileKey";

export default class ClientZkGroupCipher {
  groupSecretParams: GroupSecretParams;

  constructor(groupSecretParams: GroupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  encryptServiceId(serviceId: ServiceId): UuidCiphertext {
    return new UuidCiphertext(
      ReactNativeLibsignalClientModule.groupSecretParamsEncryptCiphertext(
        this.groupSecretParams.serialized,
        serviceId.getServiceIdFixedWidthBinary(),
      ),
    );
  }

  decryptServiceId(ciphertext: UuidCiphertext): ServiceId {
    return ServiceId.parseFromServiceIdFixedWidthBinary(
      ReactNativeLibsignalClientModule.groupSecretParamsDecryptServiceId(
        this.groupSecretParams.serialized,
        ciphertext.serialized,
      ),
    );
  }

  encryptProfileKey(profileKey: ProfileKey, userId: Aci): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      ReactNativeLibsignalClientModule.groupSecretParamsEncryptProfileKey(
        this.groupSecretParams.serialized,
        profileKey.serialized,
        userId.getServiceIdFixedWidthBinary(),
      ),
    );
  }

  decryptProfileKey(
    profileKeyCiphertext: ProfileKeyCiphertext,
    userId: Aci,
  ): ProfileKey {
    return new ProfileKey(
      ReactNativeLibsignalClientModule.groupSecretParamsDecryptProfileKey(
        this.groupSecretParams.serialized,
        profileKeyCiphertext.serialized,
        userId.getServiceIdFixedWidthBinary(),
      ),
    );
  }

  encryptBlob(plaintext: Uint8Array ): Uint8Array {
    const random = ReactNativeLibsignalClientModule.generateRandomBytes(RANDOM_LENGTH);

    return this.encryptBlobWithRandom(random, plaintext);
  }

  encryptBlobWithRandom(random: Uint8Array, plaintext: Uint8Array): Uint8Array {
    return ReactNativeLibsignalClientModule.groupSecretParamsEncryptBlobWithPaddingDeterministic(
      this.groupSecretParams.serialized,
      random,
      plaintext,
      0,
    );
  }

  decryptBlob(blobCiphertext: Uint8Array): Uint8Array {
    return ReactNativeLibsignalClientModule.groupSecretParamsDecryptBlobWithPadding(
      this.groupSecretParams.serialized,
      blobCiphertext,
    );
  }
}
