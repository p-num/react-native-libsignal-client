import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import { RANDOM_LENGTH } from '../internal/Constants';
import GroupMasterKey from './GroupMasterKey';
import GroupPublicParams from './GroupPublicParams';

export default class GroupSecretParams {
  readonly serialized: Uint8Array;

  static generate(): GroupSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return GroupSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Uint8Array): GroupSecretParams {
    return new GroupSecretParams(
      new Uint8Array(
        ReactNativeLibsignalClientModule.groupSecretParamsGenerateDeterministic(
          random
        )
      )
    );
  }

  static deriveFromMasterKey(
    groupMasterKey: GroupMasterKey
  ): GroupSecretParams {
    return new GroupSecretParams(
      new Uint8Array(
        ReactNativeLibsignalClientModule.groupSecretParamsDeriveFromMasterKey(
          groupMasterKey.serialized
        )
      )
    );
  }

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getMasterKey(): GroupMasterKey {
    return new GroupMasterKey(
      new Uint8Array(
        ReactNativeLibsignalClientModule.groupSecretParamsGetMasterKey(
          this.serialized
        )
      )
    );
  }

  getPublicParams(): GroupPublicParams {
    return new GroupPublicParams(
      new Uint8Array(
        ReactNativeLibsignalClientModule.groupSecretParamsGetPublicParams(
          this.serialized
        )
      )
    );
  }
}
