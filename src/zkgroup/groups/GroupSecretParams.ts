import GroupMasterKey from "./GroupMasterKey";
import GroupPublicParams from "./GroupPublicParams";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import { RANDOM_LENGTH } from "../internal/Constants";
import { randomBytes } from "../../randomBytes";

export default class GroupSecretParams {
  readonly serialized: Uint8Array;

  static generate(): GroupSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return GroupSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Uint8Array): GroupSecretParams {
    return new GroupSecretParams(
      ReactNativeLibsignalClientModule.groupSecretParamsGenerateDeterministic(
        random,
      )
    );
  }

  static deriveFromMasterKey(
    groupMasterKey: GroupMasterKey
  ): GroupSecretParams {
    return new GroupSecretParams(
      ReactNativeLibsignalClientModule.groupSecretParamsDeriveFromMasterKey(groupMasterKey.serialized)
    );
  }

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getMasterKey(): GroupMasterKey {
    return new GroupMasterKey(
      ReactNativeLibsignalClientModule.groupSecretParamsGetMasterKey(this.serialized)
    );
  }

  getPublicParams(): GroupPublicParams {
    return new GroupPublicParams(
      ReactNativeLibsignalClientModule.groupSecretParamsGetPublicParams(this.serialized)
    );
  }
}
