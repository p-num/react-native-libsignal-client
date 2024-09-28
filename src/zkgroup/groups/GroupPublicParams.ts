import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";
import GroupIdentifier from "./GroupIdentifier";

export default class GroupPublicParams {
  readonly serialized: Uint8Array;

  constructor(serialized: Uint8Array) {
    this.serialized = serialized;
  }

  getGroupIdentifier(): GroupIdentifier {
    return new GroupIdentifier(
      new Uint8Array(
        ReactNativeLibsignalClientModule.groupPublicParamsGetGroupIdentifier(
          this.serialized
        )
      )
    );
  }
}
