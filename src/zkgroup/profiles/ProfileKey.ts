import ProfileKeyCommitment from "./ProfileKeyCommitment";
import ProfileKeyVersion from "./ProfileKeyVersion";
import { Aci } from "../../Address";
import ReactNativeLibsignalClientModule from "../../ReactNativeLibsignalClientModule";

export default class ProfileKey {
    readonly serialized: Uint8Array;
    static SIZE = 32;

    constructor(serialized: Uint8Array) {
        if (serialized.length !== ProfileKey.SIZE) {
            throw new Error(`ProfileKey must be ${ProfileKey.SIZE} bytes, but was ${serialized.length}`);
        }

        this.serialized = serialized;
    }

    getCommitment(userId: Aci): ProfileKeyCommitment {
        return new ProfileKeyCommitment(
            ReactNativeLibsignalClientModule.profileKeyGetCommitment(
                this.serialized,
                userId.getServiceIdFixedWidthBinary()
            )
        );
    }

    getProfileKeyVersion(userId: Aci): ProfileKeyVersion {
        return new ProfileKeyVersion(
            ReactNativeLibsignalClientModule.profileKeyGetVersion(
                this.serialized,
                userId.getServiceIdFixedWidthBinary()
            )
        );
    }

    deriveAccessKey(): Uint8Array {
        return ReactNativeLibsignalClientModule.profileKeyDeriveAccessKey(this.serialized);
    }
}
