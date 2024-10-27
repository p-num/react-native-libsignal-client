import { ServiceId } from '../../Address';
import GroupSendDerivedKeyPair from './GroupSendDerivedKeyPair';

// For docs
import type GroupSendEndorsement from './GroupSendEndorsement';
import type { VerificationFailedError } from '../../Errors';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';

/**
 * A token representing a particular {@link GroupSendEndorsement}, along with the endorsement's
 * expiration.
 *
 * Generated by {@link GroupSendToken#toFullToken}, and verified by the chat server.
 */
export default class GroupSendFullToken {
    readonly serialized: Uint8Array;

    constructor(contents: Uint8Array) {
        this.serialized = contents;
    }

    /** Gets the expiration embedded in the token. */
    getExpiration(): Date {
        return new Date(
            1000 * ReactNativeLibsignalClientModule.groupSendFullTokenGetExpiration(this.serialized)
        );
    }

    /**
     * Verifies that this token was generated from an endorsement of `userIds` by `keyPair`.
     *
     * The correct `keyPair` must be selected based on {@link #getExpiration}.
     *
     * @throws {VerificationFailedError} if the token is invalid.
     */
    verify(
        userIds: ServiceId[],
        keyPair: GroupSendDerivedKeyPair,
        now: Date = new Date()
    ): void {
        ReactNativeLibsignalClientModule.groupSendFullTokenVerify(
            this.serialized,
            ServiceId.toConcatenatedFixedWidthBinary(userIds),
            Math.floor(now.getTime() / 1000),
            keyPair.serialized
        );
    }
}
