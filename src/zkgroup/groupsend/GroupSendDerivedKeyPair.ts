import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import ServerSecretParams from '../ServerSecretParams';

// For docs
import type GroupSendEndorsementsResponse from './GroupSendEndorsementsResponse';

/**
 * The key pair used to issue and verify group send endorsements.
 *
 * Group send endorsements use a different key pair depending on the endorsement's expiration (but
 * not the user ID being endorsed). The server may cache these keys to avoid the (small) cost of
 * deriving them from the root key in {@link ServerSecretParams}. The key object stores the
 * expiration so that it doesn't need to be provided again when issuing endorsements.
 *
 * @see {@link GroupSendEndorsementsResponse.issue}
 * @see {@link GroupSendFullToken#verify}
 */
export default class GroupSendDerivedKeyPair {
    readonly serialized: Uint8Array;

    constructor(contents: Uint8Array) {
        this.serialized = contents
    }

    /**
     * Derives a new key for group send endorsements that expire at `expiration`.
     *
     * `expiration` must be day-aligned as a protection against fingerprinting by the issuing server.
     */
    public static forExpiration(
        expiration: Date,
        params: ServerSecretParams
    ): GroupSendDerivedKeyPair {
        return new GroupSendDerivedKeyPair(
            new Uint8Array(
                ReactNativeLibsignalClientModule.groupSendDerivedKeyPairForExpiration(
                    Math.floor(expiration.getTime() / 1000),
                    params.serialized
                )
            )
        );
    }
}
