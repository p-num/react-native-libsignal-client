import { RANDOM_LENGTH } from '../internal/Constants';

import { type Aci, ServiceId } from '../../Address';
import type ServerPublicParams from '../ServerPublicParams';
import type GroupSecretParams from '../groups/GroupSecretParams';
import UuidCiphertext from '../groups/UuidCiphertext';
import type GroupSendDerivedKeyPair from './GroupSendDerivedKeyPair';
import GroupSendEndorsement from './GroupSendEndorsement';

// For docs
import type { VerificationFailedError } from '../../Errors';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import GroupSendFullToken from './GroupSendFullToken';

/**
 * A collection of endorsements known to be valid.
 *
 * The result of the `receive` operations on {@link GroupSendEndorsementsResponse}. Contains an
 * endorsement for each member of the group, in the same order they were originally provided, plus a
 * combined endorsement for "everyone but me", intended for multi-recipient sends.
 */
export type ReceivedEndorsements = {
  endorsements: GroupSendEndorsement[];
  combinedEndorsement: GroupSendEndorsement;
};

/**
 * A set of endorsements of the members in a group, along with a proof of their validity.
 *
 * Issued by the group server based on the group's member ciphertexts. The endorsements will
 * eventually be verified by the chat server in the form of {@link GroupSendFullToken}s. See
 * {@link GroupSendEndorsement} for a full description of the endorsement flow from the client's
 * perspective.
 */
export default class GroupSendEndorsementsResponse {
  readonly serialized: Uint8Array;

  constructor(contents: Uint8Array) {
    this.serialized = contents;
  }

  /**
   * Issues a new set of endorsements for `groupMembers`.
   *
   * `groupMembers` should include `requestingUser` as well.
   */
  public static issue(
    groupMembers: UuidCiphertext[],
    keyPair: GroupSendDerivedKeyPair
  ): GroupSendEndorsementsResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return GroupSendEndorsementsResponse.issueWithRandom(
      groupMembers,
      keyPair,
      random
    );
  }

  /**
   * Issues a new set of endorsements for `groupMembers`, with an explicity-chosen expiration and
   * source of randomness.
   *
   * Should only be used for testing purposes.
   *
   * @see {@link GroupSendEndorsementsResponse#issue}
   */
  public static issueWithRandom(
    groupMembers: UuidCiphertext[],
    keyPair: GroupSendDerivedKeyPair,
    random: Uint8Array
  ): GroupSendEndorsementsResponse {
    return new GroupSendEndorsementsResponse(
      ReactNativeLibsignalClientModule.groupSendEndorsementsResponseIssueDeterministic(
        UuidCiphertext.serializeAndConcatenate(groupMembers),
        keyPair.serialized,
        random
      )
    );
  }

  /** Returns the expiration for the contained endorsements. */
  getExpiration(): Date {
    return new Date(
      1000 *
        ReactNativeLibsignalClientModule.groupSendEndorsementsResponseGetExpiration(
          this.serialized
        )
    );
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * Note that the `receive` operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, {@link
   * #receiveWithCiphertexts} should be faster; if you don't, this method is faster than generating
   * the ciphertexts and throwing them away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * @throws {VerificationFailedError} if the endorsements are not valid for any reason
   */
  receiveWithServiceIds(
    groupMembers: ServiceId[],
    localUser: Aci,
    groupParams: GroupSecretParams,
    serverParams: ServerPublicParams,
    now: Date = new Date()
  ): ReceivedEndorsements {
    const endorsementContents =
      ReactNativeLibsignalClientModule.groupSendEndorsementsResponseReceiveAndCombineWithServiceIds(
        this.serialized,
        ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
        localUser.getServiceIdFixedWidthBinary(),
        Math.floor(now.getTime() / 1000),
        groupParams.serialized,
        serverParams.serialized
      );
    const endorsements = endorsementContents.map((next) => {
      // Normally we don't notice the cost of validating just-created zkgroup objects,
      // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
      return new GroupSendEndorsement(next);
    });
    const combinedEndorsement = endorsements.pop();
    if (!combinedEndorsement) {
      throw new Error(
        "GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds didn't produce a combined endorsement"
      );
    }
    return { endorsements, combinedEndorsement };
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * Note that the `receive` operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, this
   * method should be faster; if you don't, {@link #receiveWithServiceIds} is faster than generating
   * the ciphertexts and throwing them away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * @throws {VerificationFailedError} if the endorsements are not valid for any reason
   */
  receiveWithCiphertexts(
    groupMembers: UuidCiphertext[],
    localUser: UuidCiphertext,
    serverParams: ServerPublicParams,
    now: Date = new Date()
  ): ReceivedEndorsements {
    const endorsementContents =
      ReactNativeLibsignalClientModule.groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts(
        this.serialized,
        UuidCiphertext.serializeAndConcatenate(groupMembers),
        localUser.serialized,
        Math.floor(now.getTime() / 1000),
        serverParams.serialized
      );
    const endorsements = endorsementContents.map((next) => {
      // Normally we don't notice the cost of validating just-created zkgroup objects,
      // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
      return new GroupSendEndorsement(next);
    });
    const combinedEndorsement = endorsements.pop();
    if (!combinedEndorsement) {
      throw new Error(
        "GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts didn't produce a combined endorsement"
      );
    }
    return { endorsements, combinedEndorsement };
  }
}
