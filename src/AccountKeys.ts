import { type Aci, PrivateKey } from '.';
import ReactNativeLibsignalModule from './ReactNativeLibsignalClientModule';
import { randomBytes } from './randomBytes';

/**
 * The randomly-generated user-memorized entropy used to derive the backup key,
 *    with other possible future uses.
 *
 * Contains log_2(36^64) = ~330 bits of entropy.
 */

// biome-ignore lint/complexity/noStaticOnlyClass: <explanation>
export class AccountEntropyPool {
	/**
	 * Randomly generates an Account Entropy Pool and returns the canonical string
	 *  representation of that pool.
	 *
	 * @returns cryptographically random 64 character string of characters a-z, 0-9
	 */
	public static generate(): string {
		return ReactNativeLibsignalModule.accountEntropyPoolGenerate();
	}

	/**
	 * Checks whether a string can be used as an account entropy pool.
	 *
	 * @returns `true` if the string is a structurally valid account entropy value.
	 */
	public static isValid(accountEntropyPool: string): boolean {
		return ReactNativeLibsignalModule.accountEntropyPoolIsValid(
			accountEntropyPool
		);
	}

	/**
	 * Derives an SVR key from the given account entropy pool.
	 *
	 * `accountEntropyPool` must be a **validated** account entropy pool;
	 * passing an arbitrary string here is considered a programmer error.
	 */
	public static deriveSvrKey(accountEntropyPool: string): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalModule.accountEntropyPoolDeriveSvrKey(
				accountEntropyPool
			)
		);
	}

	/**
	 * Derives a backup key from the given account entropy pool.
	 *
	 * `accountEntropyPool` must be a **validated** account entropy pool;
	 * passing an arbitrary string here is considered a programmer error.
	 *
	 * @see {@link BackupKey.generateRandom}
	 */
	public static deriveBackupKey(accountEntropyPool: string): BackupKey {
		return new BackupKey(
			new Uint8Array(
				ReactNativeLibsignalModule.accountEntropyPoolDeriveBackupKey(
					accountEntropyPool
				)
			)
		);
	}
}

/**
 * A key used for many aspects of backups.
 *
 * Clients are typically concerned with two long-lived keys: a "messages" key (sometimes called "the
 * root backup key" or just "the backup key") that's derived from an {@link AccountEntropyPool}, and
 * a "media" key (formally the "media root backup key") that's not derived from anything else.
 */
export class BackupKey {
	static SIZE = 32;
	serialized: Uint8Array;

	constructor(contents: Uint8Array) {
		// BackupKey.checkLength(BackupKey.SIZE);
		if (contents.length !== BackupKey.SIZE) {
			throw new Error(`BackupKey must be ${BackupKey.SIZE} bytes`);
		}
		this.serialized = contents;
	}

	/**
	 * Generates a random backup key.
	 *
	 * Useful for tests and for the media root backup key, which is not derived from anything else.
	 *
	 * @see {@link AccountEntropyPool.deriveBackupKey}
	 */
	public static generateRandom(): BackupKey {
		const bytes = randomBytes(BackupKey.SIZE);
		return new BackupKey(bytes);
	}

	/**
	 * Derives the backup ID to use given the current device's ACI.
	 *
	 * Used for both message and media backups.
	 */
	public deriveBackupId(aci: Aci): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalModule.backupKeyDeriveBackupId(
				this.serialized,
				aci.getServiceIdFixedWidthBinary()
			)
		);
	}

	/**
	 * Derives the backup EC key to use given the current device's ACI.
	 *
	 * Used for both message and media backups.
	 */
	public deriveEcKey(aci: Aci): PrivateKey {
		return PrivateKey._fromSerialized(
			new Uint8Array(
				ReactNativeLibsignalModule.backupKeyDeriveEcKey(
					this.serialized,
					aci.getServiceIdFixedWidthBinary()
				)
			)
		);
	}

	/**
	 * Derives the AES key used for encrypted fields in local backup metadata.
	 *
	 * Only relevant for message backup keys.
	 */
	public deriveLocalBackupMetadataKey(): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalModule.backupKeyDeriveLocalBackupMetadataKey(
				this.serialized
			)
		);
	}

	/**
	 * Derives the ID for uploading media with the name `mediaName`.
	 *
	 * Only relevant for media backup keys.
	 */
	public deriveMediaId(mediaName: string): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalModule.backupKeyDeriveMediaId(
				this.serialized,
				mediaName
			)
		);
	}

	/**
	 * Derives the composite encryption key for re-encrypting media with the given ID.
	 *
	 * This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
	 *
	 * Only relevant for media backup keys.
	 */
	public deriveMediaEncryptionKey(mediaId: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalModule.backupKeyDeriveMediaEncryptionKey(
				this.serialized,
				mediaId
			)
		);
	}

	/**
	 * Derives the composite encryption key for uploading thumbnails with the given ID to the "transit
	 * tier" CDN.
	 *
	 * This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
	 *
	 * Only relevant for media backup keys.
	 */
	public deriveThumbnailTransitEncryptionKey(mediaId: Uint8Array): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalModule.backupKeyDeriveThumbnailTransitEncryptionKey(
				this.serialized,
				mediaId
			)
		);
	}
}
