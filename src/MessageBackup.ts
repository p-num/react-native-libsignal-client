import { BackupKey } from './AccountKeys';
import type { Aci } from './Address';
import ReactNativeLibsignalModule from './ReactNativeLibsignalClientModule';

// export type InputStreamFactory = () => InputStream;

/**
 * Result of validating a message backup bundle.
 */
export class ValidationOutcome {
	/**
	 * A developer-facing message about the error encountered during validation,
	 * if any.
	 */
	public errorMessage: string | null;

	/**
	 * Information about unknown fields encountered during validation.
	 */
	public unknownFieldMessages: string[];

	/**
	 * `true` if the backup is valid, `false` otherwise.
	 *
	 * If this is `true`, there might still be messages about unknown fields.
	 */
	public get ok(): boolean {
		return this.errorMessage == null;
	}

	constructor(unknownFieldMessages: Array<string>) {
		this.errorMessage = null;
		this.unknownFieldMessages = unknownFieldMessages;
	}
}

export type MessageBackupKeyInput = Readonly<
	| {
			accountEntropy: string;
			aci: Aci;
	  }
	| {
			backupKey: BackupKey | Uint8Array;
			backupId: Uint8Array;
	  }
>;

/**
 * Key used to encrypt and decrypt a message backup bundle.
 *
 * @see {@link BackupKey}
 */
export class MessageBackupKey {
	serialized: Uint8Array;

	/**
	 * Create a backup bundle key from an account entropy pool and ACI.
	 *
	 * ...or from a backup key and ID, used when reading from a local backup, which may have been
	 * created with a different ACI. This still uses AccountEntropyPool-based key derivation rules; it
	 * cannot be used to read a backup created from a master key.
	 *
	 * The account entropy pool must be **validated**; passing an arbitrary string here is considered
	 * a programmer error. Similarly, passing a backup key or ID of the wrong length is also an error.
	 */
	public constructor(input: MessageBackupKeyInput) {
		if ('accountEntropy' in input) {
			const { accountEntropy, aci } = input;
			this.serialized =
				ReactNativeLibsignalModule.messageBackupKeyFromAccountEntropyPool(
					accountEntropy,
					aci.getServiceIdFixedWidthBinary()
				);
		} else {
			const { backupId } = input;
			let { backupKey } = input;
			if (backupKey instanceof BackupKey) {
				backupKey = backupKey.serialized;
			}
			this.serialized =
				ReactNativeLibsignalModule.messageBackupKeyFromBackupKeyAndBackupId(
					backupKey,
					backupId
				);
		}
	}

	/** An HMAC key used to sign a backup file. */
	public get hmacKey(): Uint8Array {
		return ReactNativeLibsignalModule.messageBackupKeyGetHmacKey(
			this.serialized
		);
	}

	/** An AES-256-CBC key used to encrypt a backup file. */
	public get aesKey(): Uint8Array {
		return ReactNativeLibsignalModule.messageBackupKeyGetAesKey(
			this.serialized
		);
	}
}

// This must match the Rust version of the enum.
export enum Purpose {
	DeviceTransfer = 0,
	RemoteBackup = 1,
}

/**
 * Validate a backup file
 *
 * @param backupKey The key to use to decrypt the backup contents.
 * @param purpose Whether the backup is intended for device-to-device transfer or remote storage.
 * @param filePath The path to the backup file to validate.
 * @param length The exact length of the input stream.
 * @returns The outcome of validation, including any errors and warnings.
 * @throws IoError If an IO error on the input occurs.
 *
 * @see OnlineBackupValidator
 */
export async function validate(
	backupKey: MessageBackupKey,
	purpose: Purpose,
	filePath: string,
	length: number
): Promise<ValidationOutcome> {
	return new ValidationOutcome(
		await ReactNativeLibsignalModule.messageBackupValidatorValidate(
			backupKey.serialized,
			filePath,
			length,
			purpose as number
		)
	);
}

/**
 * An alternative to {@link validate()} that validates a backup frame-by-frame.
 *
 * This is much faster than using `validate()` because it bypasses the decryption and decompression
 * steps, but that also means it's validating less. Don't forget to call `finalize()`!
 *
 * Unlike `validate()`, unknown fields are treated as "soft" errors and logged, rather than
 * collected and returned to the app for processing.
 *
 * # Example
 *
 * ```
 * const validator = new OnlineBackupValidator(
 *     backupInfoProto.serialize(),
 *     Purpose.deviceTransfer)
 * repeat {
 *   // ...generate Frames...
 *   validator.addFrame(frameProto.serialize())
 * }
 * validator.finalize() // don't forget this!
 * ```
 */
export class OnlineBackupValidator {
	bridgeHandle: string;

	/**
	 * Initializes an OnlineBackupValidator from the given BackupInfo protobuf message.
	 *
	 * "Soft" errors will be logged, including unrecognized fields in the protobuf.
	 *
	 * @throws BackupValidationError on error
	 */
	constructor(backupInfo: Uint8Array, purpose: Purpose) {
		this.bridgeHandle = ReactNativeLibsignalModule.onlineBackupValidatorNew(
			backupInfo,
			purpose
		);
	}

	/**
	 * Processes a single Frame protobuf message.
	 *
	 * "Soft" errors will be logged, including unrecognized fields in the protobuf.
	 *
	 * @throws BackupValidationError on error
	 */
	addFrame(frame: Uint8Array): void {
		ReactNativeLibsignalModule.onlineBackupValidatorAddFrame(
			this.bridgeHandle,
			frame
		);
	}

	/**
	 * Marks that a backup is complete, and does any final checks that require whole-file knowledge.
	 *
	 * "Soft" errors will be logged.
	 *
	 * @throws BackupValidationError on error
	 */
	finalize(): void {
		ReactNativeLibsignalModule.onlineBackupValidatorFinalize(this.bridgeHandle);
	}
}

/**
 * An in-memory representation of a backup file used to compare contents.
 *
 * When comparing the contents of two backups:
 *   1. Create a `ComparableBackup` instance for each of the inputs.
 *   2. Check the `unknownFields()` value; if it's not empty, some parts of the
 *      backup weren't parsed and won't be compared.
 *   3. Produce a canonical string for each backup with `comparableString()`.
 *   4. Compare the canonical string representations.
 *
 * The diff of the canonical strings (which may be rather large) will show the
 * differences between the logical content of the input backup files.
 */
export class ComparableBackup {
	private bridgeHandle: string | null;
	private cmpString: string | null = null;
	private uFields: Array<string> | null = null;

	constructor(handle: string) {
		this.bridgeHandle = handle;
	}

	/**
	 * Read an unencrypted backup file into memory for comparison.
	 *
	 * @param purpose Whether the backup is intended for device-to-device transfer or remote storage.
	 * @param input An input stream that reads the backup contents.
	 * @param length The exact length of the input stream.
	 * @returns The in-memory representation.
	 * @throws BackupValidationError If an IO error occurs or the input is invalid.
	 */
	public static async fromUnencrypted(
		purpose: Purpose,
		filePath: string,
		length: number
	): Promise<ComparableBackup> {
		const handle =
			await ReactNativeLibsignalModule.comparableBackupReadUnencrypted(
				filePath,
				length,
				purpose
			);
		return new ComparableBackup(handle);
	}

	private getInfo() {
		if (this.bridgeHandle == null) {
			return;
		}

		const [cmpString, unknownFields] =
			ReactNativeLibsignalModule.comparableBackupGetInfo(this.bridgeHandle);

		this.cmpString = cmpString;
		this.uFields = unknownFields;
		this.bridgeHandle = null;
	}

	/**
	 * Produces a string representation of the contents.
	 *
	 * The returned strings for two backups will be equal if the backups contain
	 * the same logical content. If two backups' strings are not equal, the diff
	 * will show what is different between them.
	 *
	 * @returns a canonical string representation of the backup
	 */
	public comparableString(): string {
		this.getInfo();

		return this.cmpString!;
	}

	/**
	 * Unrecognized protobuf fields present in the backup.
	 *
	 * If this is not empty, some parts of the backup were not recognized and
	 * won't be present in the string representation.
	 */
	public get unknownFields(): Array<string> {
		this.getInfo();

		return this.uFields!;
	}
}
