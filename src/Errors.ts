import { ProtocolAddress } from '.';

export enum ErrorCode {
	Generic = 0,

	DuplicatedMessage = 1,
	SealedSenderSelfSend = 2,
	UntrustedIdentity = 3,
	InvalidRegistrationId = 4,
	VerificationFailed = 5,
	InvalidSession = 6,
	InvalidSenderKeySession = 7,

	NicknameCannotBeEmpty = 8,
	CannotStartWithDigit = 9,
	MissingSeparator = 10,
	BadNicknameCharacter = 11,
	NicknameTooShort = 12,
	NicknameTooLong = 13,
	DiscriminatorCannotBeEmpty = 14,
	DiscriminatorCannotBeZero = 15,
	DiscriminatorCannotBeSingleDigit = 16,
	DiscriminatorCannotHaveLeadingZeros = 17,
	BadDiscriminatorCharacter = 18,
	DiscriminatorTooLarge = 19,

	IoError = 20,
	CdsiInvalidToken = 21,
	InvalidUri = 22,

	InvalidMediaInput = 23,
	UnsupportedMediaInput = 24,

	InputDataTooLong = 25,
	InvalidEntropyDataLength = 26,
	InvalidUsernameLinkEncryptedData = 27,

	RateLimitedError = 28,

	SvrDataMissing = 29,
	SvrRequestFailed = 30,
	SvrRestoreFailed = 31,

	ChatServiceInactive = 32,
}

export class LibSignalErrorBase extends Error {
	public readonly code: ErrorCode;
	public readonly operation: string;
	readonly _addr?: string;

	constructor(
		message: string,
		name: keyof typeof ErrorCode | undefined,
		operation: string,
		extraProps?: Record<string, unknown>
	) {
		super(message);
		// Include the dynamic check for `name in ErrorCode` in case there's a bug in the Rust code.
		if (name !== undefined && name in ErrorCode) {
			this.name = name;
			this.code = ErrorCode[name];
		} else {
			this.name = 'LibSignalError';
			this.code = ErrorCode.Generic;
		}
		this.operation = operation;
		if (extraProps !== undefined) {
			Object.assign(this, extraProps);
		}

		// Maintains proper stack trace, where our error was thrown (only available on V8)
		//   via https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error
		// if (Error.captureStackTrace) {
		// 	Error.captureStackTrace(this);
		// }
	}

	public get addr(): ProtocolAddress | string {
		switch (this.code) {
			case ErrorCode.UntrustedIdentity:
				return this._addr as string;
			case ErrorCode.InvalidRegistrationId:
				return ProtocolAddress.new(this._addr as string);
			default:
				throw new TypeError(`cannot get address from this error (${this})`);
		}
	}
}

export type LibSignalErrorCommon = Omit<LibSignalErrorBase, 'addr'>;

export type GenericError = LibSignalErrorCommon & {
	code: ErrorCode.Generic;
};

export type DuplicatedMessageError = LibSignalErrorCommon & {
	code: ErrorCode.DuplicatedMessage;
};

export type SealedSenderSelfSendError = LibSignalErrorCommon & {
	code: ErrorCode.SealedSenderSelfSend;
};

export type UntrustedIdentityError = LibSignalErrorCommon & {
	code: ErrorCode.UntrustedIdentity;
	addr: string;
};

export type InvalidRegistrationIdError = LibSignalErrorCommon & {
	code: ErrorCode.InvalidRegistrationId;
	addr: ProtocolAddress;
};

export type VerificationFailedError = LibSignalErrorCommon & {
	code: ErrorCode.VerificationFailed;
};

export type InvalidSessionError = LibSignalErrorCommon & {
	code: ErrorCode.InvalidSession;
};

export type InvalidSenderKeySessionError = LibSignalErrorCommon & {
	code: ErrorCode.InvalidSenderKeySession;
	distributionId: string;
};

export type NicknameCannotBeEmptyError = LibSignalErrorCommon & {
	code: ErrorCode.NicknameCannotBeEmpty;
};
export type CannotStartWithDigitError = LibSignalErrorCommon & {
	code: ErrorCode.CannotStartWithDigit;
};
export type MissingSeparatorError = LibSignalErrorCommon & {
	code: ErrorCode.MissingSeparator;
};

export type BadNicknameCharacterError = LibSignalErrorCommon & {
	code: ErrorCode.BadNicknameCharacter;
};

export type NicknameTooShortError = LibSignalErrorCommon & {
	code: ErrorCode.NicknameTooShort;
};

export type NicknameTooLongError = LibSignalErrorCommon & {
	code: ErrorCode.NicknameTooLong;
};

export type DiscriminatorCannotBeEmptyError = LibSignalErrorCommon & {
	code: ErrorCode.DiscriminatorCannotBeEmpty;
};
export type DiscriminatorCannotBeZeroError = LibSignalErrorCommon & {
	code: ErrorCode.DiscriminatorCannotBeZero;
};
export type DiscriminatorCannotBeSingleDigitError = LibSignalErrorCommon & {
	code: ErrorCode.DiscriminatorCannotBeSingleDigit;
};
export type DiscriminatorCannotHaveLeadingZerosError = LibSignalErrorCommon & {
	code: ErrorCode.DiscriminatorCannotHaveLeadingZeros;
};
export type BadDiscriminatorCharacterError = LibSignalErrorCommon & {
	code: ErrorCode.BadDiscriminatorCharacter;
};
export type DiscriminatorTooLargeError = LibSignalErrorCommon & {
	code: ErrorCode.DiscriminatorTooLarge;
};

export type InputDataTooLong = LibSignalErrorCommon & {
	code: ErrorCode.InputDataTooLong;
};

export type InvalidEntropyDataLength = LibSignalErrorCommon & {
	code: ErrorCode.InvalidEntropyDataLength;
};

export type InvalidUsernameLinkEncryptedData = LibSignalErrorCommon & {
	code: ErrorCode.InvalidUsernameLinkEncryptedData;
};

export type IoError = LibSignalErrorCommon & {
	code: ErrorCode.IoError;
};

export type CdsiInvalidTokenError = LibSignalErrorCommon & {
	code: ErrorCode.CdsiInvalidToken;
};

export type InvalidUriError = LibSignalErrorCommon & {
	code: ErrorCode.InvalidUri;
};

export type InvalidMediaInputError = LibSignalErrorCommon & {
	code: ErrorCode.InvalidMediaInput;
};

export type UnsupportedMediaInputError = LibSignalErrorCommon & {
	code: ErrorCode.UnsupportedMediaInput;
};

export type RateLimitedError = LibSignalErrorBase & {
	code: ErrorCode.RateLimitedError;
	readonly retryAfterSecs: number;
};

export type ChatServiceInactive = LibSignalErrorBase & {
	code: ErrorCode.ChatServiceInactive;
};

export type SvrDataMissingError = LibSignalErrorBase & {
	code: ErrorCode.SvrDataMissing;
};

export type SvrRequestFailedError = LibSignalErrorCommon & {
	code: ErrorCode.SvrRequestFailed;
};

export type SvrRestoreFailedError = LibSignalErrorCommon & {
	code: ErrorCode.SvrRestoreFailed;
};

export type LibSignalError =
	| GenericError
	| DuplicatedMessageError
	| SealedSenderSelfSendError
	| UntrustedIdentityError
	| InvalidRegistrationIdError
	| VerificationFailedError
	| InvalidSessionError
	| InvalidSenderKeySessionError
	| NicknameCannotBeEmptyError
	| CannotStartWithDigitError
	| MissingSeparatorError
	| BadNicknameCharacterError
	| NicknameTooShortError
	| NicknameTooLongError
	| DiscriminatorCannotBeEmptyError
	| DiscriminatorCannotBeZeroError
	| DiscriminatorCannotBeSingleDigitError
	| DiscriminatorCannotHaveLeadingZerosError
	| BadDiscriminatorCharacterError
	| DiscriminatorTooLargeError
	| InputDataTooLong
	| InvalidEntropyDataLength
	| InvalidUsernameLinkEncryptedData
	| IoError
	| CdsiInvalidTokenError
	| InvalidUriError
	| InvalidMediaInputError
	| SvrDataMissingError
	| SvrRestoreFailedError
	| SvrRequestFailedError
	| UnsupportedMediaInputError
	| ChatServiceInactive;
