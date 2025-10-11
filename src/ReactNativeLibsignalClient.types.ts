export enum CiphertextMessageType {
	Whisper = 2,
	PreKey = 3,
	SenderKey = 7,
	Plaintext = 8,
}

export enum Direction {
	Sending = 0,
	Receiving = 1,
}

// This enum must be kept in sync with sealed_sender.proto.
export enum ContentHint {
	Default = 0,
	Resendable = 1,
	Implicit = 2,
}

export type Uuid = string;

export enum CipherType {
	AES256CBC = 'AES/CBC/PKCS5Padding',
	AES256GCM = 'AES/GCM/NoPadding',
	AES256CTR = 'AES/CTR/NoPadding',
}

export type EncryptionOptions = {
	key: Uint8Array;
	text: Uint8Array;
	iv: Uint8Array;
	aad?: Uint8Array;
};
