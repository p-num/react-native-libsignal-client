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
