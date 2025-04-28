import { Buffer } from '@craftzdog/react-native-buffer';

export default class ProfileKeyVersion {
	readonly serialized: Uint8Array;
	static SIZE = 64;

	constructor(serialized: Uint8Array | string) {
		if (serialized.length !== ProfileKeyVersion.SIZE) {
			throw new Error(
				`ProfileKeyVersion must be ${ProfileKeyVersion.SIZE} bytes, but was ${serialized.length}`
			);
		}

		this.serialized =
			typeof serialized === 'string'
				? Uint8Array.from(
						Array.from(serialized).map((letter) => letter.charCodeAt(0))
					)
				: serialized;
	}

	toString(): string {
		return Buffer.from(this.serialized).toString('utf-8');
	}
}
