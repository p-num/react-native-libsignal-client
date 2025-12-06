export default class BackupAuthCredentialResponse {
	serialized: Uint8Array;

	constructor(contents: Uint8Array) {
		this.serialized = contents;
	}
}
