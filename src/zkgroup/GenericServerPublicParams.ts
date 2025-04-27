export default class GenericServerPublicParams {
	readonly serialized: Uint8Array;

	constructor(serialized: Uint8Array) {
		this.serialized = serialized;
	}
}
