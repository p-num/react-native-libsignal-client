export default class GroupMasterKey {
    readonly serialized: Uint8Array;
    static SIZE = 32;

    constructor(serialized: Uint8Array) {
        if (serialized.length !== GroupMasterKey.SIZE) {
            throw new Error(`GroupMasterKey must be ${GroupMasterKey.SIZE} bytes, but was ${serialized.length}`);
        }

        this.serialized = serialized;
    }
}
