export default class GroupIdentifier {
  readonly contents: Uint8Array;
  static SIZE = 32;

  constructor(contents: Uint8Array) {
    if (contents.length !== GroupIdentifier.SIZE) {
      throw new Error(
        `GroupIdentifier must be ${GroupIdentifier.SIZE} bytes, but was ${contents.length}`
      );
    }

    this.contents = contents;
  }
}
