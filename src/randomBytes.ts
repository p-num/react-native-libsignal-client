import ReactNativeLibsignalClientModule from './ReactNativeLibsignalClientModule';

export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(
    ReactNativeLibsignalClientModule.generateRandomBytes(length)
  );
}
