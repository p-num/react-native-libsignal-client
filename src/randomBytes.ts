import ReactNativeLibsignalClientModule from "./ReactNativeLibsignalClientModule";

export function randomBytes(length: number): Uint8Array {
  return ReactNativeLibsignalClientModule.generateRandomBytes(length);
}
