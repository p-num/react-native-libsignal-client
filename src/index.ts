import { NativeModulesProxy, EventEmitter, Subscription } from 'expo-modules-core';

// Import the native module. On web, it will be resolved to ReactNativeLibsignalClient.web.ts
// and on native platforms to ReactNativeLibsignalClient.ts
import ReactNativeLibsignalClientModule from './ReactNativeLibsignalClientModule';
import ReactNativeLibsignalClientView from './ReactNativeLibsignalClientView';
import { ChangeEventPayload, ReactNativeLibsignalClientViewProps } from './ReactNativeLibsignalClient.types';

// Get the native constant value.
export const PI = ReactNativeLibsignalClientModule.PI;

export function hello(): string {
  return ReactNativeLibsignalClientModule.hello();
}

export async function setValueAsync(value: string) {
  return await ReactNativeLibsignalClientModule.setValueAsync(value);
}

const emitter = new EventEmitter(ReactNativeLibsignalClientModule ?? NativeModulesProxy.ReactNativeLibsignalClient);

export function addChangeListener(listener: (event: ChangeEventPayload) => void): Subscription {
  return emitter.addListener<ChangeEventPayload>('onChange', listener);
}

export { ReactNativeLibsignalClientView, ReactNativeLibsignalClientViewProps, ChangeEventPayload };
