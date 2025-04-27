import { EventEmitter, requireNativeModule } from 'expo-modules-core';

// It loads the native module object from the JSI or falls back to
// the bridge module (from NativeModulesProxy) if the remote debugger is on.
const module = requireNativeModule('ReactNativeLibsignalClient');

const emitter = new EventEmitter(module);

export type RLCSLog = {
  level: string;
  msg: string;
};

export function addLogListener(lf: (l: RLCSLog) => void) {
  emitter.addListener('onLogGenerated', (event) => {
    lf(event as RLCSLog);
  });
}

export default module;
