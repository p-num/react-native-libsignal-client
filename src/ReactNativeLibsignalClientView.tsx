import { requireNativeViewManager } from 'expo-modules-core';
import * as React from 'react';

import { ReactNativeLibsignalClientViewProps } from './ReactNativeLibsignalClient.types';

const NativeView: React.ComponentType<ReactNativeLibsignalClientViewProps> =
  requireNativeViewManager('ReactNativeLibsignalClient');

export default function ReactNativeLibsignalClientView(props: ReactNativeLibsignalClientViewProps) {
  return <NativeView {...props} />;
}
