import * as React from 'react';

import { ReactNativeLibsignalClientViewProps } from './ReactNativeLibsignalClient.types';

export default function ReactNativeLibsignalClientView(props: ReactNativeLibsignalClientViewProps) {
  return (
    <div>
      <span>{props.name}</span>
    </div>
  );
}
