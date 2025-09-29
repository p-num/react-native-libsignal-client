import { type ConfigPlugin, createRunOncePlugin } from '@expo/config-plugins';
import { withBuildProperties } from 'expo-build-properties';

import withCoreLibraryDesugaring from './withCoreLibraryDesugaring';
import withLibSignalClient from './withLibSignalClient';

const withReactNativeLibsignalClient: ConfigPlugin = (rawConfig) => {
	let config = withBuildProperties(rawConfig, {
		ios: {
			useFrameworks: 'dynamic',
		},
	});
	config = withLibSignalClient(config);
	config = withCoreLibraryDesugaring(config);
	return config;
};

export default createRunOncePlugin(
	withReactNativeLibsignalClient,
	'react-native-libsignal-client'
);
