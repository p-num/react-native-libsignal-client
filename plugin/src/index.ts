import { type ConfigPlugin, createRunOncePlugin } from '@expo/config-plugins';
import { withBuildProperties } from 'expo-build-properties';
import withCoreLibraryDesugaring from './withCoreLibraryDesugaring';
import withLibsignalClient, {
	type LibSignalConfig,
} from './withLibSignalClient';
import withStaticWorkarounds, {
	type StaticWorkaroundOptions,
} from './withStaticWorkarounds';

export interface LibsignalPluginProps
	extends LibSignalConfig,
		StaticWorkaroundOptions {
	ios?: LibSignalConfig['ios'] &
		StaticWorkaroundOptions['ios'] & {
			frameworkLinkage?: 'static' | 'dynamic';
		};
}

const withReactNativeLibsignalClient: ConfigPlugin<
	LibsignalPluginProps | undefined
> = (config, props) => {
	// LibSignalClient needs dynamic frameworks for correct FFI linking (signal_ffi symbols).
	const linkage = props?.ios?.frameworkLinkage || 'dynamic';

	let newConfig = withBuildProperties(config, {
		ios: { useFrameworks: linkage },
	});

	newConfig = withLibsignalClient(newConfig, props);

	// Always apply static workarounds when using dynamic linkage (and allow user override list).
	if (linkage === 'dynamic') {
		newConfig = withStaticWorkarounds(newConfig, props);
	}

	newConfig = withCoreLibraryDesugaring(newConfig);
	return newConfig;
};

export default createRunOncePlugin(
	withReactNativeLibsignalClient,
	'react-native-libsignal-client'
);
