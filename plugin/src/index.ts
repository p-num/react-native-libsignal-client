import type { ConfigPlugin } from 'expo/config-plugins';
import withCoreLibraryDesugaring from './withCoreLibraryDesugaring';
import withLibsignalClient from './withLibSignalClient';

const withConfig: ConfigPlugin = (config) => {
	let newConfig = withLibsignalClient(config);
	newConfig = withCoreLibraryDesugaring(config);
	return newConfig;
};

export default withConfig;
