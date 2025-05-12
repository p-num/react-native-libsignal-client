import type { ConfigPlugin } from 'expo/config-plugins';
import withCoreLibraryDesugaring from './withCoreLibraryDesugaring';
import withLibSignalClient from './withLibSignalClient';

const withConfig: ConfigPlugin = (config) => {
	// let newConfig = withLibSignalClient(config);
	const newConfig = withCoreLibraryDesugaring(config);
	return newConfig;
};

export default withConfig;
