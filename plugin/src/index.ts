import type { ConfigPlugin } from 'expo/config-plugins';
import withCoreLibraryDesugaring from './withCoreLibraryDesugaring';

const withConfig: ConfigPlugin = (config) => {
	// let newConfig = withLibSignalClient(config);
	const newConfig = withCoreLibraryDesugaring(config);
	return newConfig;
};

export default withConfig;
