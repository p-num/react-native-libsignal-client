import type { ConfigPlugin } from 'expo/config-plugins';
import withCoreLibraryDesugaring from './withCoreLibraryDesugaring';
import withLibSignalClient from './withLibSignalClient';

const withConfig: ConfigPlugin = (config) => {
  let newConfig = withLibSignalClient(config);
  newConfig = withCoreLibraryDesugaring(newConfig);
  return newConfig;
};

export default withConfig;
