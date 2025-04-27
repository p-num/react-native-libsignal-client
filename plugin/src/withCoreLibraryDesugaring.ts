import { type ConfigPlugin, withAppBuildGradle } from '@expo/config-plugins';

const withCoreLibraryDesugaring: ConfigPlugin = (config) => {
  return withAppBuildGradle(config, async (config) => {
    const androidBlock = 'android {';
    const desugaringBlock = `    compileOptions {
        coreLibraryDesugaringEnabled true
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }`;
    if (config.modResults.contents.includes(androidBlock)) {
      config.modResults.contents = config.modResults.contents.replace(
        androidBlock,
        `${androidBlock}\n${desugaringBlock}`
      );
    }

    const dependenciesBlock = 'dependencies {';
    const implementationLine =
      "    coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:1.1.6'";
    if (config.modResults.contents.includes(dependenciesBlock)) {
      config.modResults.contents = config.modResults.contents.replace(
        dependenciesBlock,
        `${dependenciesBlock}\n${implementationLine}`
      );
    }
    return config;
  });
};

export default withCoreLibraryDesugaring;
