const { withDangerousMod, withPlugins } = require("@expo/config-plugins");
const {
  mergeContents,
} = require("@expo/config-plugins/build/utils/generateCode");
const fs = require("fs");
const path = require("path");

async function readFileAsync(path: any) {
  return fs.promises.readFile(path, "utf8");
}

async function saveFileAsync(path: any, content: any) {
  return fs.promises.writeFile(path, content, "utf8");
}

const withLibSignalClient = (c: any) => {
  return withDangerousMod(c, [
    "ios",
    async (config: any) => {
      const file = path.join(config.modRequest.platformProjectRoot, "Podfile");
      const contents = await readFileAsync(file);

      if (!contents.includes("pod 'LibSignalClient'")) {
        const newContents = contents.replace(
          /target '.*' do/,
          `target '${config.modRequest.projectName}' do\n

          pod 'SignalCoreKit', git: 'https://github.com/signalapp/SignalCoreKit', testspecs: ["Tests"]

          ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] = '188f43a4369a9980c6c116bf9230d26d51ea7baa8a8af93a29ea02376e46ab06'
          pod 'LibSignalClient', git: 'https://github.com/signalapp/libsignal.git', tag: 'v0.51.0', testspecs: ["Tests"]           
           
           `
        );
        await saveFileAsync(file, newContents);
      }

      return config;
    },
  ]);
};

module.exports = (config: any) => withLibSignalClient(config);
