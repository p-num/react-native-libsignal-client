import { type ConfigPlugin, withPodfile } from '@expo/config-plugins';

const LIBSIGNAL_POD =
	"  pod 'LibSignalClient', :git => 'https://github.com/signalapp/libsignal.git', :tag => 'v0.70.0'";
const CHECKSUM_LINE =
	"ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] ||= 'e12f6f64eb0ed503c363f3b3830c4c62976cceec04122cd6deee66f5106c482d'";

function ensureLibsignalPod(contents: string) {
	if (contents.includes("pod 'LibSignalClient'")) {
		return contents;
	}

	const targetMatch = contents.match(/target\s+'[^']+'\s+do/);
	if (targetMatch) {
		return contents.replace(
			targetMatch[0],
			`${targetMatch[0]}\n${LIBSIGNAL_POD}`
		);
	}

	return `${contents.trimEnd()}\n\n${LIBSIGNAL_POD}\n`;
}

function ensureChecksum(contents: string) {
	if (contents.includes('LIBSIGNAL_FFI_PREBUILD_CHECKSUM')) {
		return contents;
	}
	return `${CHECKSUM_LINE}\n${contents}`;
}

const withLibsignalClient: ConfigPlugin = (config) =>
	withPodfile(config, (config) => {
		const { modResults } = config;
		const next = ensureChecksum(ensureLibsignalPod(modResults.contents));
		modResults.contents = next;
		return config;
	});

export default withLibsignalClient;
