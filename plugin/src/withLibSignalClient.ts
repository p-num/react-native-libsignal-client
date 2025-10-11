import { type ConfigPlugin, withPodfile } from '@expo/config-plugins';

export interface LibSignalConfig {
	ios?: {
		libsignalTag?: string;
		libsignalChecksum?: string;
	};
}

const DEFAULT_TAG = 'v0.70.0';
const DEFAULT_CHECKSUM =
	'e12f6f64eb0ed503c363f3b3830c4c62976cceec04122cd6deee66f5106c482d';

function buildPodLine(tag: string) {
	return `  pod 'LibSignalClient', :git => 'https://github.com/signalapp/libsignal.git', :tag => '${tag}'`;
}

function ensureLibsignalPod(contents: string, tag: string) {
	if (contents.includes("pod 'LibSignalClient'")) return contents;

	const line = buildPodLine(tag);
	const targetMatch = contents.match(/target\s+'[^']+'\s+do/);
	if (targetMatch) {
		return contents.replace(targetMatch[0], `${targetMatch[0]}\n${line}`);
	}
	return `${contents.trimEnd()}\n\n${line}\n`;
}

function ensureChecksum(contents: string, checksum: string) {
	if (contents.includes('LIBSIGNAL_FFI_PREBUILD_CHECKSUM')) return contents;
	const line = `ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] ||= '${checksum}'`;
	return `${line}\n${contents}`;
}

const withLibsignalClient: ConfigPlugin<LibSignalConfig | undefined> = (
	config,
	props
) =>
	withPodfile(config, (cfg) => {
		const { modResults } = cfg;

		const tag = props?.ios?.libsignalTag || DEFAULT_TAG;
		const checksum = props?.ios?.libsignalChecksum || DEFAULT_CHECKSUM;

		let next = modResults.contents;
		next = ensureLibsignalPod(next, tag);
		next = ensureChecksum(next, checksum);

		modResults.contents = next;
		return cfg;
	});

export default withLibsignalClient;
