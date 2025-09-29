import fs from 'node:fs/promises';
import path from 'node:path';
import { type ConfigPlugin, withDangerousMod } from '@expo/config-plugins';

const LIBSIGNAL_POD =
	"  pod 'LibSignalClient', :git => 'https://github.com/signalapp/libsignal.git', :tag => 'v0.70.0'";
const CHECKSUM_LINE =
	"ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] ||= 'e12f6f64eb0ed503c363f3b3830c4c62976cceec04122cd6deee66f5106c482d'";

function ensureUseFrameworks(contents: string) {
	const dynamicLine = 'use_frameworks! :linkage => :dynamic';

	if (contents.includes(dynamicLine)) {
		return contents;
	}

	if (contents.match(/use_frameworks!\s*(?:[:(]|$)/)) {
		return contents.replace(/use_frameworks!.*\n/, `${dynamicLine}\n`);
	}

	const platformLine = contents.match(/platform :ios, .*\n/);
	if (platformLine) {
		return contents.replace(
			platformLine[0],
			`${platformLine[0]}\n${dynamicLine}\n`
		);
	}

	return `${dynamicLine}\n${contents}`;
}

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
	withDangerousMod(config, [
		'ios',
		async (config) => {
			const filePath = path.join(
				config.modRequest.platformProjectRoot,
				'Podfile'
			);
			const contents = await fs.readFile(filePath, 'utf8');
			const next = ensureChecksum(
				ensureLibsignalPod(ensureUseFrameworks(contents))
			);

			if (next !== contents) {
				await fs.writeFile(filePath, next, 'utf8');
			}

			return config;
		},
	]);

export default withLibsignalClient;
