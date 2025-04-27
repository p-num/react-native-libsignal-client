import fs from 'node:fs';
import path from 'node:path';

import { type ConfigPlugin, withDangerousMod } from '@expo/config-plugins';

async function readFileAsync(path: string) {
	return fs.promises.readFile(path, 'utf8');
}
async function saveFileAsync(path: string, content: string) {
	return fs.promises.writeFile(path, content, { encoding: 'utf8' });
}

const withLibSignalClient: ConfigPlugin = (config) => {
	return withDangerousMod(config, [
		'ios',
		async (config) => {
			const filePath = path.join(
				config.modRequest.platformProjectRoot,
				'Podfile'
			);
			const contents = await readFileAsync(filePath);
			const podfile = await readFileAsync(path.join(__dirname, 'Podfile'));

			if (!contents.includes("pod 'LibSignalClient'")) {
				await saveFileAsync(filePath, podfile);
			}
			return config;
		},
	]);
};

export default withLibSignalClient;
