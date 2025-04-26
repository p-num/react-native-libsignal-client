"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const config_plugins_1 = require("@expo/config-plugins");
async function readFileAsync(path) {
    return node_fs_1.default.promises.readFile(path, 'utf8');
}
async function saveFileAsync(path, content) {
    return node_fs_1.default.promises.writeFile(path, content, { encoding: 'utf8' });
}
const withLibSignalClient = (config) => {
    return (0, config_plugins_1.withDangerousMod)(config, [
        'ios',
        async (config) => {
            const filePath = node_path_1.default.join(config.modRequest.platformProjectRoot, 'Podfile');
            const contents = await readFileAsync(filePath);
            const podfile = await readFileAsync(node_path_1.default.join(__dirname, 'Podfile'));
            if (!contents.includes("pod 'LibSignalClient'")) {
                await saveFileAsync(filePath, podfile);
            }
            return config;
        },
    ]);
};
exports.default = withLibSignalClient;
