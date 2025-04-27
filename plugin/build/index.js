"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const withCoreLibraryDesugaring_1 = __importDefault(require("./withCoreLibraryDesugaring"));
const withLibSignalClient_1 = __importDefault(require("./withLibSignalClient"));
const withConfig = (config) => {
    let newConfig = (0, withLibSignalClient_1.default)(config);
    newConfig = (0, withCoreLibraryDesugaring_1.default)(newConfig);
    return newConfig;
};
exports.default = withConfig;
