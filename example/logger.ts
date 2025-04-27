import {
	type configLoggerType,
	consoleTransport,
	logger,
} from 'react-native-logs';
const defaultConfig: configLoggerType = {
	levels: {
		debug: 0,
		log: 1,
		info: 2,
		rootInfo: 3,
		success: 4,
		rootSuccess: 5,
		warn: 6,
		error: 7,
		rootError: 8,
	},
	severity: 'debug',
	transport: consoleTransport,
	transportOptions: {
		colors: {
			success: 'greenBright',
			rootSuccess: 'green',
			info: 'blueBright',
			rootInfo: 'blue',
			warn: 'yellowBright',
			error: 'redBright',
			rootError: 'red',
		},
	},
	async: true,
	dateFormat: 'time',
	printLevel: true,
	printDate: true,
	fixedExtLvlLength: false,
	enabled: true,
};
export const log = logger.createLogger<
	| 'debug'
	| 'log'
	| 'info'
	| 'rootInfo'
	| 'success'
	| 'rootSuccess'
	| 'warn'
	| 'error'
	| 'rootError'
>(defaultConfig);
