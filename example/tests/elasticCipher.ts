import { Buffer } from '@craftzdog/react-native-buffer';
import deepEqual from 'deep-eql';
import {
	CipherType,
	ElasticCipher,
	encrypt,
} from 'react-native-libsignal-client';
import { test } from './utils';

export const testElasticCipher = () => {
	const TEST_INPUT = 'The quick brown fox jumps over the lazy dog';

	test('elastic cipher works like encrypt', () => {
		const inputBytes = Buffer.from(TEST_INPUT, 'utf-8');
		const key = new Uint8Array(32).fill(1); // Example key (32 bytes for AES-256)
		const iv = new Uint8Array(16).fill(2); // Example IV (16 bytes for AES block size)

		// Encrypt using ElasticCipher
		const elasticCipherInstance = new ElasticCipher(
			CipherType.AES256CBC,
			iv,
			key,
			'encrypt'
		);
		const encryptedPart1 = elasticCipherInstance.update(
			new Uint8Array(inputBytes.slice(0, 20))
		);
		const encryptedPart2 = elasticCipherInstance.update(
			new Uint8Array(inputBytes.slice(20))
		);
		const encryptedFinal = elasticCipherInstance.finalize();
		const elasticEncrypted = new Uint8Array([
			...encryptedPart1,
			...encryptedPart2,
			...encryptedFinal,
		]);

		// Encrypt using ReactNativeLibsignalClientModule directly
		const directEncrypted = encrypt(CipherType.AES256CBC, {
			iv,
			key,
			text: new Uint8Array(inputBytes),
		});

		// Compare results
		deepEqual(elasticEncrypted, directEncrypted);
	});
};
