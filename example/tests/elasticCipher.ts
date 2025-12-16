import { Buffer } from '@craftzdog/react-native-buffer';
import deepEqual from 'deep-eql';
import {
	CipherType,
	ElasticCipher,
	HashType,
	IncrementalMac,
	ValidatingMac,
	chunkSizeInBytes,
	createHash,
	createHmac,
	encrypt,
} from 'react-native-libsignal-client';
import { assert } from 'typed-assert';
import { test } from './utils';

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

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
		assert(deepEqual(elasticEncrypted, directEncrypted));
	});

	test('CalculatingMac (HMAC-SHA256) incremental matches known vector', () => {
		const key = new Uint8Array(Buffer.from('key', 'utf-8'));
		const msg = new Uint8Array(Buffer.from(TEST_INPUT, 'utf-8'));

		const mac = createHmac(HashType.SHA256, key);
		mac.update(msg.slice(0, 10));
		mac.update(msg.slice(10));
		const digest = mac.digest();

		// HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog")
		const expected =
			'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8';
		assert(deepEqual(bytesToHex(digest), expected));
	});

	test('CalculatingMac (HMAC-SHA512) incremental matches known vector', () => {
		const key = new Uint8Array(Buffer.from('key', 'utf-8'));
		const msg = new Uint8Array(Buffer.from(TEST_INPUT, 'utf-8'));

		const mac = createHmac(HashType.SHA512, key);
		mac.update(msg.slice(0, 13));
		mac.update(msg.slice(13));
		const digest = mac.digest();

		// HMAC-SHA512(key="key", msg="The quick brown fox jumps over the lazy dog")
		const expected =
			'b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a';
		assert(deepEqual(bytesToHex(digest), expected));
	});

	test('IncrementalHash (SHA256) matches known vector', () => {
		const msg = new Uint8Array(Buffer.from(TEST_INPUT, 'utf-8'));
		const h = createHash(HashType.SHA256);
		h.update(msg.slice(0, 7));
		h.update(msg.slice(7));
		const digest = h.digest();

		// SHA256("The quick brown fox jumps over the lazy dog")
		const expected =
			'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592';
		assert(deepEqual(bytesToHex(digest), expected));
	});

	test('IncrementalHash (SHA512) matches known vector', () => {
		const msg = new Uint8Array(Buffer.from(TEST_INPUT, 'utf-8'));
		const h = createHash(HashType.SHA512);
		h.update(msg.slice(0, 5));
		h.update(msg.slice(5));
		const digest = h.digest();

		// SHA512("The quick brown fox jumps over the lazy dog")
		const expected =
			'07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6';
		assert(deepEqual(bytesToHex(digest), expected));
	});

	test('chunkSizeInBytes (infer) matches libsignal defaults', () => {
		assert(
			deepEqual(chunkSizeInBytes({ kind: 'chunksOf', dataSize: 0 }), 64 * 1024)
		);
		assert(
			deepEqual(chunkSizeInBytes({ kind: 'chunksOf', dataSize: 42 }), 64 * 1024)
		);
		assert(
			deepEqual(
				chunkSizeInBytes({ kind: 'chunksOf', dataSize: 1024 }),
				64 * 1024
			)
		);
	});

	test('IncrementalMac (SHA256) digest matches libsignal known vector', () => {
		const key = new Uint8Array(
			Buffer.from(
				'a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98',
				'hex'
			)
		);
		const inputParts = [
			'this is a test',
			' input to the incremental ',
			'mac stream',
		];
		const mac = new IncrementalMac(key, { kind: 'everyN', n: 32 });

		const out: Uint8Array[] = [];
		for (const part of inputParts) {
			out.push(new Uint8Array(mac.update(Buffer.from(part, 'utf-8'))));
		}
		out.push(new Uint8Array(mac.finalize()));

		const digest = new Uint8Array(Buffer.concat(out));
		const expected =
			'84892f70600e549fb72879667a9d96a273f144b698ff9ef5a76062a56061a909884f6d9f42918a9e476ed518c4ac8f714bd33f045152ae049877fd3d1b0db25a';
		assert(deepEqual(bytesToHex(digest), expected));
	});

	test('ValidatingMac validates and returns correct sizes', () => {
		const key = new Uint8Array(
			Buffer.from(
				'a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98',
				'hex'
			)
		);
		const inputParts = [
			'this is a test',
			' input to the incremental ',
			'mac stream',
		];
		const digest = new Uint8Array(
			Buffer.from(
				'84892f70600e549fb72879667a9d96a273f144b698ff9ef5a76062a56061a909884f6d9f42918a9e476ed518c4ac8f714bd33f045152ae049877fd3d1b0db25a',
				'hex'
			)
		);
		const validator = new ValidatingMac(key, { kind: 'everyN', n: 32 }, digest);

		let validatedBytes = 0;
		let totalBytes = 0;
		for (const part of inputParts) {
			const bytes = Buffer.from(part, 'utf-8');
			totalBytes += bytes.length;
			const n = validator.update(bytes);
			// Native returns 0 (no chunk boundary), 32 (validated full chunk), or -1 (failure)
			assert(n === 0 || n === 32);
			validatedBytes += n;
		}
		const remainder = validator.finalize();
		assert(remainder >= 0);
		assert(deepEqual(validatedBytes + remainder, totalBytes));
	});

	test('ValidatingMac fails with a bad digest', () => {
		const key = new Uint8Array(
			Buffer.from(
				'a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98',
				'hex'
			)
		);
		const inputParts = [
			'this is a test',
			' input to the incremental ',
			'mac stream',
		];
		const digest = new Uint8Array(
			Buffer.from(
				'84892f70600e549fb72879667a9d96a273f144b698ff9ef5a76062a56061a909884f6d9f42918a9e476ed518c4ac8f714bd33f045152ae049877fd3d1b0db25a',
				'hex'
			)
		);
		digest[42] ^= 0xff;
		const validator = new ValidatingMac(key, { kind: 'everyN', n: 32 }, digest);

		let failed = false;
		for (const part of inputParts) {
			const n = validator.update(Buffer.from(part, 'utf-8'));
			if (n < 0) {
				failed = true;
				break;
			}
		}
		const finalResult = failed ? -1 : validator.finalize();
		assert(deepEqual(finalResult, -1));
	});
};
