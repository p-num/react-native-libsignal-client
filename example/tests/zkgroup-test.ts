import { Buffer } from "@craftzdog/react-native-buffer";
import { test } from "./utils";
import { Aci, Pni } from "../../src";
import { ClientZkAuthOperations, ClientZkGroupCipher, GroupMasterKey, GroupSecretParams, ServerZkProfileOperations, ServerZkAuthOperations, ServerSecretParams, ClientZkProfileOperations, ProfileKey } from "../../src/zkgroup";
import { assert } from "typed-assert";
import deepEqual from "deep-eql";
import { throwsSync } from "./extentions";

const SECONDS_PER_DAY = 86400;

function hexToBuffer(hex: string) {
    return new Uint8Array(Buffer.from(hex, 'hex'));
}

export const testZkGroup = () => {
    const TEST_UUID = 'dc249e7a-56ea-49cd-abce-aa3a0d65f6f0';
    const TEST_UUID_1 = '18c7e848-2213-40c1-bd6b-3b69a82dd1f5';
    const TEST_ARRAY_32 = hexToBuffer(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    );
    const TEST_ARRAY_32_1 = hexToBuffer(
        '6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283'
    );
    const TEST_ARRAY_32_2 = hexToBuffer(
        'c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7'
    );
    const TEST_ARRAY_32_3 = new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ]);
    const TEST_ARRAY_32_4 = new Uint8Array([
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
    ]);
    const TEST_ARRAY_32_5 = hexToBuffer(
        '030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122'
    );
    test("Test auth with pni integration", async () => {
        const aci = Aci.fromUuid(TEST_UUID);
        const pni = Pni.fromUuid(TEST_UUID_1);
        const redemptionTime = 123456 * SECONDS_PER_DAY;
        
        // Generate keys (client's are per-group, server's are not)
        // ---
        
        // SERVER
        const serverSecretParams =
        ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
        const serverPublicParams = serverSecretParams.getPublicParams();
        const serverZkAuth = new ServerZkAuthOperations(serverSecretParams);
        
        // CLIENT
        const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
        const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

        assert(deepEqual(
            groupSecretParams.getMasterKey().serialized,
            masterKey.serialized
        ), "Group secret params is not equal to master key");

        const groupPublicParams = groupSecretParams.getPublicParams();

        // SERVER
        // Issue credential
        const authCredentialResponse =
            serverZkAuth.issueAuthCredentialWithPniAsServiceIdWithRandom(
                TEST_ARRAY_32_2,
                aci,
                pni,
                redemptionTime
            );
    
            
        // CLIENT
        // Receive credential
        const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
        const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
        const authCredential =
        clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(
            aci,
            pni,
            redemptionTime,
            authCredentialResponse
        );

        // Create and decrypt user entry
        const aciCiphertext = clientZkGroupCipher.encryptServiceId(aci);
        const aciPlaintext = clientZkGroupCipher.decryptServiceId(aciCiphertext);
        assert(aci.isEqual(aciPlaintext));
        const pniCiphertext = clientZkGroupCipher.encryptServiceId(pni);
        const pniPlaintext = clientZkGroupCipher.decryptServiceId(pniCiphertext);
        assert(pni.isEqual(pniPlaintext));

        // Create presentation
        const presentation =
        clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
            TEST_ARRAY_32_5,
            groupSecretParams,
            authCredential
        );

        // Verify presentation
        assert(deepEqual(
            aciCiphertext.serialized,
            presentation.getUuidCiphertext().serialized)
        );
        const presentationPniCiphertext = presentation.getPniCiphertext();
        // Use a generic assertion instead of assert.isNotNull because TypeScript understands it.
        assert(presentationPniCiphertext !== null);
        assert(deepEqual(
            pniCiphertext.serialized,
            presentationPniCiphertext?.serialized)
        );
        assert(deepEqual(
            presentation.getRedemptionTime(),
            new Date(1000 * redemptionTime))
        );

        serverZkAuth.verifyAuthCredentialPresentation(
            groupPublicParams,
            presentation,
            new Date(1000 * redemptionTime)
        );
    })

    test("Test Auth Zkc Integration", async () => {
        const aci = Aci.fromUuid(TEST_UUID);
        const pni = Pni.fromUuid(TEST_UUID_1);
        const redemptionTime = 123456 * SECONDS_PER_DAY;

        // Generate keys (client's are per-group, server's are not)
        // ---

        // SERVER
        const serverSecretParams =
        ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
        const serverPublicParams = serverSecretParams.getPublicParams();
        const serverZkAuth = new ServerZkAuthOperations(serverSecretParams);

        // CLIENT
        const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
        const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

        assert(deepEqual(
            groupSecretParams.getMasterKey().serialized,
            masterKey.serialized)
            );

        const groupPublicParams = groupSecretParams.getPublicParams();

        // SERVER
        // Issue credential
        const authCredentialResponse =
        serverZkAuth.issueAuthCredentialWithPniZkcWithRandom(
            TEST_ARRAY_32_2,
            aci,
            pni,
            redemptionTime
        );

        // CLIENT
        // Receive credential
        const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
        const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
        const authCredential =
        clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(
            aci,
            pni,
            redemptionTime,
            authCredentialResponse
        );

        // Create and decrypt user entry
        const aciCiphertext = clientZkGroupCipher.encryptServiceId(aci);
        const aciPlaintext = clientZkGroupCipher.decryptServiceId(aciCiphertext);
        assert(aci.isEqual(aciPlaintext));
        const pniCiphertext = clientZkGroupCipher.encryptServiceId(pni);
        const pniPlaintext = clientZkGroupCipher.decryptServiceId(pniCiphertext);
        assert(pni.isEqual(pniPlaintext));

        // Create presentation
        const presentation =
        clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
            TEST_ARRAY_32_5,
            groupSecretParams,
            authCredential
        );

        // Verify presentation
        assert(deepEqual(
            aciCiphertext.serialized,
            presentation.getUuidCiphertext().serialized)
        );
        const presentationPniCiphertext = presentation.getPniCiphertext();
        // Use a generic assertion instead of assert.isNotNull because TypeScript understands it.
        assert(presentationPniCiphertext !== null);
        assert(deepEqual(
            pniCiphertext.serialized,
            presentationPniCiphertext?.serialized)
        );
        assert(deepEqual(
            presentation.getRedemptionTime(),
            new Date(1000 * redemptionTime))
        );

        serverZkAuth.verifyAuthCredentialPresentation(
            groupPublicParams,
            presentation,
            new Date(1000 * redemptionTime)
        );
    })

    test("Test expiring profile key integration", () => {
        const userId = Aci.fromUuid(TEST_UUID);

        // Generate keys (client's are per-group, server's are not)
        // ---

        // SERVER
        const serverSecretParams =
        ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
        const serverPublicParams = serverSecretParams.getPublicParams();
        const serverZkProfile = new ServerZkProfileOperations(serverSecretParams);

        // CLIENT
        const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
        const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

        const groupPublicParams = groupSecretParams.getPublicParams();
        const clientZkProfileCipher = new ClientZkProfileOperations(
        serverPublicParams
        );

        const profileKey = new ProfileKey(TEST_ARRAY_32_1);
        const profileKeyCommitment = profileKey.getCommitment(userId);

        // Create context and request
        const context = clientZkProfileCipher.createProfileKeyCredentialRequestContextWithRandom(
            TEST_ARRAY_32_3,
            userId,
            profileKey
        );
        const request = context.getRequest();

        // SERVER
        const now = Math.floor(Date.now() / 1000);
        const startOfDay = now - (now % SECONDS_PER_DAY);
        const expiration = startOfDay + 5 * SECONDS_PER_DAY;
        const response =
        serverZkProfile.issueExpiringProfileKeyCredentialWithRandom(
            TEST_ARRAY_32_4,
            request,
            userId,
            profileKeyCommitment,
            expiration
        );

        // CLIENT
        // Gets stored profile credential
        const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
        const profileKeyCredential =
        clientZkProfileCipher.receiveExpiringProfileKeyCredential(
            context,
            response
        );

        // Create encrypted UID and profile key
        const uuidCiphertext = clientZkGroupCipher.encryptServiceId(userId);
        const plaintext = clientZkGroupCipher.decryptServiceId(uuidCiphertext);
        assert(plaintext.isEqual(userId));

        const profileKeyCiphertext = clientZkGroupCipher.encryptProfileKey(
        profileKey,
        userId
        );
        const decryptedProfileKey = clientZkGroupCipher.decryptProfileKey(
        profileKeyCiphertext,
        userId
        );
        assert(deepEqual(profileKey.serialized, decryptedProfileKey.serialized));
        assert(deepEqual(
            profileKeyCredential.getExpirationTime(),
            new Date(expiration * 1000)
        ));

        const presentation =
        clientZkProfileCipher.createExpiringProfileKeyCredentialPresentationWithRandom(
            TEST_ARRAY_32_5,
            groupSecretParams,
            profileKeyCredential
        );

        // Verify presentation
        serverZkProfile.verifyProfileKeyCredentialPresentation(
        groupPublicParams,
        presentation
        );
        serverZkProfile.verifyProfileKeyCredentialPresentation(
        groupPublicParams,
        presentation,
        new Date(expiration * 1000 - 5)
        );
        const uuidCiphertextRecv = presentation.getUuidCiphertext();
        assert(deepEqual(
            uuidCiphertext.serialized,
            uuidCiphertextRecv.serialized
        ));

        // Test expiration
        assert(throwsSync(() =>
            serverZkProfile.verifyProfileKeyCredentialPresentation(
                groupPublicParams,
                presentation,
                new Date(expiration * 1000)
            )
        ));
        assert(throwsSync(() =>
            serverZkProfile.verifyProfileKeyCredentialPresentation(
                groupPublicParams,
                presentation,
                new Date(expiration * 1000 + 5)
            )
        ));
    })

    // test("Test server signatures", async () => {
    //     const serverSecretParams =
    //         ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    //     const serverPublicParams = serverSecretParams.getPublicParams();

    //     const message = TEST_ARRAY_32_1;

    //     const signature = serverSecretParams.signWithRandom(
    //         TEST_ARRAY_32_2,
    //         message
    //     );
    //     serverPublicParams.verifySignature(message, signature);
    //     assert(deepEqual(
    //         new Uint8Array(Buffer.from('87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06', 'base64')),
    //         signature.serialized
    //     ));
        
    //     const alteredMessage = new Uint8Array(Buffer.from(message));
    //     alteredMessage[0] ^= 1;

    //     assert(!deepEqual(message, alteredMessage));

    //     try {
    //         serverPublicParams.verifySignature(alteredMessage, signature);
    //         assert(fail('signature validation should have failed!'));
    //     } catch (error) {
    //     // good
    //     }
    // })

    test('Test Blob Encryption', () => {
        const groupSecretParams = GroupSecretParams.generate();
        const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

        const plaintext = new Uint8Array(Buffer.from([0, 1, 2, 3, 4]));
        const ciphertext = clientZkGroupCipher.encryptBlob(plaintext);
        const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
        assert(deepEqual(plaintext, plaintext2));
    });

    test('Test Derive Profile Key', () => {
        const expectedAccessKey = hexToBuffer('5a723acee52c5ea02b92a3a360c09595');
        const profileKey = new Uint8Array(Buffer.alloc(32, 0x02));
    
        const result = new ProfileKey(profileKey).deriveAccessKey();
        assert(deepEqual(expectedAccessKey, result));
    });

    
}
