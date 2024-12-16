import deepEqual from "deep-eql";
import { assert, isInstanceOf } from "typed-assert";
import { Buffer } from "@craftzdog/react-native-buffer";

import { TestStores } from "./mockStores";
import { test } from "./utils";
import {
  ContentHint,
  createAndProcessPreKeyBundle,
  groupDecrypt,
  groupEncrypt,
  PreKeyRecord,
  PrivateKey,
  processSenderKeyDistributionMessage,
  ProtocolAddress,
  sealedSenderDecryptToUsmc,
  sealedSenderMultiRecipientEncrypt,
  sealedSenderMultiRecipientMessageForSingleRecipient,
  SenderCertificate,
  SenderKeyDistributionMessage,
  ServerCertificate,
  ServiceId,
  SignedPreKeyRecord,
  UnidentifiedSenderMessageContent,
} from "../../src";

export const testGroup = () => {
  test("can encrypt and decrypt", async () => {
    const sender = ProtocolAddress.new("sender.1");
    const distributionId = "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6";
    const aSenderKeyStore = new TestStores().sender;
    const skdm = await SenderKeyDistributionMessage.create(
      sender,
      distributionId,
      aSenderKeyStore
    );
    assert(deepEqual(distributionId, skdm.distributionId()));
    assert(deepEqual(0, skdm.iteration()));

    const bSenderKeyStore = new TestStores().sender;
    await processSenderKeyDistributionMessage(sender, skdm, bSenderKeyStore);

    const message = new Uint8Array(Buffer.from("0a0b0c", "hex"));

    const aCtext = await groupEncrypt(
      sender,
      distributionId,
      aSenderKeyStore,
      new Uint8Array(message)
    );

    const bPtext = await groupDecrypt(
      sender,
      bSenderKeyStore,
      aCtext.serialized
    );

    assert(deepEqual(message, bPtext));

    const anotherSkdm = await SenderKeyDistributionMessage.create(
      sender,
      distributionId,
      aSenderKeyStore
    );
    assert(deepEqual(skdm.chainId(), anotherSkdm.chainId()));
    assert(deepEqual(1, anotherSkdm.iteration()));
  });

  test("can encrypt/decrypt group messages", async () => {
    const aKeys = new TestStores().identity;
    const bKeys = new TestStores().identity;

    const aSess = new TestStores().session;

    const bPreK = new TestStores().prekey;
    const bSPreK = new TestStores().signed;

    const bPreKey = PrivateKey.generate();
    const bSPreKey = PrivateKey.generate();

    const aIdentityKey = await aKeys.getIdentityKey();
    const bIdentityKey = await bKeys.getIdentityKey();

    const aE164 = "+14151111111";

    const aDeviceId = 1;
    const bDeviceId = 3;

    const aUuid = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const bUuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f";

    const trustRoot = PrivateKey.generate();
    const serverKey = PrivateKey.generate();

    const serverCert = ServerCertificate.new(
      1,
      serverKey.getPublicKey(),
      trustRoot
    );

    const expires = 1605722925;
    const senderCert = SenderCertificate.new(
      aUuid,
      aE164,
      aDeviceId,
      aIdentityKey.getPublicKey(),
      expires,
      serverCert,
      serverKey
    );

    const bRegistrationId = await bKeys.getLocalRegistrationId();
    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialized
    );
    const bAddress = ProtocolAddress.new(`${bUuid}.${bDeviceId}`);

    const bPreKeyRecord = PreKeyRecord.new(
      bPreKeyId,
      bPreKey.getPublicKey(),
      bPreKey
    );
    await bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

    const bSPreKeyRecord = SignedPreKeyRecord.new(
      bSignedPreKeyId,
      42,
      bSPreKey.getPublicKey(),
      bSPreKey,
      bSignedPreKeySig
    );
    await bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

    createAndProcessPreKeyBundle(
      bRegistrationId,
      bAddress,
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey(),
      aSess,
      aKeys,
      null
    );

    const aAddress = ProtocolAddress.new(`${aUuid}.${aDeviceId}`);

    const distributionId = "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6";
    const aSenderKeyStore = new TestStores().sender;
    const skdm = await SenderKeyDistributionMessage.create(
      aAddress,
      distributionId,
      aSenderKeyStore
    );

    const bSenderKeyStore = new TestStores().sender;
    await processSenderKeyDistributionMessage(aAddress, skdm, bSenderKeyStore);

    const message = new Uint8Array(Buffer.from("0a0b0c", "hex"));

    const aCtext = await groupEncrypt(
      aAddress,
      distributionId,
      aSenderKeyStore,
      new Uint8Array(message)
    );

    const aUsmc = UnidentifiedSenderMessageContent.new(
      aCtext,
      senderCert,
      ContentHint.Implicit,
      new Uint8Array(Buffer.from([42]))
    );

    const aSealedSenderMessage = await sealedSenderMultiRecipientEncrypt(
      aUsmc,
      [bAddress],
      aKeys,
      aSess
    );

    const bSealedSenderMessage =
      sealedSenderMultiRecipientMessageForSingleRecipient(aSealedSenderMessage);

    const bUsmc = await sealedSenderDecryptToUsmc(
      bSealedSenderMessage,
      bKeys,
      bAddress
    );

    assert(deepEqual(bUsmc.senderCertificate().senderE164(), aE164), "sender E164 an calculated certificate E164 were not equal.");
    assert(deepEqual(bUsmc.senderCertificate().senderUuid(), aUuid), "sender certificate uuid is not equal to expected uuid");
    assert(deepEqual(bUsmc.senderCertificate().senderDeviceId(), aDeviceId), "sender certificate device id is not equal to expected device id");
    assert(deepEqual(bUsmc.contentHint(), ContentHint.Implicit), "decrypted content hint is not implicit");
    assert(deepEqual(bUsmc.groupId(), new Uint8Array(Buffer.from([42]))), "group id    missmatch");

    const bPtext = await groupDecrypt(
      aAddress,
      bSenderKeyStore,
      bUsmc.contents()
    );

    assert(deepEqual(message, bPtext));

    // Make sure the option-based syntax does the same thing.
    const aSealedSenderMessageViaOptions =
      await sealedSenderMultiRecipientEncrypt({
        content: aUsmc,
        recipients: [bAddress],
        identityStore: aKeys,
        sessionStore: aSess,
      });

    const bSealedSenderMessageViaOptions =
      sealedSenderMultiRecipientMessageForSingleRecipient(
        aSealedSenderMessageViaOptions
      );

    const bUsmcViaOptions = await sealedSenderDecryptToUsmc(
      bSealedSenderMessageViaOptions,
      bKeys,
      bAddress
    );

    assert(deepEqual(bUsmcViaOptions, bUsmc));
  });

  test("rejects invalid registration IDs", async () => {
    const aKeys = new TestStores().identity;
    const bKeys = new TestStores().identity;

    const aSess = new TestStores().session;

    const bPreKey = PrivateKey.generate();
    const bSPreKey = PrivateKey.generate();

    const aIdentityKey = await aKeys.getIdentityKey();
    const bIdentityKey = await bKeys.getIdentityKey();

    const aE164 = "+14151111111";

    const aDeviceId = 1;
    const bDeviceId = 3;

    const aUuid = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const bUuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f";

    const trustRoot = PrivateKey.generate();
    const serverKey = PrivateKey.generate();

    const serverCert = ServerCertificate.new(
      1,
      serverKey.getPublicKey(),
      trustRoot
    );

    const expires = 1605722925;
    const senderCert = SenderCertificate.new(
      aUuid,
      aE164,
      aDeviceId,
      aIdentityKey.getPublicKey(),
      expires,
      serverCert,
      serverKey
    );

    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialized
    );

    const bAddress = ProtocolAddress.new(`${bUuid}.${bDeviceId}`);
    createAndProcessPreKeyBundle(
      0x4000,
      bAddress,
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey(),
      aSess,
      aKeys,
      null
    );

    const aAddress = ProtocolAddress.new(`${aUuid}.${aDeviceId}`);

    const distributionId = "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6";
    const aSenderKeyStore = new TestStores().sender;
    await SenderKeyDistributionMessage.create(
      aAddress,
      distributionId,
      aSenderKeyStore
    );

    const message = new Uint8Array(Buffer.from("0a0b0c", "hex"));

    const aCtext = await groupEncrypt(
      aAddress,
      distributionId,
      aSenderKeyStore,
      new Uint8Array(message)
    );

    const aUsmc = UnidentifiedSenderMessageContent.new(
      aCtext,
      senderCert,
      ContentHint.Implicit,
      new Uint8Array(Buffer.from([42]))
    );

    try {
      await sealedSenderMultiRecipientEncrypt(aUsmc, [bAddress], aKeys, aSess);
      assert(fail("should have thrown"));
    } catch (e) {
      isInstanceOf(e, Error);
    }
  });

  test("can have excluded recipients", async () => {
    const aKeys = new TestStores().identity;
    const bKeys = new TestStores().identity;

    const aSess = new TestStores().session;

    const bPreKey = PrivateKey.generate();
    const bSPreKey = PrivateKey.generate();

    const aIdentityKey = await aKeys.getIdentityKey();
    const bIdentityKey = await bKeys.getIdentityKey();

    const aE164 = "+14151111111";

    const aDeviceId = 1;
    const bDeviceId = 3;

    const aUuid = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const bUuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f";
    const eUuid = "3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7";
    const mUuid = "5d088142-6fd7-4dbd-af00-fdda1b3ce988";

    const trustRoot = PrivateKey.generate();
    const serverKey = PrivateKey.generate();

    const serverCert = ServerCertificate.new(
      1,
      serverKey.getPublicKey(),
      trustRoot
    );

    const expires = 1605722925;
    const senderCert = SenderCertificate.new(
      aUuid,
      aE164,
      aDeviceId,
      aIdentityKey.getPublicKey(),
      expires,
      serverCert,
      serverKey
    );

    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialized
    );

    const bAddress = ProtocolAddress.new(`${bUuid}.${bDeviceId}`);
    createAndProcessPreKeyBundle(
      0x2000,
      bAddress,
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey(),
      aSess,
      aKeys,
      null
    );

    const aAddress = ProtocolAddress.new(`${aUuid}.${aDeviceId}`);

    const distributionId = "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6";
    const aSenderKeyStore = new TestStores().sender;
    await SenderKeyDistributionMessage.create(
      aAddress,
      distributionId,
      aSenderKeyStore
    );

    const message = new Uint8Array(Buffer.from("0a0b0c", "hex"));

    const aCtext = await groupEncrypt(
      aAddress,
      distributionId,
      aSenderKeyStore,
      new Uint8Array(message)
    );

    const aUsmc = UnidentifiedSenderMessageContent.new(
      aCtext,
      senderCert,
      ContentHint.Implicit,
      new Uint8Array(Buffer.from([42]))
    );

    const aSentMessage = await sealedSenderMultiRecipientEncrypt({
      content: aUsmc,
      recipients: [bAddress],
      excludedRecipients: [
        ServiceId.parseFromServiceIdString(eUuid),
        ServiceId.parseFromServiceIdString(mUuid),
      ],
      identityStore: aKeys,
      sessionStore: aSess,
    });

    // Clients can't directly parse arbitrary SSv2 SentMessages, so just check that it contains
    // the excluded recipient service IDs followed by a device ID of 0.
    const hexEncodedSentMessage = Buffer.from(aSentMessage).toString("hex"); 

    const indexOfE = hexEncodedSentMessage.indexOf(
      Buffer.from(
        ServiceId.parseFromServiceIdString(eUuid)
        .getServiceIdFixedWidthBinary()).toString("hex")
    );
    assert(!deepEqual(indexOfE, -1), "1");
    assert(deepEqual(aSentMessage[indexOfE / 2 + 17], 0), "2");

    const indexOfM = hexEncodedSentMessage.indexOf(
      Buffer.from(ServiceId.parseFromServiceIdString(mUuid)
        .getServiceIdFixedWidthBinary())
        .toString("hex")
    );
    assert(!deepEqual(indexOfM, -1), "3");
    assert(deepEqual(aSentMessage[indexOfM / 2 + 17], 0), "4");
  });
};
