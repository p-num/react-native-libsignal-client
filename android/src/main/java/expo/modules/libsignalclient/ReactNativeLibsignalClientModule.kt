package expo.modules.libsignalclient

import android.app.Service
import android.app.slice.Slice
import android.provider.Settings.Secure
import android.util.Base64
import android.view.accessibility.AccessibilityNodeInfo.CollectionInfo
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.signal.libsignal.metadata.SealedSessionCipher
import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.signal.libsignal.metadata.certificate.InvalidCertificateException
import org.signal.libsignal.metadata.certificate.SenderCertificate
import org.signal.libsignal.metadata.certificate.ServerCertificate
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.protocol.ServiceId.Pni
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.GroupSessionBuilder
import org.signal.libsignal.protocol.groups.state.InMemorySenderKeyStore
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.kdf.HKDF
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.DecryptionErrorMessage
import org.signal.libsignal.protocol.message.PlaintextContent
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SenderKeyDistributionMessage
import org.signal.libsignal.protocol.message.SenderKeyMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.util.KeyHelper
import org.signal.libsignal.zkgroup.NotarySignature
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.ServerSecretParams
import org.signal.libsignal.zkgroup.VerificationFailedException
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher
import org.signal.libsignal.zkgroup.groups.GroupMasterKey
import org.signal.libsignal.zkgroup.groups.GroupPublicParams
import org.signal.libsignal.zkgroup.groups.GroupSecretParams
import org.signal.libsignal.zkgroup.groups.ProfileKeyCiphertext
import org.signal.libsignal.zkgroup.groups.UuidCiphertext
import org.signal.libsignal.zkgroup.groupsend.GroupSendDerivedKeyPair
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsement
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsementsResponse
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken
import org.signal.libsignal.zkgroup.internal.Constants
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredentialResponse
import org.signal.libsignal.zkgroup.profiles.ProfileKey
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCommitment
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequest
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations
import java.security.SecureRandom
import java.security.Security
import java.time.Instant
import java.util.ArrayList
import java.util.UUID
import kotlin.random.Random
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

typealias StringifiedProtocolAddress = String
typealias SerializedAddressedKeys = Map<StringifiedProtocolAddress, String>
typealias RegistrationId = Int
typealias IdKey = String
typealias Keypair = String
typealias OwnerData = Pair<Keypair, RegistrationId>
typealias IdentityStoreData = Pair<IdKey, OwnerData>

fun getDeviceIdAndServiceId(address: String): Pair<String, Int> {
  val (serviceId, deviceId) = address.split(".")
  return Pair(serviceId, deviceId.toInt())
}
fun updateSessionStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList, address: SignalProtocolAddress ): SerializedAddressedKeys {
  val sessionRecords = store.loadExistingSessions(listOf(address))
  val updatedStore = mutableMapOf<String, String>() ;
  for (sessionRecord in sessionRecords) {
    updatedStore[address.toString()] =  Base64.encodeToString(sessionRecord.serialize(), Base64.NO_WRAP)
  }
  return updatedStore
}
fun updateIdentityStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList, address: SignalProtocolAddress): SerializedAddressedKeys {
    val identityKey = store.getIdentity(address)
    val updatedStore = mutableMapOf<String, String>() ;
    updatedStore[address.toString()] =  Base64.encodeToString(identityKey.serialize(), Base64.NO_WRAP)
    return updatedStore
}
fun updatePreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList) : SerializedAddressedKeys {
    val updatedStore = mutableMapOf<String, String>()
    val preKeys = store.loadPreKeys()
    for (entry in preKeys) {
        updatedStore[entry.id.toString()] = Base64.encodeToString(entry.serialize(), Base64.NO_WRAP)
    }
    return updatedStore
}
fun updateSignedPreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList): SerializedAddressedKeys {
    val updatedStore = mutableMapOf<String, String>()
    val signedPreKeys = store.loadSignedPreKeys()
    for (entry in signedPreKeys) {
        updatedStore[entry.id.toString()] = Base64.encodeToString(entry.serialize(), Base64.NO_WRAP)
    }
    return updatedStore
}
fun updateKyberPreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPrekeysList): SerializedAddressedKeys {
    val updatedStore = mutableMapOf<String, String>()
    val kyberPreKeys = store.loadKyberPreKeys()
    for (entry in kyberPreKeys) {
        updatedStore[entry.id.toString()] = Base64.encodeToString(entry.serialize(), Base64.NO_WRAP)
    }
    return updatedStore
}

class ReactNativeLibsignalClientModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ReactNativeLibsignalClient")

    Function("serviceIdServiceIdBinary", this@ReactNativeLibsignalClientModule::serviceIdServiceIdBinary)
    Function("serviceIdServiceIdString", this@ReactNativeLibsignalClientModule::serviceIdServiceIdString)
    Function("serviceIdServiceIdLog", this@ReactNativeLibsignalClientModule::serviceIdServiceIdLog)
    Function("serviceIdParseFromServiceIdBinary", this@ReactNativeLibsignalClientModule::serviceIdParseFromServiceIdBinary)
    Function("serviceIdParseFromServiceIdString", this@ReactNativeLibsignalClientModule::serviceIdParseFromServiceIdString)

    Function("serverCertificateGetCertificate", this@ReactNativeLibsignalClientModule::serverCertificateGetCertificate)
    Function("serverCertificateGetKey", this@ReactNativeLibsignalClientModule::serverCertificateGetKey)
    Function("serverCertificateGetKeyId", this@ReactNativeLibsignalClientModule::serverCertificateGetKeyId)
    Function("serverCertificateGetSignature", this@ReactNativeLibsignalClientModule::serverCertificateGetSignature)

    Function("senderCertificateGetCertificate", this@ReactNativeLibsignalClientModule::senderCertificateGetCertificate)
    Function("senderCertificateGetExpiration", this@ReactNativeLibsignalClientModule::senderCertificateGetExpiration)
    Function("senderCertificateGetKey", this@ReactNativeLibsignalClientModule::senderCertificateGetKey)
    Function("senderCertificateGetSenderE164", this@ReactNativeLibsignalClientModule::senderCertificateGetSenderE164)
    Function("senderCertificateGetSenderUuid", this@ReactNativeLibsignalClientModule::senderCertificateGetSenderUuid)
    Function("senderCertificateGetDeviceId", this@ReactNativeLibsignalClientModule::senderCertificateGetDeviceId)
    Function("senderCertificateGetServerCertificate", this@ReactNativeLibsignalClientModule::senderCertificateGetServerCertificate)
    Function("senderCertificateGetSignature", this@ReactNativeLibsignalClientModule::senderCertificateGetSignature)
    Function("senderCertificateValidate", this@ReactNativeLibsignalClientModule::senderCertificateValidate)

    Function("privateKeyGenerate", this@ReactNativeLibsignalClientModule::privateKeyGenerate)
    Function("privateKeySign", this@ReactNativeLibsignalClientModule::privateKeySign)
    Function("privateKeyAgree", this@ReactNativeLibsignalClientModule::privateKeyAgree)
    Function("privateKeyGetPublicKey", this@ReactNativeLibsignalClientModule::privateKeyGetPublicKey)
    Function("publicKeyCompare", this@ReactNativeLibsignalClientModule::publicKeyCompare)
    Function("publicKeyGetPublicKeyBytes", this@ReactNativeLibsignalClientModule::publicKeyGetPublicKeyBytes)
    Function("publicKeyVerify", this@ReactNativeLibsignalClientModule::publicKeyVerify)
    Function("identityKeyPairSerialize", this@ReactNativeLibsignalClientModule::identityKeyPairSerialize) 
    Function("identityKeyVerifyAlternateIdentity", this@ReactNativeLibsignalClientModule::identityKeyVerifyAlternateIdentity)
    Function("generateIdentityKeyPair", this@ReactNativeLibsignalClientModule::generateIdentityKeyPair)
    Function("generateKyberKeyPair", this@ReactNativeLibsignalClientModule::generateKyberKeyPair)
    Function("generateKyberRecord", this@ReactNativeLibsignalClientModule::generateKyberRecord)
    Function("kyberPreKeyRecordGetId", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetId)
    Function("kyberPreKeyRecordGetPublicKey", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetPublicKey)
    Function("kyberPreKeyRecordGetSecretKey", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetSecretKey)
    Function("kyberPreKeyRecordGetSignature", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetSignature)
    Function("kyberPreKeyRecordGetTimestamp", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetTimestamp)
    Function("createAndProcessPreKeyBundle", this@ReactNativeLibsignalClientModule::createAndProcessPreKeyBundle)
    Function("signedPreKeyRecordNew", this@ReactNativeLibsignalClientModule::signedPreKeyRecordNew)
    Function("signedPreKeyRecordGetId", this@ReactNativeLibsignalClientModule::signedPreKeyRecordGetId)
    Function("signedPreKeyRecordGetPrivateKey", this@ReactNativeLibsignalClientModule::signedPreKeyRecordGetPrivateKey)
    Function("signedPreKeyRecordGetPublicKey", this@ReactNativeLibsignalClientModule::signedPreKeyRecordGetPublicKey)
    Function("signedPreKeyRecordGetSignature", this@ReactNativeLibsignalClientModule::signedPreKeyRecordGetSignature)
    Function("signedPreKeyRecordGetTimestamp", this@ReactNativeLibsignalClientModule::signedPreKeyRecordGetTimestamp)
    Function("preKeyRecordNew", this@ReactNativeLibsignalClientModule::preKeyRecordNew)
    Function("preKeyRecordGetId", this@ReactNativeLibsignalClientModule::preKeyRecordGetId)
    Function("preKeyRecordGetPrivateKey", this@ReactNativeLibsignalClientModule::preKeyRecordGetPrivateKey)
    Function("preKeyRecordGetPublicKey", this@ReactNativeLibsignalClientModule::preKeyRecordGetPublicKey)
    Function("sessionRecordArchiveCurrentState", this@ReactNativeLibsignalClientModule::sessionRecordArchiveCurrentState)
    Function("sessionRecordGetLocalRegistrationId", this@ReactNativeLibsignalClientModule::sessionRecordGetLocalRegistrationId)
    Function("sessionRecordGetRemoteRegistrationId", this@ReactNativeLibsignalClientModule::sessionRecordGetRemoteRegistrationId)
    Function("sessionRecordHasUsableSenderChain", this@ReactNativeLibsignalClientModule::sessionRecordHasUsableSenderChain)
    Function("sessionRecordCurrentRatchetKeyMatches", this@ReactNativeLibsignalClientModule::sessionRecordCurrentRatchetKeyMatches)
    Function("sessionCipherEncryptMessage", this@ReactNativeLibsignalClientModule::sessionCipherEncryptMessage)
    Function("plaintextContentFromDecryptionErrorMessage", this@ReactNativeLibsignalClientModule::plaintextContentFromDecryptionErrorMessage)
    Function("plaintextContentGetBody", this@ReactNativeLibsignalClientModule::plaintextContentGetBody)
    Function("decryptionErrorMessageForOriginalMessage", this@ReactNativeLibsignalClientModule::decryptionErrorMessageForOriginalMessage)
    Function("decryptionErrorMessageExtractFromSerializedContent", this@ReactNativeLibsignalClientModule::decryptionErrorMessageExtractFromSerializedContent)
    Function("decryptionErrorMessageGetTimestamp", this@ReactNativeLibsignalClientModule::decryptionErrorMessageGetTimestamp)
    Function("decryptionErrorMessageGetDeviceId", this@ReactNativeLibsignalClientModule::decryptionErrorMessageGetDeviceId)
    Function("decryptionErrorMessageGetRatchetKey", 
    this@ReactNativeLibsignalClientModule::decryptionErrorMessageGetRatchetKey)
    Function("signalMessageGetBody", this@ReactNativeLibsignalClientModule::signalMessageGetBody)
    Function("signalMessageGetCounter", this@ReactNativeLibsignalClientModule::signalMessageGetCounter)
    Function("signalMessageGetMessageVersion", this@ReactNativeLibsignalClientModule::signalMessageGetMessageVersion)
    Function("signalMessageVerifyMac", this@ReactNativeLibsignalClientModule::signalMessageVerifyMac)

    Function("preKeySignalMessageGetPreKeyId", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetPreKeyId)
    Function("preKeySignalMessageGetRegistrationId", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetRegistrationId)
    Function("preKeySignalMessageGetSignedPreKeyId", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetSignedPreKeyId)
    Function("preKeySignalMessageGetVersion", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetVersion)

    Function("senderKeyMessageGetCipherText", this@ReactNativeLibsignalClientModule::senderKeyMessageGetCipherText)
    Function("senderKeyMessageGetIteration", this@ReactNativeLibsignalClientModule::senderKeyMessageGetIteration)
    Function("senderKeyMessageGetChainId", this@ReactNativeLibsignalClientModule::senderKeyMessageGetChainId)
    Function("senderKeyMessageGetDistributionId", this@ReactNativeLibsignalClientModule::senderKeyMessageGetDistributionId)
    Function("senderKeyMessageVerifySignature", this@ReactNativeLibsignalClientModule::senderKeyMessageVerifySignature)

    Function("sessionCipherDecryptSignalMessage", this@ReactNativeLibsignalClientModule::sessionCipherDecryptSignalMessage)
    Function("sessionCipherDecryptPreKeySignalMessage", this@ReactNativeLibsignalClientModule::sessionCipherDecryptPreKeySignalMessage)
    Function("hkdfDeriveSecrets", this@ReactNativeLibsignalClientModule::hkdfDeriveSecrets)

    Function("senderKeyDistributionMessageGetChainKey", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetChainKey)
    Function("senderKeyDistributionMessageGetIteration", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetIteration)
    Function("senderKeyDistributionMessageGetChainId", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetChainId)
    Function("senderKeyDistributionMessageGetDistributionId", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetDistributionId)

    Function("senderKeyDistributionMessageProcess", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageProcess)

    Function("unidentifiedSenderMessageContentGetContents", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetContents)
    Function("unidentifiedSenderMessageContentGetMsgType", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetMsgType)
    Function("unidentifiedSenderMessageContentGetSenderCert", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetSenderCert)
    Function("unidentifiedSenderMessageContentGetContentHint", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetContentHint)
    Function("unidentifiedSenderMessageContentGetGroupId", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetGroupId)

    Function("sealedSenderDecryptToUsmc", this@ReactNativeLibsignalClientModule::sealedSenderDecryptToUsmc)

    Function("generateRegistrationId", this@ReactNativeLibsignalClientModule::generateRegistrationId)
    Function("serverPublicParamsVerifySignature", this@ReactNativeLibsignalClientModule::serverPublicParamsVerifySignature)
    Function("groupPublicParamsGetGroupIdentifier", this@ReactNativeLibsignalClientModule::groupPublicParamsGetGroupIdentifier)
    Function("groupSecretParamsGenerateDeterministic", this@ReactNativeLibsignalClientModule::groupSecretParamsGenerateDeterministic)
    Function("groupSecretParamsDeriveFromMasterKey", this@ReactNativeLibsignalClientModule::groupSecretParamsDeriveFromMasterKey)
    Function("groupSecretParamsGetPublicParams", this@ReactNativeLibsignalClientModule::groupSecretParamsGetPublicParams)
    Function("groupSecretParamsGetMasterKey", this@ReactNativeLibsignalClientModule::groupSecretParamsGetMasterKey)
    Function("generateRandomBytes", this@ReactNativeLibsignalClientModule::generateRandomBytes)
    Function("profileKeyGetCommitment", this@ReactNativeLibsignalClientModule::profileKeyGetCommitment)
    Function("profileKeyGetVersion", this@ReactNativeLibsignalClientModule::profileKeyGetVersion)
    Function("profileKeyDeriveAccessKey", this@ReactNativeLibsignalClientModule::profileKeyDeriveAccessKey)

    Function("serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic", this@ReactNativeLibsignalClientModule::serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic)
    Function("serverPublicParamsReceiveAuthCredentialWithPniAsServiceId", this@ReactNativeLibsignalClientModule::serverPublicParamsReceiveAuthCredentialWithPniAsServiceId)
    Function("authCredentialPresentationGetRedemptionTime", this@ReactNativeLibsignalClientModule::authCredentialPresentationGetRedemptionTime)
    Function("authCredentialPresentationGetPniCiphertext", this@ReactNativeLibsignalClientModule::authCredentialPresentationGetPniCiphertext)
    Function("authCredentialPresentationGetUuidCiphertext", this@ReactNativeLibsignalClientModule::authCredentialPresentationGetUuidCiphertext)
    Function("serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic", this@ReactNativeLibsignalClientModule::serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic)
    Function("serverPublicParamsReceiveExpiringProfileKeyCredential", this@ReactNativeLibsignalClientModule::serverPublicParamsReceiveExpiringProfileKeyCredential)
    Function("serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic", this@ReactNativeLibsignalClientModule::serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic)
    Function("profileKeyCredentialRequestContextGetRequest", this@ReactNativeLibsignalClientModule::profileKeyCredentialRequestContextGetRequest)
    Function("profileKeyCredentialPresentationGetProfileKeyCiphertext", this@ReactNativeLibsignalClientModule::profileKeyCredentialPresentationGetProfileKeyCiphertext)
    Function("profileKeyCredentialPresentationGetUuidCiphertext", this@ReactNativeLibsignalClientModule::profileKeyCredentialPresentationGetUuidCiphertext)
    Function("expiringProfileKeyCredentialGetExpirationTime", this@ReactNativeLibsignalClientModule::expiringProfileKeyCredentialGetExpirationTime)
    Function("groupSecretParamsDecryptBlobWithPadding", this@ReactNativeLibsignalClientModule::groupSecretParamsDecryptBlobWithPadding)
    Function("groupSecretParamsEncryptBlobWithPaddingDeterministic", this@ReactNativeLibsignalClientModule::groupSecretParamsEncryptBlobWithPaddingDeterministic)
    Function("groupSecretParamsDecryptProfileKey", this@ReactNativeLibsignalClientModule::groupSecretParamsDecryptProfileKey)
    Function("groupSecretParamsEncryptProfileKey", this@ReactNativeLibsignalClientModule::groupSecretParamsEncryptProfileKey)
    Function("groupSecretParamsDecryptServiceId", this@ReactNativeLibsignalClientModule::groupSecretParamsDecryptServiceId)
    Function("groupSecretParamsEncryptServiceId", this@ReactNativeLibsignalClientModule::groupSecretParamsEncryptServiceId)
    Function("serverSecretParamsGenerateDeterministic", this@ReactNativeLibsignalClientModule::serverSecretParamsGenerateDeterministic)
    Function("serverSecretParamsGetPublicParams", this@ReactNativeLibsignalClientModule::serverSecretParamsGetPublicParams)
    Function("serverSecretParamsSignDeterministic", this@ReactNativeLibsignalClientModule::serverSecretParamsSignDeterministic)
    Function("serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic", this@ReactNativeLibsignalClientModule::serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic)
    Function("serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic", this@ReactNativeLibsignalClientModule::serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic)
    Function("serverSecretParamsVerifyAuthCredentialPresentation", this@ReactNativeLibsignalClientModule::serverSecretParamsVerifyAuthCredentialPresentation)
    Function("groupSecretParamsEncryptCiphertext", this@ReactNativeLibsignalClientModule::groupSecretParamsEncryptCiphertext)
    Function("serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic", this@ReactNativeLibsignalClientModule::serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic)
    Function("serverSecretParamsVerifyProfileKeyCredentialPresentation", this@ReactNativeLibsignalClientModule::serverSecretParamsVerifyProfileKeyCredentialPresentation)

    Function("Aes256GcmEncrypt", this@ReactNativeLibsignalClientModule::Aes256GcmEncrypt)
    Function("Aes256GcmDecrypt", this@ReactNativeLibsignalClientModule::Aes256GcmDecrypt)
    Function("Aes256CbcEncrypt", this@ReactNativeLibsignalClientModule::Aes256CbcEncrypt)
    Function("Aes256CbcDecrypt", this@ReactNativeLibsignalClientModule::Aes256CbcDecrypt)
    Function("HmacSHA256", this@ReactNativeLibsignalClientModule::HmacSHA256)
    Function("ConstantTimeEqual", this@ReactNativeLibsignalClientModule::ConstantTimeEqual)
    Function("groupSendFullTokenGetExpiration", this@ReactNativeLibsignalClientModule::groupSendFullTokenGetExpiration)
    Function("groupSendFullTokenVerify", this@ReactNativeLibsignalClientModule::groupSendFullTokenVerify)
    Function("groupSendTokenToFullToken", this@ReactNativeLibsignalClientModule::groupSendTokenToFullToken)
    Function("groupSendDerivedKeyPairForExpiration", this@ReactNativeLibsignalClientModule::groupSendDerivedKeyPairForExpiration)
    Function("groupSendEndorsementCombine", this@ReactNativeLibsignalClientModule::groupSendEndorsementCombine)
    Function("groupSendEndorsementRemove", this@ReactNativeLibsignalClientModule::groupSendEndorsementRemove)
    Function("groupSendEndorsementToToken", this@ReactNativeLibsignalClientModule::groupSendEndorsementToToken)
    Function("groupSendEndorsementsResponseIssueDeterministic", this@ReactNativeLibsignalClientModule::groupSendEndorsementsResponseIssueDeterministic)
    Function("groupSendEndorsementsResponseGetExpiration", this@ReactNativeLibsignalClientModule::groupSendEndorsementsResponseGetExpiration)
    Function("groupSendEndorsementsResponseReceiveAndCombineWithServiceIds", this@ReactNativeLibsignalClientModule::groupSendEndorsementsResponseReceiveAndCombineWithServiceIds)
    Function("groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts", this@ReactNativeLibsignalClientModule::groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts)
  }

    private fun serviceIdServiceIdBinary(fixedWidthServiceId: ByteArray) : ByteArray {
        return ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId).toServiceIdBinary()
    }
    private fun serviceIdServiceIdString(fixedWidthServiceId: ByteArray) : String {
        return ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId).toServiceIdString()
    }
    private fun serviceIdServiceIdLog(fixedWidthServiceId: ByteArray) : String {
        return ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId).toLogString()
    }
    private fun serviceIdParseFromServiceIdBinary(serviceIdBinary: ByteArray) : ByteArray {
        return ServiceId.parseFromBinary(serviceIdBinary).toServiceIdFixedWidthBinary()
    }
    private fun serviceIdParseFromServiceIdString(serviceIdString: String) : ByteArray {
        return ServiceId.parseFromString(serviceIdString).toServiceIdFixedWidthBinary()
    }


  private fun privateKeyGenerate() : ByteArray {
    val keypair = Curve.generateKeyPair()
    return keypair.privateKey.serialize()
  }
  private fun privateKeyAgree(serializedPrivateKey: ByteArray, serializedOtherPublicKey : ByteArray) : ByteArray {
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    val publicKey = ECPublicKey(serializedOtherPublicKey)
    return privateKey.calculateAgreement(publicKey)
  }
  private fun privateKeyGetPublicKey(serializedPrivateKey: ByteArray) : ByteArray {
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    return privateKey.publicKey().serialize()
  }
  private fun publicKeyCompare(serializedPublicKey1: ByteArray, otherSerializedPublicKey2: ByteArray) : Int {
    val publicKey1 = ECPublicKey(serializedPublicKey1)
    val publicKey2 = ECPublicKey(otherSerializedPublicKey2)
    return publicKey1.compareTo(publicKey2)
  }
  private fun publicKeyGetPublicKeyBytes(serializedPublicKey: ByteArray) : ByteArray {
    val publicKey = ECPublicKey(serializedPublicKey)
    return publicKey.publicKeyBytes
  }
  private fun publicKeyVerify(serializedPublicKey: ByteArray, message : ByteArray, signature : ByteArray) : Boolean {
    val publicKey = ECPublicKey(serializedPublicKey)
    return publicKey.verifySignature(message, signature)
  }
  private fun identityKeyVerifyAlternateIdentity(serializedIdentityKey: ByteArray, otherPublicKey: ByteArray, message: ByteArray) : Boolean {
    val identityKey = IdentityKey(serializedIdentityKey)
    val otherIdentityKey = IdentityKey(otherPublicKey)
    return identityKey.verifyAlternateIdentity(otherIdentityKey, message)
  }
  private fun privateKeySign(serializedPrivateKey: ByteArray, message: ByteArray) : ByteArray {
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    return privateKey.calculateSignature(message)
  }
  private fun generateIdentityKeyPair() : Pair<ByteArray, ByteArray>  {
    val keypair = Curve.generateKeyPair()
    return Pair(keypair.publicKey.serialize(), keypair.privateKey.serialize())
  }
  private fun identityKeyPairSerialize(serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray) : ByteArray {
    val pubKey = IdentityKey(serializedPublicKey)
    val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
    return IdentityKeyPair(pubKey, privateKey).serialize()
  }
  private fun generateKyberKeyPair() : Pair<ByteArray, ByteArray>   {
    val keypair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
    return Pair(keypair.secretKey.serialize(), keypair.publicKey.serialize())
  }

  private fun generateKyberRecord(id: Int, timestamp: Long, privateIdentityKey: ByteArray) : ByteArray {
    val keypair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
    val privateKey =  Curve.decodePrivatePoint(privateIdentityKey)
    val signature = privateKey.calculateSignature(keypair.publicKey.serialize())
    val record = KyberPreKeyRecord(id, timestamp, keypair, signature)
    return record.serialize()
  }

  private fun kyberPreKeyRecordGetId(record: ByteArray) : Int {
    val rec = KyberPreKeyRecord(record)
    return rec.id
  }
  private fun kyberPreKeyRecordGetPublicKey(record: ByteArray) : ByteArray {
    val rec = KyberPreKeyRecord(record)
    return rec.keyPair.publicKey.serialize()
  }
  private fun kyberPreKeyRecordGetSecretKey(record: ByteArray) : ByteArray {
      val rec = KyberPreKeyRecord(record)
      return rec.keyPair.secretKey.serialize()
  }
  private fun kyberPreKeyRecordGetSignature(record: ByteArray) : ByteArray {
    val rec = KyberPreKeyRecord(record)
    return rec.signature
  }
  private fun kyberPreKeyRecordGetTimestamp(record: ByteArray): Long {
    val rec = KyberPreKeyRecord(record)
    return rec.timestamp
  }
   // we are passing some arguments in array and receiving them as pairs for reducing the number of parameters to >= 8. we can clean it up further by putting it in a Record class whih is expo's max limit due to the limitations of generics in both Swift and Kotlin because this component must be implemented separately for each.
  private fun createAndProcessPreKeyBundle(
    registrationData: Pair<String, Int>,
    preKeyData: Pair<Int, String>,
    signedPreKeyData: Pair<Int, String>,
    base64SignedPreKeySignature: String,
    base64IdentityKey: String,
    ownerIdentityData: OwnerData,
    kyberPreKeyData: Pair<Int, String>?,
    base64KyberPreKeySignature: String?
  ) : Pair<SerializedAddressedKeys, SerializedAddressedKeys> {
     val (base64OwnerKeypair, ownerRegistrationId) = ownerIdentityData;
       val ownerKeypair = Base64.decode(base64OwnerKeypair, Base64.NO_WRAP)
       val ownerIdentityKey = IdentityKeyPair(ownerKeypair)
     val (address, registrationId) = registrationData
     val (preKeyId, base64PreKeyPublic) = preKeyData;
     val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
     val (signedPreKeyId, base64SignedPreKeyPublic) = signedPreKeyData
     val signedPreKeyPublic = Base64.decode(base64SignedPreKeyPublic, Base64.NO_WRAP)
     val signedPublicPreKey = ECPublicKey(signedPreKeyPublic)
     val identityKey = Base64.decode(base64IdentityKey, Base64.NO_WRAP)
     val idKey = IdentityKey(identityKey)
       val preKeyPublic = Base64.decode(base64PreKeyPublic, Base64.NO_WRAP)
     val publicPreKey = ECPublicKey(preKeyPublic)
     val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)

     val store = InMemorySignalProtocolStoreWithPrekeysList(ownerIdentityKey, ownerRegistrationId)
     val sessionBuilder = SessionBuilder(store, remoteProtoAddress)
    val signedPreKeySignature = Base64.decode(base64SignedPreKeySignature, Base64.NO_WRAP)
     if (kyberPreKeyData !== null && base64KyberPreKeySignature !== null) {
       val (keyId, base64KyberPreKeyPublic) = kyberPreKeyData;
         val kyberPreKeyPublic = Base64.decode(base64KyberPreKeyPublic, Base64.NO_WRAP)
       val pubKey = KEMPublicKey(kyberPreKeyPublic)
       val kyberPreKeySignature = Base64.decode(base64KyberPreKeySignature, Base64.NO_WRAP)
       val bundle = PreKeyBundle(
         registrationId,
         deviceId,
         preKeyId,
         publicPreKey,
         signedPreKeyId,
         signedPublicPreKey,
         signedPreKeySignature,
         idKey,
         keyId,
         pubKey,
         kyberPreKeySignature
       )
       sessionBuilder.process(bundle)
     } else {
         
       val noKyberBundle = PreKeyBundle(
         registrationId,
         deviceId,
         preKeyId,
         publicPreKey,
         signedPreKeyId,
         signedPublicPreKey,
         signedPreKeySignature,
         idKey,
       )
       sessionBuilder.process(noKyberBundle)
     }
     val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
     val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
     return Pair(updatedInMemorySessionStore, updatedInMemoryIdentityStore)
   }

   private fun signedPreKeyRecordNew(id: Int, timestamp: Long, serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray, signature: ByteArray) : ByteArray {
     val publicKey = ECPublicKey(serializedPublicKey)
     val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
     val keyPair = ECKeyPair(publicKey, privateKey)
     return SignedPreKeyRecord(id, timestamp, keyPair, signature).serialize()
   }
   private fun signedPreKeyRecordGetId(record: ByteArray) : Int {
     val rec = SignedPreKeyRecord(record)
     return rec.id
   }
    private fun signedPreKeyRecordGetPrivateKey(record: ByteArray) : ByteArray {
      val rec = SignedPreKeyRecord(record)
      return rec.keyPair.privateKey.serialize()
    }
    private fun signedPreKeyRecordGetPublicKey(record: ByteArray) : ByteArray {
      val rec = SignedPreKeyRecord(record)
      return rec.keyPair.publicKey.serialize()
    }
    private fun signedPreKeyRecordGetSignature(record: ByteArray) : ByteArray {
      val rec = SignedPreKeyRecord(record)
      return rec.signature
    }
    private fun signedPreKeyRecordGetTimestamp(record: ByteArray) : Long {
      val rec = SignedPreKeyRecord(record)
      return rec.timestamp
    }

    private fun preKeyRecordNew(id: Int, serializedPublicKey: ByteArray, serializedPrivateKey: ByteArray) : ByteArray {
        val publicKey = ECPublicKey(serializedPublicKey)
        val privateKey = Curve.decodePrivatePoint(serializedPrivateKey)
        val keyPair = ECKeyPair(publicKey, privateKey)
        return PreKeyRecord(id, keyPair).serialize()
    }
    private fun preKeyRecordGetId(record: ByteArray) : Int {
        val rec = PreKeyRecord(record)
        return rec.id
    }
    private fun preKeyRecordGetPrivateKey(record: ByteArray) : ByteArray {
        val rec = PreKeyRecord(record)
        return rec.keyPair.privateKey.serialize()
    }
    private fun preKeyRecordGetPublicKey(record: ByteArray) : ByteArray {
        val rec = PreKeyRecord(record)
        return rec.keyPair.publicKey.serialize()
    }

    private fun sessionRecordArchiveCurrentState(record: ByteArray) : ByteArray {
      val rec = SessionRecord(record)
      rec.archiveCurrentState()
      return rec.serialize()
    }
    private fun sessionRecordGetLocalRegistrationId(record: ByteArray) : Int {
      val rec = SessionRecord(record)
      return rec.localRegistrationId
    }
    private fun sessionRecordGetRemoteRegistrationId(record: ByteArray) : Int {
      val rec = SessionRecord(record)
      return rec.remoteRegistrationId
    }
    private fun sessionRecordHasUsableSenderChain(record: ByteArray, now: Long) : Boolean {
      val rec = SessionRecord(record)
      return rec.hasSenderChain(Instant.ofEpochMilli(now))
    }
    private fun sessionRecordCurrentRatchetKeyMatches(record: ByteArray, pubKey : ByteArray) : Boolean {
      val ecPublicKey = ECPublicKey(pubKey)
      val rec = SessionRecord(record)
      return rec.currentRatchetKeyMatches(ecPublicKey)
    }
    private fun sessionCipherEncryptMessage(
        base64Message: String,
        address: String,
        sessionStoreState: SerializedAddressedKeys,
        identityKeyState: IdentityStoreData,
        now: Long
    )
    : Pair<Pair<ByteArray, Int>, Pair<SerializedAddressedKeys, SerializedAddressedKeys>>
    {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        val (base64IdentityKey, ownerData) = identityKeyState
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val identityKey = IdentityKey(Base64.decode(base64IdentityKey, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        store.saveIdentity(remoteProtoAddress, identityKey)
        for ((key, value) in sessionStoreState) {
            val (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(key)
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            val protoAddress = SignalProtocolAddress(inStoreName, inStoreDeviceId)
            store.storeSession(protoAddress, SessionRecord(keyBuffer))
        }
        val sessionCipher = SessionCipher(store, remoteProtoAddress)
        val msg = Base64.decode(base64Message, Base64.NO_WRAP)
                val cipher = sessionCipher.encrypt(msg, Instant.ofEpochMilli(now))
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        return Pair(Pair(cipher.serialize(), cipher.type), Pair(updatedInMemorySessionStore, updatedInMemoryIdentityStore))
    }
//    private fun SessionCipher_DecryptPreKeySignalMessage(
//        message: Long,
//        address: StringifiedProtocolAddress,
//        idData: OwnerData,
//        prekeyStoreState: SerializedAddressedKeys,
//        signedPrekeyStoreState: SerializedAddressedKeys,
//        kyberPrekeys: SerializedAddressedKeys
//    ) : Pair<ByteArray, Array<SerializedAddressedKeys>> {
//        val (keypair, registrationId) = idData
//        val inMemoryIdentityKeyStore = InMemoryIdentityKeyStore(IdentityKeyPair(Base64.decode(keypair, Base64.NO_WRAP)), registrationId)
//        val protoAddressHandle = address.toLong()
//        val inMemorySessionStore = InMemorySessionStore()
//        var inMemorySignedPrekeyStore = InMemorySignedPreKeyStore()
//        for ((keyId, value) in signedPrekeyStoreState) {
//            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
//            inMemorySignedPrekeyStore.storeSignedPreKey(keyId.toInt(), SignedPreKeyRecord(keyBuffer))
//        }
//        var inMemoryKyberPreKeyStore = InMemoryKyberPreKeyStore()
//        for ((keyId, value) in kyberPrekeys) {
//            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
//            inMemoryKyberPreKeyStore.storeKyberPreKey(keyId.toInt(), KyberPreKeyRecord(keyBuffer))
//        }
//        var inMemoryPreKeyStore = InMemoryPreKeyStoreWithList()
//        for ((keyId, value) in prekeyStoreState) {
//            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
//            inMemoryPreKeyStore.storePreKey(keyId.toInt(), PreKeyRecord(keyBuffer))
//        }
//        val msg = Native.SessionCipher_DecryptPreKeySignalMessage(
//            message,
//            protoAddressHandle,
//            inMemorySessionStore,
//            inMemoryIdentityKeyStore,
//            inMemoryPreKeyStore,
//            inMemorySignedPrekeyStore,
//            inMemoryKyberPreKeyStore
//        )
//        val protoAddress = SignalProtocolAddress(protoAddressHandle)
//        val updatedSession = updateSessionStoreStateFromInMemoryProtocolStore(inMemorySessionStore, protoAddress)
//        val updatedId = updateIdentityStoreStateFromInMemoryProtocolStore(inMemoryIdentityKeyStore, protoAddress)
//        val updatedPreKeyStore = updatePreKeyStoreStateFromInMemoryProtocolStore(inMemoryPreKeyStore)
//        val updatedSignedPreKeyStore = updateSignedPreKeyStoreStateFromInMemoryProtocolStore(inMemorySignedPrekeyStore)
//        val updatedKyberPreKeyStore = updateKyberPreKeyStoreStateFromInMemoryProtocolStore(inMemoryKyberPreKeyStore)
//        return Pair(msg, arrayOf(updatedSession, updatedId, updatedPreKeyStore, updatedSignedPreKeyStore))
//    }
//    const [
//    msg,
//    [
//    updatedSessionStore,
//    updatedIdentityStore,
//    updatedPrekeyStore,
//    updatedSignedPrekeyStore,
//    ],
//    ] = ReactNativeLibsignalClientModule.SessionCipher_DecryptPreKeySignalMessage(
//    message._nativeHandle,
//    String(address._nativeHandle),
//    identityStoreInitializer,
//    prekeyStoreState,
//    signedPrekeyStoreState,
//    kyberPrekeyStoreState
//    );

    private fun sessionCipherDecryptSignalMessage(
        serializedMessage: ByteArray,
        address: String,
        sessionStoreState: SerializedAddressedKeys,
        identityKeyState: IdentityStoreData,
    ) : Pair<ByteArray, Pair<SerializedAddressedKeys, SerializedAddressedKeys>> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        val (base64IdentityKey, ownerData) = identityKeyState
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val identityKey = IdentityKey(Base64.decode(base64IdentityKey, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        store.saveIdentity(remoteProtoAddress, identityKey)
        for ((key, value) in sessionStoreState) {
            val (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(key)
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            val protoAddress = SignalProtocolAddress(inStoreName, inStoreDeviceId)
            store.storeSession(protoAddress, SessionRecord(keyBuffer))
        }
        val sessionCipher = SessionCipher(store, remoteProtoAddress)
        val message = SignalMessage(serializedMessage)
        val plaintext = sessionCipher.decrypt(message)
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        return Pair(plaintext, Pair(updatedInMemorySessionStore, updatedInMemoryIdentityStore))
    }
    private fun sessionCipherDecryptPreKeySignalMessage(
        serializedMessage: ByteArray,
        address: String,
        ownerIdentityData: OwnerData,
        prekeyStoreState: SerializedAddressedKeys,
        signedPrekeyStoreState: SerializedAddressedKeys,
        kyberPrekeyStoreState: SerializedAddressedKeys
    ) : Pair<ByteArray, Array<SerializedAddressedKeys>> {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(address)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        val (base64OwnerKeypair, ownerRegistrationId) = ownerIdentityData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        for ((key, value) in prekeyStoreState) {
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            store.storePreKey(key.toInt(), PreKeyRecord(keyBuffer))
        }
        for ((key, value) in signedPrekeyStoreState) {
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            store.storeSignedPreKey(key.toInt(), SignedPreKeyRecord(keyBuffer))
        }
        for ((key, value) in kyberPrekeyStoreState) {
            val keyBuffer = Base64.decode(value, Base64.NO_WRAP)
            store.storeKyberPreKey(key.toInt(), KyberPreKeyRecord(keyBuffer))
        }
        val sessionCipher = SessionCipher(store, remoteProtoAddress)
        val message = PreKeySignalMessage(serializedMessage)
        val plaintext = sessionCipher.decrypt(message)
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryProtocolStore(store, remoteProtoAddress)
        val updatedPreKeyStore = updatePreKeyStoreStateFromInMemoryProtocolStore(store)
        val updatedSignedPreKeyStore = updateSignedPreKeyStoreStateFromInMemoryProtocolStore(store)
        val updatedKyberPreKeyStore = updateKyberPreKeyStoreStateFromInMemoryProtocolStore(store)
        return Pair(plaintext, arrayOf(updatedInMemorySessionStore, updatedInMemoryIdentityStore, updatedPreKeyStore, updatedSignedPreKeyStore, updatedKyberPreKeyStore))
    }

    private fun plaintextContentFromDecryptionErrorMessage(message: ByteArray) : ByteArray {
        val plaintextContent = PlaintextContent(message)
        return plaintextContent.serialize()
    }
    private fun plaintextContentGetBody(message: ByteArray) : ByteArray {
        val plaintextContent = PlaintextContent(message)
        return plaintextContent.body
    }

    private fun decryptionErrorMessageForOriginalMessage(originalBytes: ByteArray, messageType: Int, timestamp: Long, originalSenderDeviceId: Int) : ByteArray {
        return DecryptionErrorMessage.forOriginalMessage(originalBytes, messageType, timestamp, originalSenderDeviceId).serialize()
    }
    private fun decryptionErrorMessageExtractFromSerializedContent(serializedContent: ByteArray) : ByteArray {
        val content = DecryptionErrorMessage.extractFromSerializedContent(serializedContent)
        return content.serialize()
    }
    private fun decryptionErrorMessageGetTimestamp(serializedContent: ByteArray) : Long {
        val content = DecryptionErrorMessage.extractFromSerializedContent(serializedContent)
        return content.timestamp
    }
    private fun decryptionErrorMessageGetDeviceId(serializedContent: ByteArray) : Int {
        val content = DecryptionErrorMessage.extractFromSerializedContent(serializedContent)
        return content.deviceId
    }
    private fun decryptionErrorMessageGetRatchetKey(serializedContent: ByteArray) : ByteArray? {
        var ecPublicKey : ByteArray? = null
        val content = DecryptionErrorMessage.extractFromSerializedContent(serializedContent)
        if (content.ratchetKey.isPresent) {
            ecPublicKey = content.ratchetKey.get().serialize()
        }
        return ecPublicKey
    }
    // this is not used anywhere in app but is useful for testing things separately. here as a reference
//    private fun signalMessageNew(
//        messageVersion: Int,
//        serializedMacKey: ByteArray,
//        serializedSenderRatchetKey: ByteArray,
//        counter: Int,
//        previousCounter: Int,
//        ciphertext: ByteArray,
//        serializedSenderIdentityKey: ByteArray,
//        serializedReceiverIdentityKey: ByteArray
//    ) : ByteArray {
//        val macKey = SecretKeySpec(serializedMacKey, "HmacSHA256")
//        val senderRatchetKey = ECPublicKey(serializedSenderRatchetKey)
//        val senderIdentityKey = ECPublicKey(serializedSenderIdentityKey)
//        val receiverIdentityKey = ECPublicKey(serializedReceiverIdentityKey)
//        return SignalMessage(
//            Native.SignalMessage_New(
//                messageVersion,
//                macKey.encoded,
//                senderRatchetKey.unsafeNativeHandleWithoutGuard(),
//                counter,
//                previousCounter,
//                ciphertext,
//                senderIdentityKey.unsafeNativeHandleWithoutGuard(),
//                receiverIdentityKey.unsafeNativeHandleWithoutGuard()
//            )
//        ).serialize()
//    }
    private fun signalMessageGetBody(serializedMessage: ByteArray) : ByteArray {
        val message = SignalMessage(serializedMessage)
        return message.body
    }
    private fun signalMessageGetCounter(serializedMessage: ByteArray) : Int {
        val message = SignalMessage(serializedMessage)
        return message.counter
    }
    private fun signalMessageGetMessageVersion(serializedMessage: ByteArray) : Int {
        val message = SignalMessage(serializedMessage)
        return message.messageVersion
    }
    private fun signalMessageVerifyMac(serializedMessage: ByteArray, serializedSenderIdentityKey: ByteArray, serializedReceiverIdentityKey: ByteArray, serializedMacKey: ByteArray) : Boolean {
        return try {
            val message = SignalMessage(serializedMessage)
            val senderIdentityKey = IdentityKey(serializedSenderIdentityKey)
            val receiverIdentityKey = IdentityKey(serializedReceiverIdentityKey)
            val macKey = SecretKeySpec(serializedMacKey, "HmacSHA256")
            message.verifyMac(senderIdentityKey, receiverIdentityKey, macKey)
            true
        } catch (e: InvalidMessageException) {
            false
        } catch (e: InvalidKeyException) {
            false
        }
    }

    private fun preKeySignalMessageGetPreKeyId(serializedMessage: ByteArray) : Int? {
        var optionalPreKeyId : Int? = null
        val message = PreKeySignalMessage(serializedMessage)
        if (message.preKeyId.isPresent) {
            optionalPreKeyId = message.preKeyId.get()
        }
        return optionalPreKeyId
    }
    private fun preKeySignalMessageGetRegistrationId(serializedMessage: ByteArray) : Int {
        val message = PreKeySignalMessage(serializedMessage)
        return message.registrationId
    }
    private fun preKeySignalMessageGetSignedPreKeyId(serializedMessage: ByteArray) : Int {
        val message = PreKeySignalMessage(serializedMessage)
        return message.signedPreKeyId
    }
    private fun preKeySignalMessageGetVersion(serializedMessage: ByteArray) : Int {
        val message = PreKeySignalMessage(serializedMessage)
        return message.messageVersion
    }

    private fun senderKeyMessageGetCipherText(serializedMessage: ByteArray) : ByteArray {
        val message = SenderKeyMessage(serializedMessage)
        return message.cipherText
    }
    private fun senderKeyMessageGetIteration(serializedMessage: ByteArray) : Int {
        val message = SenderKeyMessage(serializedMessage)
        return message.iteration
    }
    private fun senderKeyMessageGetChainId(serializedMessage: ByteArray) : Int {
        val message = SenderKeyMessage(serializedMessage)
        return message.chainId
    }
    private fun senderKeyMessageGetDistributionId(serializedMessage: ByteArray) : String {
        val message = SenderKeyMessage(serializedMessage)
        return message.distributionId.toString()
    }
    private fun senderKeyMessageVerifySignature(serializedMessage: ByteArray, serializedSenderIdentityKey: ByteArray) : Boolean {
        return try {
            val message = SenderKeyMessage(serializedMessage)
            val senderIdentityKey = ECPublicKey(serializedSenderIdentityKey)
            message.verifySignature(senderIdentityKey)
            true
        } catch (e: InvalidMessageException) {
            false
        } catch (e: InvalidKeyException) {
            false
        }
    }

    private fun hkdfDeriveSecrets(
        outputLength: Int,
        keyMaterial: ByteArray,
        label: ByteArray,
        salt: ByteArray?
    ) : ByteArray {
        return HKDF.deriveSecrets( keyMaterial, salt, label, outputLength)
    }

    private fun senderCertificateGetCertificate(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.certificate
    }
    private fun senderCertificateGetSignature(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.signature
    }
    private fun senderCertificateGetExpiration(serializedCertificate: ByteArray) : Long {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.expiration
    }
    private fun senderCertificateGetKey(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.key.serialize()
    }
    private fun senderCertificateGetSenderE164(serializedCertificate: ByteArray) : String? {
        val certificate = SenderCertificate(serializedCertificate)
        var senderE164 : String? = null
        if (certificate.senderE164.isPresent) {
            senderE164 = certificate.senderE164.get()
        }
        return senderE164
    }
    private fun senderCertificateGetSenderUuid(serializedCertificate: ByteArray) : String {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.senderUuid.toString()
    }
    private fun senderCertificateGetDeviceId(serializedCertificate: ByteArray) : Int {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.senderDeviceId
    }
    private fun senderCertificateGetServerCertificate(serializedCertificate: ByteArray) : ByteArray {
        val certificate = SenderCertificate(serializedCertificate)
        return certificate.certificate
    }
    private fun senderCertificateValidate(trustRoot: ByteArray, serializedCertificate: ByteArray, timestamp: Long) : Boolean {
        val certificate = SenderCertificate(serializedCertificate)
        val publicKey = ECPublicKey(trustRoot)
        val certificateValidator = CertificateValidator(publicKey)
        try {
            certificateValidator.validate(certificate, timestamp)
            return true
        } catch (e: InvalidCertificateException) {
            return false
        }
    }

    private fun serverCertificateGetCertificate(serializedCertificate: ByteArray) : ByteArray {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.certificate
    }
    private fun serverCertificateGetKey(serializedCertificate: ByteArray) : ByteArray {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.key.serialize()
    }
    private fun serverCertificateGetKeyId(serializedCertificate: ByteArray) : Int {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.keyId
    }
    private fun serverCertificateGetSignature(serializedCertificate: ByteArray) : ByteArray {
        val certificate = ServerCertificate(serializedCertificate)
        return certificate.signature
    }

    private fun senderKeyDistributionMessageGetChainKey(serializedMessage: ByteArray) : ByteArray {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.chainKey
    }
    private fun senderKeyDistributionMessageGetIteration(serializedMessage: ByteArray) : Int {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.iteration
    }
    private fun senderKeyDistributionMessageGetChainId(serializedMessage: ByteArray) : Int {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.chainId
    }
    private fun senderKeyDistributionMessageGetDistributionId(serializedMessage: ByteArray) : String {
        val message = SenderKeyDistributionMessage(serializedMessage)
        return message.distributionId.toString()
    }

//    export async function processSenderKeyDistributionMessage(
//    sender: ProtocolAddress,
//    message: SenderKeyDistributionMessage,
//    store: SenderKeyStore
//    ): Promise<void> {
//        const distributionId = message.distributionId();
//        const newSenderKeyRecord =
//        await ReactNativeLibsignalClientModule.senderKeyDistributionMessageProcess(
//                sender.toString(),
//        message.serialized,
//        await getCurrentKeyHandle(sender, distributionId, store)
//        );
//        store.saveSenderKey(sender, distributionId, newSenderKeyRecord);
//    }
    private fun senderKeyDistributionMessageProcess(
        senderAddress: String,
        serializedMessage: ByteArray,
        currentSerializedKey: ByteArray
    ) : ByteArray {
        val (serviceId, deviceId) = getDeviceIdAndServiceId(senderAddress)
        val protoAddress = SignalProtocolAddress(serviceId, deviceId)
        val message = SenderKeyDistributionMessage(serializedMessage)
        val senderKey = SenderKeyRecord(currentSerializedKey)
        val senderKeyStore = InMemorySenderKeyStore()
        senderKeyStore.storeSenderKey(protoAddress, message.distributionId,  senderKey)

        val groupSessionBuilder = GroupSessionBuilder(senderKeyStore)
        groupSessionBuilder.process(protoAddress,message)
        val newSenderKeyRecord = senderKeyStore.loadSenderKey(protoAddress, message.distributionId)
        return newSenderKeyRecord.serialize()
    }

    private fun unidentifiedSenderMessageContentGetContents(serializedContent: ByteArray) : ByteArray {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.content
    }
    private fun unidentifiedSenderMessageContentGetMsgType(serializedContent: ByteArray) : Int {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.type
    }
    private fun unidentifiedSenderMessageContentGetSenderCert(serializedContent: ByteArray) : ByteArray {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.senderCertificate.serialized
    }
    private fun unidentifiedSenderMessageContentGetContentHint(serializedContent: ByteArray) : Int {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.contentHint
    }
    private fun unidentifiedSenderMessageContentGetGroupId(serializedContent: ByteArray) : String {
        val content = UnidentifiedSenderMessageContent(serializedContent)
        return content.groupId.toString()
    }

    private fun sealedSenderDecryptToUsmc(base64Message: String, identityKeyState: IdentityStoreData, senderAddress: String) :Pair<ByteArray, SerializedAddressedKeys>  {
        val message = Base64.decode(base64Message, Base64.NO_WRAP)
        val (base64IdentityKey, ownerData) = identityKeyState
        val (base64OwnerKeypair, ownerRegistrationId) = ownerData
        val ownerKeypair = IdentityKeyPair(Base64.decode(base64OwnerKeypair, Base64.NO_WRAP))
        val identityKey = IdentityKey(Base64.decode(base64IdentityKey, Base64.NO_WRAP))
        val store = InMemorySignalProtocolStoreWithPrekeysList(ownerKeypair, ownerRegistrationId)
        val (serviceId, deviceId) = getDeviceIdAndServiceId(senderAddress)
        val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId)
        store.saveIdentity(remoteProtoAddress, identityKey)
        val sealedSessionCipher = SealedSessionCipher(store, UUID.fromString(serviceId), serviceId, deviceId)
        val validator = CertificateValidator(ECPublicKey(ownerKeypair.publicKey.serialize()))
        val plaintext = sealedSessionCipher.decrypt(validator, message, Instant.now().toEpochMilli())
        val updatedInMemorySessionStore = updateSessionStoreStateFromInMemoryProtocolStore(store, SignalProtocolAddress(serviceId, deviceId))
        return Pair(plaintext.paddedMessage, updatedInMemorySessionStore)
    }

    private fun generateRegistrationId(): Int {
        return KeyHelper.generateRegistrationId(false)
    }

    private fun serverPublicParamsVerifySignature(serializedSrvPubParams: ByteArray, msg: ByteArray, sig: ByteArray) : Boolean {
        val svpublicParams = ServerPublicParams(serializedSrvPubParams);
        val signature = NotarySignature(sig);

        try {
            svpublicParams.verifySignature(msg, signature);
            return true
        } catch (e: VerificationFailedException) {
            return false
        }
    }

    private fun groupPublicParamsGetGroupIdentifier(serializedGpPubParams: ByteArray) : ByteArray {
        val groupPublicParams = GroupPublicParams(serializedGpPubParams);
        return groupPublicParams.groupIdentifier.serialize()
    }

    private fun groupSecretParamsGenerateDeterministic(rand: ByteArray) : ByteArray {
        val groupSecretParams = GroupSecretParams.generate(SecureRandom(rand));

        return groupSecretParams.serialize();
    }

    private fun groupSecretParamsDeriveFromMasterKey(serializedGpMasterKey: ByteArray) : ByteArray {
        val masterKey = GroupMasterKey(serializedGpMasterKey);
        return GroupSecretParams.deriveFromMasterKey(masterKey).serialize();
    }

    private fun groupSecretParamsGetPublicParams(gpSecParams: ByteArray) : ByteArray {
        val groupSecretParams = GroupSecretParams(gpSecParams);
        return groupSecretParams.publicParams.serialize();

        return ByteArray(0);
    }

    private fun groupSecretParamsGetMasterKey(gpSecParams: ByteArray) : ByteArray {
        val groupSecretParams = GroupSecretParams(gpSecParams);
        return groupSecretParams.masterKey.serialize();
    }

    private fun generateRandomBytes(len: Int) : ByteArray {
        val srandom = SecureRandom();
        val random = ByteArray(len)

        srandom.nextBytes(random);

        return random;
    }

    private fun profileKeyGetCommitment(serializedProfileKey: ByteArray, fixedWidthAci: ByteArray) : ByteArray {
        val pk = ProfileKey(serializedProfileKey);
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci);

        return pk.getCommitment(aci).serialize();
    }

    private fun profileKeyGetVersion(serializedProfileKey: ByteArray, fixedWidthAci: ByteArray) : String {
        val pk = ProfileKey(serializedProfileKey);
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci);

        return pk.getProfileKeyVersion(aci).serialize();
    }

    private fun profileKeyDeriveAccessKey(serializedProfileKey: ByteArray) : ByteArray {
        val pk = ProfileKey(serializedProfileKey);

        return pk.deriveAccessKey()
    }

    private fun groupSecretParamsEncryptServiceId(sGroupSecretParams: ByteArray, fixedWidthServiceId: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams);
        val sId = ServiceId.parseFromFixedWidthBinary(fixedWidthServiceId);
        val clZkCipher = ClientZkGroupCipher(gsp);

        return clZkCipher.encrypt(sId).serialize();
    }

    private fun groupSecretParamsDecryptServiceId(sGroupSecretParams: ByteArray, rawCipherText: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams);
        val cipherText = UuidCiphertext(rawCipherText);
        val clZkCipher = ClientZkGroupCipher(gsp);

        return clZkCipher.decrypt(cipherText).toServiceIdFixedWidthBinary()
    }

    private fun groupSecretParamsEncryptProfileKey(sGroupSecretParams: ByteArray, rawProfileKey: ByteArray, fixedWidthAci: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams);
        val pk = ProfileKey(rawProfileKey);
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci)
        val clZkCipher = ClientZkGroupCipher(gsp);

        return clZkCipher.encryptProfileKey(pk, aci).serialize()
    }

    private fun groupSecretParamsDecryptProfileKey(sGroupSecretParams: ByteArray, rawProfileKeyCipherText: ByteArray, fixedWidthAci: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams);
        val pkct = ProfileKeyCiphertext(rawProfileKeyCipherText);
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci);
        val clZkCipher = ClientZkGroupCipher(gsp);

        return clZkCipher.decryptProfileKey(pkct, aci).serialize();
    }

    private fun groupSecretParamsEncryptBlobWithPaddingDeterministic(sGroupSecretParams: ByteArray, randomNess: ByteArray, plainText: ByteArray, paddingLen: Int) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams);
        val clZkCipher = ClientZkGroupCipher(gsp);

        return clZkCipher.encryptBlob(SecureRandom(randomNess), plainText);
    }

    private fun groupSecretParamsDecryptBlobWithPadding(sGroupSecretParams: ByteArray, blobCipherText: ByteArray) : ByteArray {
        val gsp = GroupSecretParams(sGroupSecretParams);
        val clZkCipher = ClientZkGroupCipher(gsp);

        return clZkCipher.decryptBlob(blobCipherText);
    }

    private fun expiringProfileKeyCredentialGetExpirationTime(sExpiringProfileKeyCredential: ByteArray) : Long {
        val expkc = ExpiringProfileKeyCredential(sExpiringProfileKeyCredential);

        return expkc.expirationTime.epochSecond;
    }

    private fun profileKeyCredentialPresentationGetUuidCiphertext(sProfileKeyCredentialPresentation: ByteArray) : ByteArray {
        val pkcp = ProfileKeyCredentialPresentation(sProfileKeyCredentialPresentation);

        return pkcp.uuidCiphertext.serialize();
    }

    private fun profileKeyCredentialPresentationGetProfileKeyCiphertext(sProfileKeyCredentialPresentation: ByteArray) : ByteArray {
        val pkcp = ProfileKeyCredentialPresentation(sProfileKeyCredentialPresentation);

        return pkcp.profileKeyCiphertext.serialize();
    }

    private fun profileKeyCredentialRequestContextGetRequest(sProfileKeyCredentialRequestContext: ByteArray) : ByteArray {
        val pkcrc = ProfileKeyCredentialRequestContext(sProfileKeyCredentialRequestContext);

        return pkcrc.request.serialize();
    }

    private fun serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic(sServerPublicParams: ByteArray, randomness: ByteArray, fixedWidthAci: ByteArray, sProfileKey: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sServerPublicParams);
        val clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams);
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci);
        val profileKey = ProfileKey(sProfileKey);
        return clientZkProfileOperation.createProfileKeyCredentialRequestContext(SecureRandom(randomness), aci, profileKey).serialize();
    }

    private fun serverPublicParamsReceiveExpiringProfileKeyCredential(sServerPublicParams: ByteArray, sProfileKeyCredReqCtx: ByteArray, sExpProfileKeyCredResponse: ByteArray, ts: Long) : ByteArray {
        val serverPublicParams = ServerPublicParams(sServerPublicParams);
        val clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams);
        val pkCredReqCtx = ProfileKeyCredentialRequestContext(sProfileKeyCredReqCtx);
        val pkExpCredResp = ExpiringProfileKeyCredentialResponse(sExpProfileKeyCredResponse);

        return clientZkProfileOperation.receiveExpiringProfileKeyCredential(pkCredReqCtx, pkExpCredResp).serialize();
    }

    private fun serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic(sServerPublicParams: ByteArray, randomness: ByteArray, sGpSecParams: ByteArray, sExpProfKeyCred: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sServerPublicParams);
        val clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams);
        val groupSecretParams = GroupSecretParams(sGpSecParams);
        val expProfKeyCredential = ExpiringProfileKeyCredential(sExpProfKeyCred);

        return clientZkProfileOperation.createProfileKeyCredentialPresentation(SecureRandom(randomness), groupSecretParams, expProfKeyCredential).serialize();
    }

    private fun authCredentialPresentationGetUuidCiphertext(sAuthCredPres: ByteArray) : ByteArray {
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPres);

        return authCredPresentation.uuidCiphertext.serialize();
    }

    private fun authCredentialPresentationGetPniCiphertext(sAuthCredPres: ByteArray) : ByteArray {
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPres);

        return authCredPresentation.pniCiphertext.serialize()
    }

    private fun authCredentialPresentationGetRedemptionTime(sAuthCredPres: ByteArray) : Long {
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPres);

        return authCredPresentation.redemptionTime.epochSecond
    }

    private fun serverPublicParamsReceiveAuthCredentialWithPniAsServiceId(sSrvPubParams: ByteArray, fixedWidthAci: ByteArray, fixedWidthPni: ByteArray, redemptionTime: Long, authCredPniResp: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sSrvPubParams);
        val clientZkAuthOperation = ClientZkAuthOperations(serverPublicParams);
        val aci = Aci.parseFromFixedWidthBinary(fixedWidthAci);
        val pni = Pni.parseFromFixedWidthBinary(fixedWidthPni);
        val authCredentialPniResponse = AuthCredentialWithPniResponse(authCredPniResp);

        return clientZkAuthOperation.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionTime, authCredentialPniResponse).serialize();
    }

    private fun serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic(sSrvPubParams: ByteArray, randomness: ByteArray, sGpSecParams: ByteArray, authCredPni: ByteArray) : ByteArray {
        val serverPublicParams = ServerPublicParams(sSrvPubParams);
        val clientZkAuthOperation = ClientZkAuthOperations(serverPublicParams);
        val gpSecretParams = GroupSecretParams(sGpSecParams);
        val authCredentialPni = AuthCredentialWithPni(authCredPni);

        return clientZkAuthOperation.createAuthCredentialPresentation(gpSecretParams, authCredentialPni).serialize();
    }

    private fun serverSecretParamsGenerateDeterministic(rndm: ByteArray) : ByteArray {
        val srvSecParams = ServerSecretParams.generate(SecureRandom(rndm));

        return srvSecParams.serialize();
    }

    private fun serverSecretParamsGetPublicParams(sSrvSecParams: ByteArray) : ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams)

        return srvSecParams.publicParams.serialize()
    }

    private fun serverSecretParamsSignDeterministic(sSrvSecParams: ByteArray, rndm: ByteArray, msg: ByteArray) : ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams)

        return srvSecParams.sign(SecureRandom(rndm), msg).serialize()
    }

    private fun serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic(sSrvSecParams: ByteArray, rndm: ByteArray, sAci: ByteArray, sPni: ByteArray, redemptionTime: Long): ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams);
        val serverAuthOp = ServerZkAuthOperations(srvSecParams);
        val aci = Aci.parseFromFixedWidthBinary(sAci);
        val pni = Pni.parseFromFixedWidthBinary(sPni);
        val authCredPniResp = serverAuthOp.issueAuthCredentialWithPniAsServiceId(SecureRandom(rndm), aci, pni, Instant.ofEpochSecond(redemptionTime))

        return authCredPniResp.serialize()
    }

    private fun serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic(sSrvSecParams: ByteArray, rndm: ByteArray, sAci: ByteArray, sPni: ByteArray, redemptionTime: Long): ByteArray {
        val srvSecParams = ServerSecretParams(sSrvSecParams);
        val serverAuthOp = ServerZkAuthOperations(srvSecParams);
        val aci = Aci.parseFromFixedWidthBinary(sAci);
        val pni = Pni.parseFromFixedWidthBinary(sPni);
        val authCredPniResp = serverAuthOp.issueAuthCredentialWithPniZkc(SecureRandom(rndm), aci, pni, Instant.ofEpochSecond(redemptionTime))

        return authCredPniResp.serialize()
    }

    private fun serverSecretParamsVerifyAuthCredentialPresentation(sSrvSecParams: ByteArray, sGpPublicParams: ByteArray, sAuthCredPresent: ByteArray, instant: Long) {
        val srvSecParams = ServerSecretParams(sSrvSecParams);
        val serverAuthOp = ServerZkAuthOperations(srvSecParams);
        val gpPubParams = GroupPublicParams(sGpPublicParams);
        val authCredPresentation = AuthCredentialPresentation(sAuthCredPresent)

        serverAuthOp.verifyAuthCredentialPresentation(gpPubParams, authCredPresentation, Instant.ofEpochSecond( instant))
    }

    private fun groupSecretParamsEncryptCiphertext(sGpSecParams: ByteArray, sServiceId: ByteArray): ByteArray {
        val gpSecParams = GroupSecretParams(sGpSecParams)
        val serviceId = ServiceId.parseFromFixedWidthBinary(sServiceId)
        val clZkGpCipher = ClientZkGroupCipher(gpSecParams)

        return clZkGpCipher.encrypt(serviceId).serialize()
    }

    private fun serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic(sSrvSecParams: ByteArray, rand: ByteArray, sProfCredRequest: ByteArray, sAci: ByteArray, sProfileKeyCommitment: ByteArray, expiration: Long): ByteArray {
        val SrvSecretParams = ServerSecretParams(sSrvSecParams)
        val SrvProfileOp = ServerZkProfileOperations(SrvSecretParams)
        val profCredRequest = ProfileKeyCredentialRequest(sProfCredRequest)
        val aci = Aci.parseFromFixedWidthBinary(sAci)
        val ProfCommitment = ProfileKeyCommitment(sProfileKeyCommitment)

        return SrvProfileOp.issueExpiringProfileKeyCredential(SecureRandom(rand),  profCredRequest, aci, ProfCommitment, Instant.ofEpochSecond(expiration)).serialize()
    }

    private fun serverSecretParamsVerifyProfileKeyCredentialPresentation(sSrvSecParams: ByteArray, sGpPublicParams: ByteArray, sProfileKeyCredentialPresentation: ByteArray, instant: Long) {
        val SrvSecretParams = ServerSecretParams(sSrvSecParams)
        val SrvProfileOp = ServerZkProfileOperations(SrvSecretParams)
        val GpPubParams = GroupPublicParams(sGpPublicParams)
        val ProfKeyCredPresentation = ProfileKeyCredentialPresentation(sProfileKeyCredentialPresentation)

        SrvProfileOp.verifyProfileKeyCredentialPresentation(GpPubParams,
            ProfKeyCredPresentation, Instant.ofEpochSecond(instant))
    }

    private fun Aes256GcmEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            gcmSpec
        )
        if (aad != null) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(plaintext)
    }

    private fun Aes256GcmDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            gcmSpec
        )
        if (aad != null) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(ciphertext)
    }

    private fun Aes256CbcEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(plaintext)
    }

    private fun Aes256CbcDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(ciphertext)
    }

    private fun HmacSHA256(key: ByteArray, data: ByteArray): ByteArray? {
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            val secretKey = SecretKeySpec(key, "HmacSHA256")
            mac.init(secretKey)
            mac.doFinal(data)
        } catch (e: Exception) {
            
            return null
        }
    }

    private fun ConstantTimeEqual(lhs: ByteArray, rhs: ByteArray): Boolean {
        if (lhs === rhs) return true

        if (lhs.size != rhs.size) return false

        var result = 0
        for (i in lhs.indices) {
            result = result or (lhs[i].toInt() xor rhs[i].toInt())
        }
        return result == 0
    }


    
    private fun groupSendFullTokenGetExpiration(sgpfulltoken: ByteArray): Number {
        val gpFullToken = GroupSendFullToken(sgpfulltoken)

        return gpFullToken.expiration.epochSecond
    }

    private fun groupSendFullTokenVerify(sgpfulltoken: ByteArray, fixedWidthIds: ByteArray, time: Long, gpsenddrivedkp: ByteArray) {
        val gpFullToken = GroupSendFullToken(sgpfulltoken)
        val serviceIds = parseFixedWidthServiceIds(fixedWidthIds)
        val groupSendKeyPair = GroupSendDerivedKeyPair(gpsenddrivedkp)

        gpFullToken.verify(serviceIds, Instant.ofEpochSecond(time), groupSendKeyPair)
    }

    private fun groupSendTokenToFullToken(sgpsendtoken: ByteArray, expTime: Long): ByteArray {
        val groupSendToken = GroupSendEndorsement.Token(sgpsendtoken)

        return groupSendToken.toFullToken(Instant.ofEpochSecond(expTime)).serialize()
    }

    private fun groupSendDerivedKeyPairForExpiration(expTime: Long, svSecParams: ByteArray): ByteArray {
        val serverSecParams = ServerSecretParams(svSecParams)

        return GroupSendDerivedKeyPair.forExpiration(Instant.ofEpochSecond(expTime), serverSecParams).serialize()
    }

    private fun groupSendEndorsementCombine(sendorseMents: Array<ByteArray>): ByteArray {
        val rr = sendorseMents.map { se -> GroupSendEndorsement(se) }

        return GroupSendEndorsement.combine(rr).serialize()
    }

    private fun groupSendEndorsementRemove(sgpsendendorsement: ByteArray, toRemove: ByteArray): ByteArray {
        val bGroupSendEndorsement = GroupSendEndorsement(sgpsendendorsement)
        val gpseToRemove = GroupSendEndorsement(toRemove)

        return bGroupSendEndorsement.byRemoving(gpseToRemove).serialize()
    }

    private fun groupSendEndorsementToToken(sgpsendendorsement: ByteArray, sGpSecParams: ByteArray): ByteArray {
        val groupSendEndorsement = GroupSendEndorsement(sgpsendendorsement)

        return groupSendEndorsement.toToken(GroupSecretParams(sGpSecParams)).serialize()
    }

    private fun groupSendEndorsementsResponseIssueDeterministic(uuidCipherTexts: ByteArray, gpsenddrivedkp: ByteArray, rndm: ByteArray): ByteArray {
        val serviceIds = parseUuidCipherTexts(uuidCipherTexts)
        val groupSendKeyPair = GroupSendDerivedKeyPair(gpsenddrivedkp)

        return GroupSendEndorsementsResponse.issue(serviceIds, groupSendKeyPair, SecureRandom(rndm)).serialize()
    }

    private fun groupSendEndorsementsResponseGetExpiration(gpSendEndResponse: ByteArray): Long {
        val groupSendEndResponse = GroupSendEndorsementsResponse(gpSendEndResponse)

        return groupSendEndResponse.expiration.epochSecond
    }

    private fun groupSendEndorsementsResponseReceiveAndCombineWithServiceIds(gpSendEndResponse: ByteArray, svcIds: ByteArray, userId: ByteArray, time: Long, gpSecParams: ByteArray, srvPubParams: ByteArray): List<ByteArray> {
        val groupSendEndResponse = GroupSendEndorsementsResponse(gpSendEndResponse)
        val serviceIds = parseFixedWidthServiceIds(svcIds)
        val userServiceId = Aci.parseFromFixedWidthBinary(userId)
        val groupSecretParams = GroupSecretParams(gpSecParams)
        val serverPublicParams = ServerPublicParams(srvPubParams)

        return groupSendEndResponse.receive(serviceIds, userServiceId, Instant.ofEpochSecond(time), groupSecretParams, serverPublicParams).endorsements.map { s -> s.serialize() }
    }

    private fun groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts(gpSendEndResponse: ByteArray, svcUuidIds: ByteArray, userId: ByteArray, time: Long, srvPubParams: ByteArray): List<ByteArray> {
        val groupSendEndResponse = GroupSendEndorsementsResponse(gpSendEndResponse)
        val serviceIds = parseUuidCipherTexts(svcUuidIds)
        val userServiceId = UuidCiphertext(userId)
        val serverPublicParams = ServerPublicParams(srvPubParams)

        return groupSendEndResponse.receive(serviceIds, userServiceId, Instant.ofEpochSecond(time), serverPublicParams).endorsements.map { s -> s.serialize() }
    }
}

fun parseUuidCipherTexts(raw: ByteArray): MutableList<UuidCiphertext> {
    if (raw.size % 65 != 0) {
        throw Error("invalid uuid ciphertexts length")
    }

    val clc: MutableList<UuidCiphertext> = mutableListOf()
    val count = raw.size / 65
    for (i in 1..count) {
        val cphtx = UuidCiphertext(raw.slice((i-1)*65..(i*65)-1).toByteArray())
        clc.add(cphtx)
    }

    return clc
}

fun parseFixedWidthServiceIds(raw: ByteArray): MutableList<ServiceId> {
    if (raw.size % 17 != 0) {
        throw Error("invalid service ids length")
    }

    val clc: MutableList<ServiceId> = mutableListOf()
    val count = raw.size / 17
    for (i in 1..count) {
        val svcid = ServiceId.parseFromFixedWidthBinary(raw.slice((i-1)*17..(i*17)-1).toByteArray())
        clc.add(svcid)
    }

    return clc
}