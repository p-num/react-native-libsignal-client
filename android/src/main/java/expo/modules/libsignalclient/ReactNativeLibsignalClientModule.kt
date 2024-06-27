package expo.modules.libsignalclient

import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.signal.libsignal.metadata.SealedSessionCipher
import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.signal.libsignal.metadata.certificate.InvalidCertificateException
import org.signal.libsignal.metadata.certificate.SenderCertificate
import org.signal.libsignal.metadata.certificate.ServerCertificate
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent
import org.signal.libsignal.protocol.*
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
import org.signal.libsignal.protocol.state.impl.InMemorySessionStore
import org.signal.libsignal.protocol.util.KeyHelper
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.UUID
import javax.crypto.SealedObject
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

      // Function("serviceIdServiceIdBinary", this@ReactNativeLibsignalClientModule::serviceIdServiceIdBinary)
      // Function("serviceIdServiceIdString", this@ReactNativeLibsignalClientModule::serviceIdServiceIdString)
      // Function("serviceIdServiceIdLog", this@ReactNativeLibsignalClientModule::serviceIdServiceIdLog)
      // Function("serviceIdParseFromServiceIdBinary", this@ReactNativeLibsignalClientModule::serviceIdParseFromServiceIdBinary)
      // Function("serviceIdParseFromServiceIdString", this@ReactNativeLibsignalClientModule::serviceIdParseFromServiceIdString)

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

      Function("generatePrivateKey", this@ReactNativeLibsignalClientModule::generatePrivateKey)
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
//      DecryptionErrorMessageForOriginalMessage
//      DecryptionErrorMessageExtractFromSerializedContent
//      DecryptionErrorMessageGetTimestamp
//      DecryptionErrorMessageGetDeviceId
//      DecryptionErrorMessageGetRatchetKey
    Function("decryptionErrorMessageForOriginalMessage", this@ReactNativeLibsignalClientModule::decryptionErrorMessageForOriginalMessage)
    Function("decryptionErrorMessageExtractFromSerializedContent", this@ReactNativeLibsignalClientModule::decryptionErrorMessageExtractFromSerializedContent)
    Function("decryptionErrorMessageGetTimestamp", this@ReactNativeLibsignalClientModule::decryptionErrorMessageGetTimestamp)
    Function("decryptionErrorMessageGetDeviceId", this@ReactNativeLibsignalClientModule::decryptionErrorMessageGetDeviceId)
    Function("decryptionErrorMessageGetRatchetKey", 
    this@ReactNativeLibsignalClientModule::decryptionErrorMessageGetRatchetKey)
    // signalMessageGetBody
    // signalMessageGetCounter
    // SignalMessageGetMessageVersion
    // SignalMessageVerifyMac
    // this is not used anywhere in app but is useful for testing things separately
    // Function("signalMessageNew", this@ReactNativeLibsignalClientModule::signalMessageNew)
    Function("signalMessageGetBody", this@ReactNativeLibsignalClientModule::signalMessageGetBody)
    Function("signalMessageGetCounter", this@ReactNativeLibsignalClientModule::signalMessageGetCounter)
    Function("signalMessageGetMessageVersion", this@ReactNativeLibsignalClientModule::signalMessageGetMessageVersion)
    Function("signalMessageVerifyMac", this@ReactNativeLibsignalClientModule::signalMessageVerifyMac)
//      PreKeySignalMessage_GetPreKeyId
//      PreKeySignalMessage_GetRegistrationId
//      PreKeySignalMessage_GetSignedPreKeyId
//      PreKeySignalMessage_GetVersion
      Function("preKeySignalMessageGetPreKeyId", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetPreKeyId)
        Function("preKeySignalMessageGetRegistrationId", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetRegistrationId)
        Function("preKeySignalMessageGetSignedPreKeyId", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetSignedPreKeyId)
        Function("preKeySignalMessageGetVersion", this@ReactNativeLibsignalClientModule::preKeySignalMessageGetVersion)


//      SenderKeyMessage_GetCipherText
//      SenderKeyMessage_GetIteration
//      SenderKeyMessage_GetChainId
//      SenderKeyMessage_GetDistributionId
//      SenderKeyMessage_VerifySignature
        Function("senderKeyMessageGetCipherText", this@ReactNativeLibsignalClientModule::senderKeyMessageGetCipherText)
        Function("senderKeyMessageGetIteration", this@ReactNativeLibsignalClientModule::senderKeyMessageGetIteration)
        Function("senderKeyMessageGetChainId", this@ReactNativeLibsignalClientModule::senderKeyMessageGetChainId)
        Function("senderKeyMessageGetDistributionId", this@ReactNativeLibsignalClientModule::senderKeyMessageGetDistributionId)
        Function("senderKeyMessageVerifySignature", this@ReactNativeLibsignalClientModule::senderKeyMessageVerifySignature)
//      sessionCipherDecryptSignalMessage
//      sessionCipherDecryptPreKeySignalMessage
        Function("sessionCipherDecryptSignalMessage", this@ReactNativeLibsignalClientModule::sessionCipherDecryptSignalMessage)
        Function("sessionCipherDecryptPreKeySignalMessage", this@ReactNativeLibsignalClientModule::sessionCipherDecryptPreKeySignalMessage)
        Function("hkdfDeriveSecrets", this@ReactNativeLibsignalClientModule::hkdfDeriveSecrets)
        // senderKeyDistributionMessageGetChainKey
        // senderKeyDistributionMessageGetIteration
        // senderKeyDistributionMessageGetChainId
        // senderKeyDistributionMessageGetDistributionId
        Function("senderKeyDistributionMessageGetChainKey", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetChainKey)
        Function("senderKeyDistributionMessageGetIteration", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetIteration)
        Function("senderKeyDistributionMessageGetChainId", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetChainId)
        Function("senderKeyDistributionMessageGetDistributionId", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageGetDistributionId)

//      senderKeyDistributionMessageProcess
      Function("senderKeyDistributionMessageProcess", this@ReactNativeLibsignalClientModule::senderKeyDistributionMessageProcess)

//      unidentifiedSenderMessageContentGetContents
//      unidentifiedSenderMessageContentGetMsgType
//      unidentifiedSenderMessageContentGetSenderCert
//      unidentifiedSenderMessageContentGetContentHint
//      unidentifiedSenderMessageContentGetGroupId
      Function("unidentifiedSenderMessageContentGetContents", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetContents)
      Function("unidentifiedSenderMessageContentGetMsgType", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetMsgType)
      Function("unidentifiedSenderMessageContentGetSenderCert", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetSenderCert)
      Function("unidentifiedSenderMessageContentGetContentHint", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetContentHint)
      Function("unidentifiedSenderMessageContentGetGroupId", this@ReactNativeLibsignalClientModule::unidentifiedSenderMessageContentGetGroupId)

      Function("generateRegistrationId", this@ReactNativeLibsignalClientModule::generateRegistrationId)
  }

  private fun generatePrivateKey() : ByteArray {
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


  // private fun SignedPreKeyRecord_New(id: Int, timestamp: Long, pubKey: Long, privKey: Long, signature: ByteArray) : Long {
  //   return Native.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature)
  // }
  // private fun SignedPreKeyRecord_GetId(signedPreKeyRecord: Long) : Int {
  //   return Native.SignedPreKeyRecord_GetId(signedPreKeyRecord)
  // }
  // private fun SignedPreKeyRecord_GetPrivateKey(signedPreKeyRecord: Long) : Long {
  //   return Native.SignedPreKeyRecord_GetPrivateKey(signedPreKeyRecord)
  // }
  // private fun SignedPreKeyRecord_GetPublicKey(signedPreKeyRecord: Long) : Long {
  //   return Native.SignedPreKeyRecord_GetPublicKey(signedPreKeyRecord)
  // }
  // private fun SignedPreKeyRecord_GetSignature(signedPreKeyRecord: Long) : ByteArray {
  //   return Native.SignedPreKeyRecord_GetSignature(signedPreKeyRecord)
  // }
  // private fun SignedPreKeyRecord_GetTimestamp(signedPreKeyRecord: Long) : Long {
  //   return Native.SignedPreKeyRecord_GetTimestamp(signedPreKeyRecord)
  // }

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

//  private fun PreKeyRecord_New(id: Int, pubKey: Long, privKey: Long) : Long {
//    return Native.PreKeyRecord_New(id, pubKey, privKey)
//  }
//  private fun PreKeyRecord_Deserialize(serialized: ByteArray) : Long {
//    return Native.PreKeyRecord_Deserialize(serialized)
//  }
//  private fun PreKeyRecord_GetId(preKeyRecord: Long) : Int {
//    return Native.PreKeyRecord_GetId(preKeyRecord)
//  }
//  private fun PreKeyRecord_GetPrivateKey(preKeyRecord: Long) : Long {
//    return Native.PreKeyRecord_GetPrivateKey(preKeyRecord)
//  }
//  private fun PreKeyRecord_GetPublicKey(preKeyRecord: Long) : Long {
//    return Native.PreKeyRecord_GetPublicKey(preKeyRecord)
//  }
//  private fun PreKeyRecord_Serialize(preKeyRecord: Long) : ByteArray {
//    return Native.PreKeyRecord_GetSerialized(preKeyRecord)
//  }

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

  //      private fun SessionRecord_ArchiveCurrentState(sessionRecord: Long) {
  //    return Native.SessionRecord_ArchiveCurrentState(sessionRecord)
  //  }
  // private fun SessionRecord_GetLocalRegistrationId(sessionRecord: Long) : Int {
  //   return Native.SessionRecord_GetLocalRegistrationId(sessionRecord)
  // }
  // private fun SessionRecord_GetRemoteRegistrationId(sessionRecord: Long) : Int {
  //   return Native.SessionRecord_GetRemoteRegistrationId(sessionRecord)
  // }
  // private fun SessionRecord_HasUsableSenderChain(sessionRecord: Long, now: Long) : Boolean {
  //   return Native.SessionRecord_HasUsableSenderChain(sessionRecord, now)
  // }
  // private fun SessionRecord_CurrentRatchetKeyMatches(sessionRecord: Long, publicKey: Long) : Boolean {
  //   return Native.SessionRecord_CurrentRatchetKeyMatches(sessionRecord, publicKey)
  // }
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

    private fun generateRegistrationId(): Int {
        return KeyHelper.generateRegistrationId(false)
    }
}
