package expo.modules.libsignalclient

import android.os.Build
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import android.util.Base64
import androidx.annotation.RequiresApi
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import java.time.Instant

typealias StringifiedProtocolAddress = String
typealias SerializedAddressedKeys = Map<StringifiedProtocolAddress, String>
typealias RegistrationId = Int
typealias OwnerData = Pair<String, RegistrationId>

fun updateSessionStoreStateFromInMemorySessionStore(store: InMemorySignalProtocolStore, address: SignalProtocolAddress ): SerializedAddressedKeys {
  val sessionRecords = store.loadExistingSessions(listOf(address))
  val updatedStore = mutableMapOf<String, String>() ;
  for (sessionRecord in sessionRecords) {
    updatedStore[address.toString()] =  Base64.encodeToString(sessionRecord.serialize(), Base64.NO_WRAP)
  }
  return updatedStore
}

fun updateIdentityStoreStateFromInMemoryIdentityStore(store: InMemorySignalProtocolStore, address: SignalProtocolAddress): SerializedAddressedKeys {
    val identityKey = store.getIdentity(address)
    val updatedStore = mutableMapOf<String, String>() ;
    updatedStore[address.toString()] =  Base64.encodeToString(identityKey.serialize(), Base64.NO_WRAP)
    return updatedStore
}
@RequiresApi(Build.VERSION_CODES.O)
class ReactNativeLibsignalClientModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ReactNativeLibsignalClient")

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
     val (serviceId, deviceId) = address.split(".")
     val (signedPreKeyId, base64SignedPreKeyPublic) = signedPreKeyData
     val signedPreKeyPublic = Base64.decode(base64SignedPreKeyPublic, Base64.NO_WRAP)
     val signedPublicPreKey = ECPublicKey(signedPreKeyPublic)
     val identityKey = Base64.decode(base64IdentityKey, Base64.NO_WRAP)
     val idKey = IdentityKey(identityKey)
       val preKeyPublic = Base64.decode(base64PreKeyPublic, Base64.NO_WRAP)
     val publicPreKey = ECPublicKey(preKeyPublic)
     val remoteProtoAddress = SignalProtocolAddress(serviceId, deviceId.toInt())

     val store = InMemorySignalProtocolStore(ownerIdentityKey, ownerRegistrationId)
     val sessionBuilder = SessionBuilder(store, remoteProtoAddress)

     if (kyberPreKeyData !== null && base64KyberPreKeySignature !== null) {
       val (keyId, base64KyberPreKeyPublic) = kyberPreKeyData;
         val kyberPreKeyPublic = Base64.decode(base64KyberPreKeyPublic, Base64.NO_WRAP)
       val pubKey = KEMPublicKey(kyberPreKeyPublic)
       val kyberPreKeySignature = Base64.decode(base64KyberPreKeySignature, Base64.NO_WRAP)
       val bundle = PreKeyBundle(
         registrationId,
         deviceId.toInt(),
         preKeyId,
         publicPreKey,
         signedPreKeyId,
         signedPublicPreKey,
           kyberPreKeySignature,
         idKey,
         keyId,
         pubKey,
         kyberPreKeySignature
       )
       sessionBuilder.process(bundle)
     } else {
         val signedPreKeySignature = Base64.decode(base64SignedPreKeySignature, Base64.NO_WRAP)
       val noKyberBundle = PreKeyBundle(
         registrationId,
         deviceId.toInt(),
         preKeyId,
         publicPreKey,
         signedPreKeyId,
         signedPublicPreKey,
         signedPreKeySignature,
         idKey,
       )
       sessionBuilder.process(noKyberBundle)
     }
     val updatedInMemorySessionStore = updateSessionStoreStateFromInMemorySessionStore(store, remoteProtoAddress)
     val updatedInMemoryIdentityStore = updateIdentityStoreStateFromInMemoryIdentityStore(store, remoteProtoAddress)
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
    private fun sessionRecordArchiveCurrentState(record: ByteArray) {
        val rec = SessionRecord(record)
      return rec.archiveCurrentState()
    }
    private fun sessionRecordGetLocalRegistrationId(record: ByteArray) : Int {
        val rec = SessionRecord(record)
        return rec.localRegistrationId
    }
    private fun sessionRecordGetRemoteRegistrationId(record: ByteArray) : Int {
        val rec = SessionRecord(record)
        return rec.remoteRegistrationId
    }
    private fun sessionRecordHasUsableSenderChain(record: ByteArray) : Boolean {
        val rec = SessionRecord(record)
        return rec.hasSenderChain(Instant.now())
    }
    private fun sessionRecordCurrentRatchetKeyMatches(record: ByteArray, pubKey : ByteArray) : Boolean {
        val ecPublicKey = ECPublicKey(pubKey)
        val rec = SessionRecord(record)
        return rec.currentRatchetKeyMatches(ecPublicKey)
    }
}
