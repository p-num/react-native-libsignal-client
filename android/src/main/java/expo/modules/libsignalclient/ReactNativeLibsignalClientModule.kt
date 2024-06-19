package expo.modules.libsignalclient

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.IdentityKey


class ReactNativeLibsignalClientModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ReactNativeLibsignalClient")

    Function("generatePrivateKey", this@ReactNativeLibsignalClientModule::generatePrivateKey)
    Function("privateKeySign", this@ReactNativeLibsignalClientModule::privateKeySign)
    Function("privateKeyAgree", this@ReactNativeLibsignalClientModule::privateKeyAgree)
    Function("publicKeyCompare", this@ReactNativeLibsignalClientModule::publicKeyCompare)
    Function("publicKeyGetPublicKeyBytes", this@ReactNativeLibsignalClientModule::publicKeyGetPublicKeyBytes)
     Function("publicKeyVerify", this@ReactNativeLibsignalClientModule::publicKeyVerify)
    Function("identityKeyVerifyAlternateIdentity", this@ReactNativeLibsignalClientModule::identityKeyVerifyAlternateIdentity)
    Function("generateIdentityKeyPair", this@ReactNativeLibsignalClientModule::generateIdentityKeyPair)
    Function("generateKyberKeyPair", this@ReactNativeLibsignalClientModule::generateKyberKeyPair)
    Function("generateKyberRecord", this@ReactNativeLibsignalClientModule::generateKyberRecord)
    Function("kyberPreKeyRecordGetId", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetId)
    Function("kyberPreKeyRecordGetPublicKey", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetPublicKey)
    Function("kyberPreKeyRecordGetSecretKey", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetSecretKey)
    Function("kyberPreKeyRecordGetSignature", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetSignature)
    Function("kyberPreKeyRecordGetTimestamp", this@ReactNativeLibsignalClientModule::kyberPreKeyRecordGetTimestamp)
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
}
