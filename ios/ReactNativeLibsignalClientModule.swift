import ExpoModulesCore
import LibSignalClient

public class ReactNativeLibsignalClientModule: Module {

  public func definition() -> ModuleDefinition {

    Name("ReactNativeLibsignalClient")

    Constants([
      "PI": Double.pi
    ])

    Events("onChange")

    Function("hello") {
      return String(decoding: IdentityKeyPair.generate().publicKey.serialize(), as: UTF8.self)
    }

    Function("generateIdentityKeyPair") {
      return IdentityKeyPair.generate().serialize()
    }
    Function("generatePrivateKey") {
      return PrivateKey.generate().serialize()
    }

    Function("hkdfDeriveSecrets") {
      (outputLength: Int, inputKeyMaterial: Data, info: Data, salt: Data?) -> [UInt8] in
      return try hkdf(
        outputLength: outputLength,
        inputKeyMaterial: inputKeyMaterial,
        salt: salt ?? Data(),
        info: info
      )
    }

    // Function("serviceIdServiceIdString"){(fixedWidthServiceId : [UInt8]) -> String in
    // do {
    //       let serviceId = ServiceId(fromFixedWidthBinary: fixedWidthServiceId)
    //       return try serviceId.serviceIdString
    //   } catch {
    //       print("Error serviceIdServiceIdString: \(error)")
    //       return "Error serviceIdServiceIdString: \(error)"
    //   }

    // }

    Function("privateKeyGetPublicKey") { (serializedPrivateKey: [UInt8]) -> [UInt8]? in
      let privateKey = try PrivateKey(serializedPrivateKey)
      let publicKey = privateKey.publicKey
      let serializedPublicKey = publicKey.serialize()
      return serializedPublicKey
    }

    Function("generateKyberRecord") {
      (keyId: CGFloat, timestamp: CGFloat, privateKeySerialized: [UInt8]) -> [UInt8] in

      let finalTimestamp = NSNumber(value: Float(timestamp))
      let finalKeyId = NSNumber(value: Float(keyId))
      let privateKey = try PrivateKey(privateKeySerialized)
      let keyPairObject = KEMKeyPair.generate()
      let keyPairObjectPublicKey = keyPairObject.publicKey.serialize()
      let signature = privateKey.generateSignature(message: keyPairObjectPublicKey)
      let kyberRecord = try KyberPreKeyRecord(
        id: finalKeyId.uint32Value,
        timestamp: finalTimestamp.uint64Value,
        keyPair: keyPairObject,
        signature: signature
      )
      let serializedRecord = kyberRecord.serialize()
      return serializedRecord
    }

    Function("kyberPreKeyRecordGetId") { (record: [UInt8]) -> UInt32 in
      let rec = try KyberPreKeyRecord(bytes: record)
      return rec.id
    }

    Function("kyberPreKeyRecordGetPublicKey") { (record: [UInt8]) -> [UInt8] in
      let rec = try KyberPreKeyRecord(bytes: record)
      return rec.keyPair.publicKey.serialize()
    }

    Function("kyberPreKeyRecordGetSecretKey") { (record: [UInt8]) -> [UInt8] in
      let rec = try KyberPreKeyRecord(bytes: record)
      return rec.keyPair.secretKey.serialize()
    }

    Function("kyberPreKeyRecordGetSignature") { (record: [UInt8]) -> [UInt8] in
      let rec = try KyberPreKeyRecord(bytes: record)
      return rec.signature
    }

    Function("kyberPreKeyRecordGetTimestamp") { (record: [UInt8]) -> UInt64 in
      let rec = try KyberPreKeyRecord(bytes: record)
      return rec.timestamp
    }


 

    AsyncFunction("setValueAsync") { (value: String) in

      self.sendEvent(
        "onChange",
        [
          "value": value
        ])
    }

    View(ReactNativeLibsignalClientView.self) {

      Prop("name") { (view: ReactNativeLibsignalClientView, prop: String) in
        print(prop)
      }
    }
  }
}
