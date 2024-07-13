import ExpoModulesCore
import LibSignalClient
import SignalFfi
import Foundation

internal typealias ServiceIdStorage = SignalServiceIdFixedWidthBinaryBytes
typealias SignalServiceIdFixedWidthBinaryBytes = (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

public enum ServiceIdError: Error {
    case invalidServiceId
    case wrongServiceIdKind
    case invalidArgumentType
}
enum SignalFfiError: Error {
    case serviclogStringConversionFailed
    case serviceIdBinaryConversionFailed
    case serviceIdStringConversionFailed
}
internal typealias SignalFfiErrorRef = OpaquePointer
public enum SignalError: Error {
    case invalidState(String)
    case internalError(String)
    case nullParameter(String)
    case invalidArgument(String)
    case invalidType(String)
    case invalidUtf8String(String)
    case protobufError(String)
    case legacyCiphertextVersion(String)
    case unknownCiphertextVersion(String)
    case unrecognizedMessageVersion(String)
    case invalidMessage(String)
    case invalidKey(String)
    case invalidSignature(String)
    case fingerprintVersionMismatch(String)
    case fingerprintParsingError(String)
    case sealedSenderSelfSend(String)
    case untrustedIdentity(String)
    case invalidKeyIdentifier(String)
    case sessionNotFound(String)
    case invalidSession(String)
    case invalidRegistrationId(address: ProtocolAddress, message: String)
    case invalidSenderKeySession(distributionId: UUID, message: String)
    case duplicatedMessage(String)
    case verificationFailed(String)
    case nicknameCannotBeEmpty(String)
    case nicknameCannotStartWithDigit(String)
    case missingSeparator(String)
    case badDiscriminatorCharacter(String)
    case badNicknameCharacter(String)
    case nicknameTooShort(String)
    case nicknameTooLong(String)
    case usernameLinkInvalidEntropyDataLength(String)
    case usernameLinkInvalid(String)
    case usernameDiscriminatorCannotBeEmpty(String)
    case usernameDiscriminatorCannotBeZero(String)
    case usernameDiscriminatorCannotBeSingleDigit(String)
    case usernameDiscriminatorCannotHaveLeadingZeros(String)
    case usernameDiscriminatorTooLarge(String)
    case ioError(String)
    case invalidMediaInput(String)
    case unsupportedMediaInput(String)
    case callbackError(String)
    case webSocketError(String)
    case connectionTimeoutError(String)
    case networkProtocolError(String)
    case cdsiInvalidToken(String)
    case rateLimitedError(retryAfter: TimeInterval, message: String)
    case svrDataMissing(String)
    case svrRestoreFailed(String)
    case chatServiceInactive(String)

    case unknown(UInt32, String)
}


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

    Function("identityKeyPairSerialize") {(serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8]) -> Data in
        let publicKey = try PublicKey(serializedPublicKey)
        let privateKey = try PrivateKey(serializedPrivateKey)
        let identityKeyPair = IdentityKeyPair(publicKey: publicKey, privateKey: privateKey)
        return Data(identityKeyPair.serialize())  
    }

   Function("createAndProcessPreKeyBundle"){(
    registrationData: (String, Int),
    preKeyData: (Int, String),
    signedPreKeyData: (Int, String),
    base64SignedPreKeySignature: String,
    base64IdentityKey: String,
    ownerIdentityData: OwnerData,
    kyberPreKeyData: (Int, String)?,
    base64KyberPreKeySignature: String?
) throws -> (SerializedAddressedKeys, SerializedAddressedKeys) in

    let (base64OwnerKeypair, ownerRegistrationId) = ownerIdentityData
    guard let ownerKeypair = decodeBase64(base64OwnerKeypair) else {
        throw NSError(domain: "Invalid base64 owner keypair", code: 1, userInfo: nil)
    }
    let ownerIdentityKey = try IdentityKeyPair(data: ownerKeypair)
    let (address, registrationId) = registrationData
    let (preKeyId, base64PreKeyPublic) = preKeyData
    let (serviceId, deviceId) = try getDeviceIdAndServiceId(address: address)
    let (signedPreKeyId, base64SignedPreKeyPublic) = signedPreKeyData
    guard let signedPreKeyPublic = decodeBase64(base64SignedPreKeyPublic) else {
        throw NSError(domain: "Invalid base64 signed pre-key public", code: 1, userInfo: nil)
    }
    let signedPublicPreKey = try PublicKey( signedPreKeyPublic)
    guard let identityKey = decodeBase64(base64IdentityKey) else {
        throw NSError(domain: "Invalid base64 identity key", code: 1, userInfo: nil)
    }
    let idKey = try IdentityKey(data: identityKey)
    guard let preKeyPublic = decodeBase64(base64PreKeyPublic) else {
        throw NSError(domain: "Invalid base64 pre-key public", code: 1, userInfo: nil)
    }
    let publicPreKey = try PublicKey(data: preKeyPublic)
    let remoteProtoAddress = ProtocolAddress(serviceId: serviceId, deviceId: deviceId)

    let store = InMemorySignalProtocolStore(identityKeyPair: ownerIdentityKey, registrationId: ownerRegistrationId)
    let sessionBuilder = processPreKeyBundle(sessionStore: store, address: remoteProtoAddress)
    guard let signedPreKeySignature = decodeBase64(base64SignedPreKeySignature) else {
        throw NSError(domain: "Invalid base64 signed pre-key signature", code: 1, userInfo: nil)
    }

    if let kyberPreKeyData = kyberPreKeyData, let base64KyberPreKeySignature = base64KyberPreKeySignature {
        let (keyId, base64KyberPreKeyPublic) = kyberPreKeyData
        guard let kyberPreKeyPublic = decodeBase64(base64KyberPreKeyPublic) else {
            throw NSError(domain: "Invalid base64 kyber pre-key public", code: 1, userInfo: nil)
        }
        let pubKey = KEMPublicKey(data: kyberPreKeyPublic)
        guard let kyberPreKeySignature = decodeBase64(base64KyberPreKeySignature) else {
            throw NSError(domain: "Invalid base64 kyber pre-key signature", code: 1, userInfo: nil)
        }
        let bundle = PreKeyBundle(
            registrationId: registrationId,
            deviceId: deviceId,
            preKeyId: preKeyId,
            preKeyPublic: publicPreKey,
            signedPreKeyId: signedPreKeyId,
            signedPreKeyPublic: signedPublicPreKey,
            signedPreKeySignature: signedPreKeySignature,
            identityKey: idKey,
            keyId: keyId,
            kyberPreKeyPublic: pubKey,
            kyberPreKeySignature: kyberPreKeySignature
        )
        sessionBuilder.process(bundle: bundle)
    } else {
        let noKyberBundle = PreKeyBundle(
            registrationId: registrationId,
            deviceId: deviceId,
            preKeyId: preKeyId,
            preKeyPublic: publicPreKey,
            signedPreKeyId: signedPreKeyId,
            signedPreKeyPublic: signedPublicPreKey,
            signedPreKeySignature: signedPreKeySignature,
            identityKey: idKey
        )
        sessionBuilder.process(bundle: noKyberBundle)
    }

    let updatedInMemorySessionStore = updateSessionStoreState(from: store, remoteAddress: remoteProtoAddress)
    let updatedInMemoryIdentityStore = updateIdentityStoreState(from: store, remoteAddress: remoteProtoAddress)

    return (updatedInMemorySessionStore, updatedInMemoryIdentityStore)
}

    Function("privateKeyGenerate") {
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
            
    Function("serviceIdServiceIdString") { (fixedWidthServiceId: Data) -> String in
      let serviceIdString = try signalServiceIdServiceIdString(value: [UInt8](fixedWidthServiceId))
      return serviceIdString
    }

    Function("serviceIdServiceIdLog") { (fixedWidthServiceId: Data) -> String in
      let servicelogString = try signalServiceIdServiclogString(value: [UInt8](fixedWidthServiceId))
      return servicelogString
    }

       Function("serviceIdParseFromServiceIdString") { (serviceIdString: String) -> Data in
            return Data(try serviceIdParseFromServiceIdString(serviceIdString: serviceIdString))
        }

    Function("serviceIdServiceIdBinary") { (fixedWidthServiceId: Data) -> Data in
            var bytes: SignalServiceIdFixedWidthBinaryBytes = convertDataToServiceIdStorage(data: fixedWidthServiceId)
            return Data(try signalServiceIdServiceIdBinary(value: &bytes))
    }


        Function("serviceIdParseFromServiceIdBinary") { (serviceIdBinary: Data) -> Data in
            return Data(try serviceIdParseFromServiceIdBinary(serviceIdBinary: serviceIdBinary))
        }

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

    Function("kyberPreKeyRecordGetPublicKey") { (record: [UInt8]) -> Data in
      let rec = try KyberPreKeyRecord(bytes: record)
      return Data(rec.keyPair.publicKey.serialize())
    }

    Function("kyberPreKeyRecordGetSecretKey") { (record: [UInt8]) -> Data in
      let rec = try KyberPreKeyRecord(bytes: record)
      return Data(rec.keyPair.secretKey.serialize())
    }

    Function("kyberPreKeyRecordGetSignature") { (record: [UInt8]) -> Data in
      let rec = try KyberPreKeyRecord(bytes: record)
      return Data(rec.signature)
    }

    Function("kyberPreKeyRecordGetTimestamp") { (record: [UInt8]) -> UInt64 in
      let rec = try KyberPreKeyRecord(bytes: record)
      return rec.timestamp
    }

    Function("privateKeyGenerate") { () -> [UInt8] in
      let keypair = IdentityKeyPair.generate()
      return keypair.privateKey.serialize()
    }

    Function("privateKeySign") { (serializedPrivateKey: [UInt8] , message: [UInt8]) -> Data in
      let privateKey = try PrivateKey(serializedPrivateKey)
      return Data(privateKey.generateSignature(message:message))
    }

    Function("signedPreKeyRecordNew") {
      (
        id: UInt32, timestamp: UInt64, serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8],
        signature: Data
      ) -> Data in
      let privateKey = try PrivateKey(serializedPrivateKey)
      return Data(
        try SignedPreKeyRecord(
          id: id, timestamp: timestamp, privateKey: privateKey, signature: signature
        ).serialize())
    }

    Function("signedPreKeyRecordGetId") { (record: Data) -> UInt32 in
      let rec = try SignedPreKeyRecord(bytes: record)
      return rec.id
    }

    Function("signedPreKeyRecordGetPrivateKey") { (record: Data) -> [UInt8] in
      let rec = try SignedPreKeyRecord(bytes: record)
      return rec.privateKey.serialize()
    }

    Function("signedPreKeyRecordGetPublicKey") { (record: Data) -> [UInt8] in
      let rec = try SignedPreKeyRecord(bytes: record)
      return rec.publicKey.serialize()
    }

    Function("signedPreKeyRecordGetSignature") { (record: Data) -> Data in
      let rec = try SignedPreKeyRecord(bytes: record)
      return Data(rec.signature)
    }

    Function("signedPreKeyRecordGetTimestamp") { (record: Data) -> UInt64 in
      let rec = try SignedPreKeyRecord(bytes: record)
      return rec.timestamp
    }

    Function("preKeyRecordNew") {
      (id: UInt32, serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8]) -> Data in
      let publicKey = try PublicKey(serializedPublicKey)
      let privateKey = try PrivateKey(serializedPrivateKey)
      return Data(
        try PreKeyRecord(id: id, publicKey: publicKey, privateKey: privateKey).serialize())
    }

    Function("preKeyRecordGetId") { (record: Data) -> UInt32 in
      let rec = try PreKeyRecord(bytes:record)
      return rec.id
    }

    Function("preKeyRecordGetPrivateKey") { (record: Data) -> [UInt8] in
      let rec = try PreKeyRecord(bytes:record)
      return rec.privateKey.serialize()
    }

    Function("preKeyRecordGetPublicKey") { (record: Data) -> [UInt8] in
      let rec = try PreKeyRecord(bytes:record)
      return rec.publicKey.serialize()
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

 private func decodeBase64(_ base64String: String) -> Data? {
    return Data(base64Encoded: base64String, options: .ignoreUnknownCharacters)
}

private func serviceIdParseFromServiceIdString(serviceIdString: String) throws -> [UInt8] {
    var output: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    let result = serviceIdString.withCString { cString in
        signal_service_id_parse_from_service_id_string(&output, cString)
    }
    if result != nil {
        
        throw SignalFfiError.serviceIdStringConversionFailed
    }
    let outputArray = withUnsafePointer(to: &output) {
        Array(UnsafeBufferPointer(start: $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size) { $0 }, count: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size))
    }
    return outputArray
}


private func convertDataToSignalBorrowedBuffer(data: Data) -> SignalBorrowedBuffer {
    return data.withUnsafeBytes { bytes in
        SignalBorrowedBuffer(base: bytes.bindMemory(to: UInt8.self).baseAddress, length: data.count)
    }
}


private func serviceIdParseFromServiceIdBinary(serviceIdBinary: Data) throws -> [UInt8] {
    var output: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    let borrowedBuffer = convertDataToSignalBorrowedBuffer(data: serviceIdBinary)
    let result = signal_service_id_parse_from_service_id_binary(&output, borrowedBuffer)
    if result != nil {
        
        throw SignalFfiError.serviceIdBinaryConversionFailed
    }
    let outputArray = withUnsafePointer(to: &output) {
        Array(UnsafeBufferPointer(start: $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size) { $0 }, count: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size))
    }
    return outputArray
}

      private func signalServiceIdServiceIdString(value: [UInt8]) throws -> String {
        
        guard value.count == 17 else {
            throw SignalFfiError.serviceIdStringConversionFailed
        }
        
        var result: UnsafePointer<CChar>?
        var storage: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        
        _ = value.withUnsafeBytes {
            memcpy(&storage, $0.baseAddress!, 17)
        }
        
        
        let error = signal_service_id_service_id_string(&result, &storage)
        
        
        if error != nil {
            throw SignalFfiError.serviceIdStringConversionFailed
        }
        
        
        guard let resultPointer = result, let serviceIdString = String(validatingUTF8: resultPointer) else {
            throw SignalFfiError.serviceIdStringConversionFailed
        }
        
        return serviceIdString
    }

     private func signalServiceIdServiclogString(value: [UInt8]) throws -> String {
        
        guard value.count == 17 else {
            throw SignalFfiError.serviclogStringConversionFailed
        }
        
        var result: UnsafePointer<CChar>?
        var storage: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        
        _ = value.withUnsafeBytes {
            memcpy(&storage, $0.baseAddress!, 17)
        }
        
        
        let error = signal_service_id_service_id_log(&result, &storage)
        
        
        if error != nil {
            throw SignalFfiError.serviclogStringConversionFailed
        }
        
        
        guard let resultPointer = result, let logStringString = String(validatingUTF8: resultPointer) else {
            throw SignalFfiError.serviclogStringConversionFailed
        }
        
        return logStringString
    }

private func getDeviceIdAndServiceId(address: String) throws -> (String, Int) {
    let components = address.split(separator: ".")
    guard components.count == 2, let deviceId = Int(components[1]) else {
        throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
    }
    let serviceId = String(components[0])
    return (serviceId, deviceId)
}

private func convertDataToServiceIdStorage(data: Data) -> SignalServiceIdFixedWidthBinaryBytes {
    var storage: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    _ = data.withUnsafeBytes { bytes in
        memcpy(&storage, bytes.baseAddress!, min(data.count, MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size))
    }
    return storage
}


internal func invokeFnReturningArray(fn: (UnsafeMutablePointer<SignalOwnedBuffer>?) -> SignalFfiErrorRef?) throws -> [UInt8] {
    var output = SignalOwnedBuffer()
    try checkError(fn(&output))
    let result = Array(UnsafeBufferPointer(start: output.base, count: output.length))
    signal_free_buffer(output.base, output.length)
    return result
}


private func signalServiceIdServiceIdBinary(value: inout SignalServiceIdFixedWidthBinaryBytes) throws -> [UInt8] {
    return try invokeFnReturningArray { outBuffer in
        signal_service_id_service_id_binary(outBuffer, &value)
    }
}

internal func invokeFnReturningString(fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?) throws -> String {
    try invokeFnReturningOptionalString(fn: fn)!
}

internal func invokeFnReturningOptionalString(fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?) throws -> String? {
    var output: UnsafePointer<Int8>?
    try checkError(fn(&output))
    if output == nil {
        return nil
    }
    let result = String(cString: output!)
    signal_free_string(output)
    return result
}

internal func checkError(_ error: SignalFfiErrorRef?) throws {
    guard let error = error else { return }

    let errType = signal_error_get_type(error)
    
    let errStr = try! invokeFnReturningString {
        signal_error_get_message(error, $0)
    }
    defer { signal_error_free(error) }

    switch SignalErrorCode(errType) {
    case SignalErrorCodeInvalidState:
        throw SignalError.invalidState(errStr)
    case SignalErrorCodeInternalError:
        throw SignalError.internalError(errStr)
    case SignalErrorCodeNullParameter:
        throw SignalError.nullParameter(errStr)
    case SignalErrorCodeInvalidArgument:
        throw SignalError.invalidArgument(errStr)
    case SignalErrorCodeInvalidType:
        throw SignalError.invalidType(errStr)
    case SignalErrorCodeInvalidUtf8String:
        throw SignalError.invalidUtf8String(errStr)
    case SignalErrorCodeProtobufError:
        throw SignalError.protobufError(errStr)
    case SignalErrorCodeLegacyCiphertextVersion:
        throw SignalError.legacyCiphertextVersion(errStr)
    case SignalErrorCodeUnknownCiphertextVersion:
        throw SignalError.unknownCiphertextVersion(errStr)
    case SignalErrorCodeUnrecognizedMessageVersion:
        throw SignalError.unrecognizedMessageVersion(errStr)
    case SignalErrorCodeInvalidMessage:
        throw SignalError.invalidMessage(errStr)
    case SignalErrorCodeFingerprintParsingError:
        throw SignalError.fingerprintParsingError(errStr)
    case SignalErrorCodeSealedSenderSelfSend:
        throw SignalError.sealedSenderSelfSend(errStr)
    case SignalErrorCodeInvalidKey:
        throw SignalError.invalidKey(errStr)
    case SignalErrorCodeInvalidSignature:
        throw SignalError.invalidSignature(errStr)
    case SignalErrorCodeFingerprintVersionMismatch:
        throw SignalError.fingerprintVersionMismatch(errStr)
    case SignalErrorCodeUntrustedIdentity:
        throw SignalError.untrustedIdentity(errStr)
    case SignalErrorCodeInvalidKeyIdentifier:
        throw SignalError.invalidKeyIdentifier(errStr)
    case SignalErrorCodeSessionNotFound:
        throw SignalError.sessionNotFound(errStr)
    case SignalErrorCodeInvalidSession:
        throw SignalError.invalidSession(errStr)
    case SignalErrorCodeDuplicatedMessage:
        throw SignalError.duplicatedMessage(errStr)
    case SignalErrorCodeVerificationFailure:
        throw SignalError.verificationFailed(errStr)
    case SignalErrorCodeUsernameCannotBeEmpty:
        throw SignalError.nicknameCannotBeEmpty(errStr)
    case SignalErrorCodeUsernameCannotStartWithDigit:
        throw SignalError.nicknameCannotStartWithDigit(errStr)
    case SignalErrorCodeUsernameMissingSeparator:
        throw SignalError.missingSeparator(errStr)
    case SignalErrorCodeUsernameBadDiscriminatorCharacter:
        throw SignalError.badDiscriminatorCharacter(errStr)
    case SignalErrorCodeUsernameBadNicknameCharacter:
        throw SignalError.badNicknameCharacter(errStr)
    case SignalErrorCodeUsernameTooShort:
        throw SignalError.nicknameTooShort(errStr)
    case SignalErrorCodeUsernameTooLong:
        throw SignalError.nicknameTooLong(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotBeEmpty:
        throw SignalError.usernameDiscriminatorCannotBeEmpty(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotBeZero:
        throw SignalError.usernameDiscriminatorCannotBeZero(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotBeSingleDigit:
        throw SignalError.usernameDiscriminatorCannotBeSingleDigit(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotHaveLeadingZeros:
        throw SignalError.usernameDiscriminatorCannotHaveLeadingZeros(errStr)
    case SignalErrorCodeUsernameDiscriminatorTooLarge:
        throw SignalError.usernameDiscriminatorTooLarge(errStr)
    case SignalErrorCodeUsernameLinkInvalidEntropyDataLength:
        throw SignalError.usernameLinkInvalidEntropyDataLength(errStr)
    case SignalErrorCodeUsernameLinkInvalid:
        throw SignalError.usernameLinkInvalid(errStr)
    case SignalErrorCodeIoError:
        throw SignalError.ioError(errStr)
    case SignalErrorCodeInvalidMediaInput:
        throw SignalError.invalidMediaInput(errStr)
    case SignalErrorCodeUnsupportedMediaInput:
        throw SignalError.unsupportedMediaInput(errStr)
    case SignalErrorCodeCallbackError:
        throw SignalError.callbackError(errStr)
    case SignalErrorCodeWebSocket:
        throw SignalError.webSocketError(errStr)
    case SignalErrorCodeConnectionTimedOut:
        throw SignalError.connectionTimeoutError(errStr)
    case SignalErrorCodeNetworkProtocol:
        throw SignalError.networkProtocolError(errStr)
    case SignalErrorCodeCdsiInvalidToken:
        throw SignalError.cdsiInvalidToken(errStr)
    case SignalErrorCodeSvrDataMissing:
        throw SignalError.svrDataMissing(errStr)
    case SignalErrorCodeSvrRestoreFailed:
        throw SignalError.svrRestoreFailed(errStr)
    case SignalErrorCodeChatServiceInactive:
        throw SignalError.chatServiceInactive(errStr)
    default:
        throw SignalError.unknown(errType, errStr)
    }
}



}
