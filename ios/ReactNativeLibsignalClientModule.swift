import ExpoModulesCore
import LibSignalClient
import SignalFfi
import Foundation
/*START        typealias +  structs  + enums          START*/
typealias ServiceIdStorage = SignalServiceIdFixedWidthBinaryBytes
typealias SignalServiceIdFixedWidthBinaryBytes = (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
typealias StringifiedProtocolAddress = String
typealias SerializedAddressedKeys = [StringifiedProtocolAddress: String]
typealias RegistrationId = UInt32
typealias IdKey = String
typealias Keypair = String
typealias OwnerData = (keypair: Keypair, registrationId: RegistrationId)
typealias IdentityStoreData = (idKey: IdKey, ownerData: OwnerData)
typealias SignalFfiErrorRef = OpaquePointer
public struct NullContext: StoreContext {
    public init() {
    }

}
private struct SenderKeyName: Hashable {
    var sender: ProtocolAddress
    var distributionId: UUID
}
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
/*END          typealias +  structs  + enums              END*/
/*START        InMemorySignalProtocolStoreWithPreKeysList              START*/
open class InMemorySignalProtocolStoreWithPreKeysList: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore, SenderKeyStore {
    private var publicKeys: [ProtocolAddress: IdentityKey] = [:]
    private var privateKey: IdentityKeyPair
    private var registrationId: UInt32
    private var prekeyMap: [UInt32: PreKeyRecord] = [:]
    private var signedPrekeyMap: [UInt32: SignedPreKeyRecord] = [:]
    private var kyberPrekeyMap: [UInt32: KyberPreKeyRecord] = [:]
    private var kyberPrekeysUsed: Set<UInt32> = []
    private var sessionMap: [ProtocolAddress: SessionRecord] = [:]
    private var senderKeyMap: [SenderKeyName: SenderKeyRecord] = [:]
    public init() {
        self.privateKey = IdentityKeyPair.generate()
        self.registrationId = UInt32.random(in: 0...0x3FFF)
    }

    public init(identity: IdentityKeyPair, registrationId: UInt32) {
        self.privateKey = identity
        self.registrationId = registrationId
    }

    open func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair {
        return self.privateKey
    }

    open func localRegistrationId(context: StoreContext) throws -> UInt32 {
        return self.registrationId
    }

    open func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> Bool {
        if self.publicKeys.updateValue(identity, forKey: address) == nil {
            return false // newly created
        }
        else {
            return true
        }
    }

    open func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool {
        if let pk = publicKeys[address] {
            return pk == identity
        }
        else {
            return true // tofu
        }
    }

    open func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        return self.publicKeys[address]
    }

    open func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        if let record = prekeyMap[id] {
            return record
        }
        else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    open func loadPreKeys(context: StoreContext) throws -> [PreKeyRecord] {
        return Array(prekeyMap.values)
    }

    open func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws {
        self.prekeyMap[id] = record
    }

    open func removePreKey(id: UInt32, context: StoreContext) throws {
        self.prekeyMap.removeValue(forKey: id)
    }

    open func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        if let record = signedPrekeyMap[id] {
            return record
        }
        else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    open func loadSignedPreKeys(context: StoreContext) throws -> [SignedPreKeyRecord] {
        return Array(signedPrekeyMap.values)
    }

    open func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws {
        self.signedPrekeyMap[id] = record
    }

    open func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        if let record = kyberPrekeyMap[id] {
            return record
        }
        else {
            throw SignalError.invalidKeyIdentifier("no kyber prekey with this identifier")
        }
    }

    open func loadKyberPreKeys(context: StoreContext) throws -> [KyberPreKeyRecord] {
        return Array(kyberPrekeyMap.values)
    }

    open func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws {
        self.kyberPrekeyMap[id] = record
    }

    open func markKyberPreKeyUsed(id: UInt32, context: StoreContext) throws {
        self.kyberPrekeysUsed.insert(id)
    }

    open func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        return self.sessionMap[address]
    }

    open func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord] {
        return try addresses.map {
            address in
            if let session = sessionMap[address] {
                return session
            }
            throw SignalError.sessionNotFound("\(address)")
        }
    }

    open func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        self.sessionMap[address] = record
    }

    open func storeSenderKey(from sender: ProtocolAddress, distributionId: UUID, record: SenderKeyRecord, context: StoreContext) throws {
        self.senderKeyMap[SenderKeyName(sender: sender, distributionId: distributionId)] = record
    }

    open func loadSenderKey(from sender: ProtocolAddress, distributionId: UUID, context: StoreContext) throws -> SenderKeyRecord? {
        return self.senderKeyMap[SenderKeyName(sender: sender, distributionId: distributionId)]
    }

}
/*END          InMemorySignalProtocolStoreWithPreKeysList              END*/
public class ReactNativeLibsignalClientModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ReactNativeLibsignalClient")
        /*START          bridge functions definitions              START*/
        Function("generateIdentityKeyPair") {
            return IdentityKeyPair.generate().serialize()
        }
        Function("identityKeyPairSerialize") {
            (serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8]) -> Data in
            return try identityKeyPairSerializeHelper(serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey)
        }
        Function("sessionCipherEncryptMessage") {
            (base64Message: String, address: String, sessionStoreState: [String: String], identityKeyState: [Any], now: Int64) -> [Any] in
            return try sessionCipherEncryptMessageHelper(
                base64Message: base64Message,
                address: address,
                sessionStoreState: sessionStoreState,
                identityKeyState: identityKeyState,
                now: now)
        }
        Function("preKeySignalMessageGetRegistrationId") {
            (serializedMessage: [UInt8]) -> UInt32 in
            return try preKeySignalMessageGetRegistrationIdHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetSignedPreKeyId") {
            (serializedMessage: [UInt8]) -> UInt32 in
            return try preKeySignalMessageGetSignedPreKeyIdHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetVersion") {
            (serializedMessage: [UInt8]) -> UInt32 in
            return try preKeySignalMessageGetVersionHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetPreKeyId") {
            (serializedMessage: [UInt8]) -> UInt32? in
            return try preKeySignalMessageGetPreKeyIdHelper(serializedMessage: serializedMessage)
        }
        Function("createAndProcessPreKeyBundle") {
            (
                registrationData: [Any],
                preKeyData: [Any],
                signedPreKeyData: [Any],
                base64SignedPreKeySignature: String,
                base64IdentityKey: String,
                ownerIdentityData: [Any],
                kyberPreKeyData: [Any]?,
                base64KyberPreKeySignature: String?)
            throws -> [Any] in
            return try createAndProcessPreKeyBundleHelper(
                registrationData: registrationData,
                preKeyData: preKeyData,
                signedPreKeyData: signedPreKeyData,
                base64SignedPreKeySignature: base64SignedPreKeySignature,
                base64IdentityKey: base64IdentityKey,
                ownerIdentityData: ownerIdentityData,
                kyberPreKeyData: kyberPreKeyData,
                base64KyberPreKeySignature: base64KyberPreKeySignature)
        }
        Function("sessionCipherDecryptSignalMessage") {
            (
                serializedMessage: [UInt8],
                address: String,
                sessionStoreState: [String: String],
                identityKeyState: [Any])
            throws -> [Any] in
            return try sessionCipherDecryptSignalMessageHelper(
                serializedMessage: serializedMessage,
                address: address,
                sessionStoreState: sessionStoreState,
                identityKeyState: identityKeyState)
        }
        Function("sessionCipherDecryptPreKeySignalMessage") {
            (
                serializedMessage: [UInt8],
                address: String,
                ownerIdentityData: [Any],
                prekeyStoreState: SerializedAddressedKeys,
                signedPrekeyStoreState: SerializedAddressedKeys,
                kyberPrekeyStoreState: SerializedAddressedKeys)
            throws -> [Any] in
            return try sessionCipherDecryptPreKeySignalMessageHelper(
                serializedMessage: serializedMessage,
                address: address,
                ownerIdentityData: ownerIdentityData,
                prekeyStoreState: prekeyStoreState,
                signedPrekeyStoreState: signedPrekeyStoreState,
                kyberPrekeyStoreState: kyberPrekeyStoreState)
        }
        Function("decryptionErrorMessageForOriginalMessage") {
            (
                originalBytes: Data,
                messageType: Int,
                timestamp: Int64,
                originalSenderDeviceId: Int)
            -> Data in
            return try decryptionErrorMessageForOriginalMessageHelper(
                originalBytes: originalBytes,
                messageType: messageType,
                timestamp: timestamp,
                originalSenderDeviceId: originalSenderDeviceId)
        }
        Function("decryptionErrorMessageExtractFromSerializedContent") {
            (serializedContent: Data) -> Data in
            let content = try decryptionErrorMessageExtractFromSerializedContentHelper(serializedContent: serializedContent)
            return Data(content.serialize())
        }
        Function("decryptionErrorMessageGetTimestamp") {
            (serializedContent: Data) -> Int64 in
            return try decryptionErrorMessageGetTimestampHelper(serializedContent: serializedContent)
        }
        Function("decryptionErrorMessageGetDeviceId") {
            (serializedContent: Data) -> Int in
            return try decryptionErrorMessageGetDeviceIdHelper(serializedContent: serializedContent)
        }
        Function("decryptionErrorMessageGetRatchetKey") {
            (serializedContent: Data) -> Data? in
            return try decryptionErrorMessageGetRatchetKeyHelper(serializedContent: serializedContent)
        }
        Function("plaintextContentFromDecryptionErrorMessage") {
            (message: Data) -> Data in
            let plaintextContent = try! plaintextContentFromDecryptionErrorMessageHelper(message: message)
            return Data(plaintextContent.serialize())
        }
        Function("plaintextContentGetBody") {
            (message: Data) -> Data in
            return try! plaintextContentGetBodyHelper(message: message)
        }
        Function("publicKeyCompare") {
            (serializedPublicKey1: Data, otherSerializedPublicKey2: Data) throws -> Int32 in
            return try publicKeyCompareHelper(serializedPublicKey1: serializedPublicKey1, otherSerializedPublicKey2: otherSerializedPublicKey2)
        }
        Function("publicKeyGetPublicKeyBytes") {
            (serializedPublicKey: Data) throws -> Data in
            return try publicKeyGetPublicKeyBytesHelper(serializedPublicKey: serializedPublicKey)
        }
        Function("identityKeyVerifyAlternateIdentityWithIdentityKey") {
            (serializedIdentityKey: Data, otherPublicKey: Data, message: Data) throws -> Bool in
            return try identityKeyVerifyAlternateIdentityWithIdentityKeyHelper(serializedIdentityKey: serializedIdentityKey, otherPublicKey: otherPublicKey, message: message)
        }
        Function("sessionRecordArchiveCurrentState") {
            (record: Data) throws -> Data in
            return try sessionRecordArchiveCurrentStateHelper(record: record)
        }
        Function("sessionRecordGetRemoteRegistrationId") {
            (record: Data) throws -> UInt32 in
            return try sessionRecordGetRemoteRegistrationIdHelper(record: record)
        }
        Function("sessionRecordHasUsableSenderChain") {
            (record: Data, now: Int64) throws -> Bool in
            return try sessionRecordHasUsableSenderChainHelper(record: record, now: now)
        }
        Function("identityKeyVerifyAlternateIdentityWithPublicKey") {
            (serializedPublicKey: Data, message: Data, signature: Data) throws -> Bool in
            return try identityKeyVerifyAlternateIdentityWithPublicKeyHelper(serializedPublicKey: serializedPublicKey, message: message, signature: signature)
        }
        Function("sessionRecordCurrentRatchetKeyMatches") {
            (record: Data, pubKey: [UInt8]) throws -> Bool in
            return try sessionRecordCurrentRatchetKeyMatchesHelper(record: record, pubKey: pubKey)
        }
        Function("privateKeyGenerate") {
            return PrivateKey.generate().serialize()
        }
        Function("hkdfDeriveSecrets") {
            (outputLength: Int, inputKeyMaterial: Data, info: Data, salt: Data?) -> [UInt8] in
            return try hkdfDeriveSecretsHelper(
                outputLength: outputLength,
                inputKeyMaterial: inputKeyMaterial,
                info: info,
                salt: salt ?? Data())
        }
        Function("serviceIdServiceIdString") {
            (fixedWidthServiceId: Data) -> String in
            return try serviceIdServiceIdStringHelper(fixedWidthServiceId: [UInt8](fixedWidthServiceId))
        }
        Function("serviceIdServiceIdLog") {
            (fixedWidthServiceId: Data) -> String in
            return try serviceIdServiceIdLogHelper(fixedWidthServiceId: [UInt8](fixedWidthServiceId))
        }
        Function("serviceIdParseFromServiceIdString") {
            (serviceIdString: String) -> Data in
            return Data(try serviceIdParseFromServiceIdStringHelper(serviceIdString: serviceIdString))
        }
        Function("serviceIdServiceIdBinary") {
            (fixedWidthServiceId: Data) -> Data in
            return Data(try serviceIdServiceIdBinaryHelper(fixedWidthServiceId: fixedWidthServiceId))
        }
        Function("serviceIdParseFromServiceIdBinary") {
            (serviceIdBinary: Data) -> Data in
            return Data(try serviceIdParseFromServiceIdBinaryHelper(serviceIdBinary: serviceIdBinary))
        }
        Function("privateKeyGetPublicKey") {
            (serializedPrivateKey: [UInt8]) -> [UInt8]? in
            return try privateKeyGetPublicKeyHelper(serializedPrivateKey: serializedPrivateKey)
        }
        Function("generateKyberRecord") {
            (keyId: CGFloat, timestamp: CGFloat, privateKeySerialized: [UInt8]) -> [UInt8] in
            return try generateKyberRecordBody(keyId: keyId, timestamp: timestamp, privateKeySerialized: privateKeySerialized)
        }
        Function("kyberPreKeyRecordGetId") {
            (record: [UInt8]) -> UInt32 in
            return try kyberPreKeyRecordGetIdBody(record: record)
        }
        Function("kyberPreKeyRecordGetPublicKey") {
            (record: [UInt8]) -> Data in
            return try kyberPreKeyRecordGetPublicKeyBody(record: record)
        }
        Function("kyberPreKeyRecordGetSecretKey") {
            (record: [UInt8]) -> Data in
            return try kyberPreKeyRecordGetSecretKeyBody(record: record)
        }
        Function("kyberPreKeyRecordGetSignature") {
            (record: [UInt8]) -> Data in
            return try kyberPreKeyRecordGetSignatureBody(record: record)
        }
        Function("kyberPreKeyRecordGetTimestamp") {
            (record: [UInt8]) -> UInt64 in
            return try kyberPreKeyRecordGetTimestampBody(record: record)
        }
        Function("privateKeyGenerate") {
            () -> [UInt8] in
            return privateKeyGenerateBody()
        }
        Function("privateKeySign") {
            (serializedPrivateKey: [UInt8], message: [UInt8]) -> Data in
            return try privateKeySignBody(serializedPrivateKey: serializedPrivateKey, message: message)
        }
        Function("signedPreKeyRecordNew") {
            (id: UInt32, timestamp: UInt64, serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8], signature: Data) -> Data in
            return try signedPreKeyRecordNewBody(id: id, timestamp: timestamp, serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey, signature: signature)
        }
        Function("signedPreKeyRecordGetId") {
            (record: Data) -> UInt32 in
            return try signedPreKeyRecordGetIdBody(record: record)
        }
        Function("signedPreKeyRecordGetPrivateKey") {
            (record: Data) -> [UInt8] in
            return try signedPreKeyRecordGetPrivateKeyBody(record: record)
        }
        Function("signedPreKeyRecordGetPublicKey") {
            (record: Data) -> [UInt8] in
            return try signedPreKeyRecordGetPublicKeyBody(record: record)
        }
        Function("signedPreKeyRecordGetSignature") {
            (record: Data) -> Data in
            return try signedPreKeyRecordGetSignatureBody(record: record)
        }
        Function("signedPreKeyRecordGetTimestamp") {
            (record: Data) -> UInt64 in
            return try signedPreKeyRecordGetTimestampBody(record: record)
        }
        Function("preKeyRecordNew") {
            (id: UInt32, serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8]) -> Data in
            return try preKeyRecordNewBody(id: id, serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey)
        }
        Function("preKeyRecordGetId") {
            (record: Data) -> UInt32 in
            return try preKeyRecordGetIdBody(record: record)
        }
        Function("preKeyRecordGetPrivateKey") {
            (record: Data) -> [UInt8] in
            return try preKeyRecordGetPrivateKeyBody(record: record)
        }
        Function("preKeyRecordGetPublicKey") {
            (record: Data) -> [UInt8] in
            return try preKeyRecordGetPublicKeyBody(record: record)
        }
        AsyncFunction("setValueAsync") {
            (value: String) in
            self.sendEvent(
                "onChange",
                [
                    "value": value])
        }
        View(ReactNativeLibsignalClientView.self) {
            Prop("name") {
                (view: ReactNativeLibsignalClientView, prop: String) in
                print(prop)
            }
        }
        /*END          bridge functions definitions              END*/
    }

    /*START          bridge functions implementation              START*/
    private func identityKeyPairSerializeHelper(serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8]) throws -> Data {
        let publicKey = try PublicKey(serializedPublicKey)
        let privateKey = try PrivateKey(serializedPrivateKey)
        let identityKeyPair = IdentityKeyPair(publicKey: publicKey, privateKey: privateKey)
        return Data(identityKeyPair.serialize())
    }

    private func sessionCipherEncryptMessageHelper(
        base64Message: String,
        address: String,
        sessionStoreState: [String: String],
        identityKeyState: [Any],
        now: Int64)
    throws -> [Any] {
        guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: address) else {
            throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
        }
        let remoteProtoAddress = try ProtocolAddress(name: serviceId, deviceId: UInt32(deviceId))
        guard let base64IdentityKey = identityKeyState[0] as? String,
        let ownerData = identityKeyState[1] as? [Any],
        let base64OwnerKeypair = ownerData[0] as? String,
        let ownerRegistrationId = ownerData[1] as? UInt32 else {
            throw NSError(domain: "Invalid identityKeyState format", code: 4, userInfo: nil)
        }
        let ownerKeypair = try IdentityKeyPair(bytes: Data(base64Encoded: base64OwnerKeypair, options: .ignoreUnknownCharacters)!)
        let identityKey = try IdentityKey(bytes: Data(base64Encoded: base64IdentityKey, options: .ignoreUnknownCharacters)!)
        let store = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerKeypair, registrationId: ownerRegistrationId)
        let _ = try store.saveIdentity(identityKey, for: remoteProtoAddress, context: NullContext())
        for (key, value) in sessionStoreState {
            guard let (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(address: key) else {
                throw NSError(domain: "Invalid address format", code: 5, userInfo: nil)
            }
            let keyBuffer = Data(base64Encoded: value, options: .ignoreUnknownCharacters)!
            let protoAddress = try ProtocolAddress(name: inStoreName, deviceId: UInt32(inStoreDeviceId))
            let sessionRecord = try SessionRecord(bytes: keyBuffer)
            try store.storeSession(sessionRecord, for: protoAddress, context: NullContext())
        }
        let msg = Data(base64Encoded: base64Message, options: [])!
        let cipher = try! signalEncrypt(
            message: msg,
            for: remoteProtoAddress,
            sessionStore: store,
            identityStore: store,
            context: NullContext())
        let updatedInMemorySessionStore = try updateSessionStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        let updatedInMemoryIdentityStore = try updateIdentityStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        var messageType = 0
        switch cipher.messageType {
            case .whisper:
            messageType = 2
            case .preKey:
            messageType = 3
            case .senderKey:
            messageType = 7
            case .plaintext:
            messageType = 8
            default:
            messageType = -1
        }
        return [[cipher.serialize(), messageType], [updatedInMemorySessionStore, updatedInMemoryIdentityStore]]
    }

    private func preKeySignalMessageGetSignedPreKeyIdHelper(serializedMessage: [UInt8]) throws -> UInt32 {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return message.signedPreKeyId
    }

    private func preKeySignalMessageGetVersionHelper(serializedMessage: [UInt8]) throws -> UInt32 {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return try message.version()
    }

    private func preKeySignalMessageGetRegistrationIdHelper(serializedMessage: [UInt8]) throws -> UInt32 {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return try message.registrationId()
    }

    private func preKeySignalMessageGetPreKeyIdHelper(serializedMessage: [UInt8]) throws -> UInt32? {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return try message.preKeyId()
    }

    private func createAndProcessPreKeyBundleHelper(
        registrationData: [Any],
        preKeyData: [Any],
        signedPreKeyData: [Any],
        base64SignedPreKeySignature: String,
        base64IdentityKey: String,
        ownerIdentityData: [Any],
        kyberPreKeyData: [Any]?,
        base64KyberPreKeySignature: String?)
    throws -> [Any] {
        guard let address = registrationData[0] as? String,
        let registrationId = registrationData[1] as? UInt32 else {
            throw NSError(domain: "Invalid registration data", code: 1, userInfo: nil)
        }
        guard let preKeyId = preKeyData[0] as? UInt32,
        let base64PreKeyPublic = preKeyData[1] as? String else {
            throw NSError(domain: "Invalid preKey data", code: 1, userInfo: nil)
        }
        guard let signedPreKeyId = signedPreKeyData[0] as? UInt32,
        let base64SignedPreKeyPublic = signedPreKeyData[1] as? String else {
            throw NSError(domain: "Invalid signedPreKey data", code: 1, userInfo: nil)
        }
        guard let base64OwnerKeypair = ownerIdentityData[0] as? String,
        let ownerRegistrationId = ownerIdentityData[1] as? UInt32 else {
            throw NSError(domain: "Invalid owner identity data", code: 1, userInfo: nil)
        }
        guard let ownerKeypair = decodeBase64(base64OwnerKeypair) else {
            throw NSError(domain: "Invalid base64 owner keypair", code: 1, userInfo: nil)
        }
        let ownerIdentityKey = try IdentityKeyPair(bytes: ownerKeypair)
        guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: address) else {
            throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
        }
        guard let signedPreKeyPublic = decodeBase64(base64SignedPreKeyPublic),
        let identityKey = decodeBase64(base64IdentityKey),
        let preKeyPublic = decodeBase64(base64PreKeyPublic) else {
            throw NSError(domain: "Invalid base64 data", code: 1, userInfo: nil)
        }
        let signedPublicPreKey = try PublicKey(signedPreKeyPublic)
        let idKey = try IdentityKey(bytes: identityKey)
        let publicPreKey = try PublicKey(preKeyPublic)
        guard let signedPreKeySignature = decodeBase64(base64SignedPreKeySignature) else {
            throw NSError(domain: "Invalid base64 signed pre-key signature", code: 1, userInfo: nil)
        }
        let remoteProtoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)
        let store = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerIdentityKey, registrationId: ownerRegistrationId)
        if let kyberPreKeyData = kyberPreKeyData, let base64KyberPreKeySignature = base64KyberPreKeySignature {
            guard let keyId = kyberPreKeyData[0] as? UInt32,
            let base64KyberPreKeyPublic = kyberPreKeyData[1] as? String,
            let kyberPreKeyPublic = decodeBase64(base64KyberPreKeyPublic),
            let kyberPreKeySignature = decodeBase64(base64KyberPreKeySignature) else {
                throw NSError(domain: "Invalid base64 kyber pre-key data", code: 1, userInfo: nil)
            }
            let pubKey = try KEMPublicKey(kyberPreKeyPublic)
            let bundle = try PreKeyBundle(
                registrationId: registrationId,
                deviceId: deviceId,
                prekeyId: preKeyId,
                prekey: publicPreKey,
                signedPrekeyId: signedPreKeyId,
                signedPrekey: signedPublicPreKey,
                signedPrekeySignature: signedPreKeySignature,
                identity: idKey,
                kyberPrekeyId: keyId,
                kyberPrekey: pubKey,
                kyberPrekeySignature: kyberPreKeySignature)
            try processPreKeyBundle(bundle, for: remoteProtoAddress, sessionStore: store, identityStore: store, context: NullContext())
        }
        else {
            let noKyberBundle = try PreKeyBundle(
                registrationId: registrationId,
                deviceId: deviceId,
                prekeyId: preKeyId,
                prekey: publicPreKey,
                signedPrekeyId: signedPreKeyId,
                signedPrekey: signedPublicPreKey,
                signedPrekeySignature: signedPreKeySignature,
                identity: idKey)
            try processPreKeyBundle(noKyberBundle, for: remoteProtoAddress, sessionStore: store, identityStore: store, context: NullContext())
        }
        let updatedInMemorySessionStore  = try updateSessionStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        let updatedInMemoryIdentityStore = try updateIdentityStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        return [updatedInMemorySessionStore, updatedInMemoryIdentityStore]
    }

    private func sessionCipherDecryptSignalMessageHelper(
        serializedMessage: [UInt8],
        address: String,
        sessionStoreState: [String: String],
        identityKeyState: [Any])
    throws -> [Any] {
        guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: address) else {
            throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
        }
        let remoteProtoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)
        guard let base64IdentityKey = identityKeyState[0] as? String,
        let ownerData = identityKeyState[1] as? [Any],
        let base64OwnerKeypair = ownerData[0] as? String,
        let ownerRegistrationId = ownerData[1] as? UInt32 else {
            throw NSError(domain: "Invalid identityKeyState format", code: 4, userInfo: nil)
        }
        guard let ownerKeypairBytes = decodeBase64(base64OwnerKeypair) else {
            throw NSError(domain: "Invalid owner key pair data", code: 1, userInfo: nil)
        }
        let ownerKeypair = try IdentityKeyPair(bytes: ownerKeypairBytes)
        guard let identityKeyBytes = decodeBase64(base64IdentityKey) else {
            throw NSError(domain: "Invalid identity key data", code: 1, userInfo: nil)
        }
        let identityKey = try IdentityKey(bytes: identityKeyBytes)
        let store = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerKeypair, registrationId: ownerRegistrationId)
        let _ = try store.saveIdentity(identityKey, for: remoteProtoAddress, context: NullContext())
        for (key, value) in sessionStoreState {
            guard let (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(address: key) else {
                throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
            }
            let keyBuffer = decodeBase64(value)!
            let protoAddress = try ProtocolAddress(name: inStoreName, deviceId: inStoreDeviceId)
            try store.storeSession(try SessionRecord(bytes: keyBuffer), for: protoAddress, context: NullContext())
        }
        let message = try SignalMessage(bytes: serializedMessage)
        let plaintext = try signalDecrypt(
            message: message,
            from: remoteProtoAddress,
            sessionStore: store,
            identityStore: store,
            context: NullContext())
        let updatedInMemorySessionStore = try updateSessionStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        let updatedInMemoryIdentityStore = try updateIdentityStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        return [Data(plaintext), [updatedInMemorySessionStore, updatedInMemoryIdentityStore]]
    }

    private func sessionCipherDecryptPreKeySignalMessageHelper(
        serializedMessage: [UInt8],
        address: String,
        ownerIdentityData: [Any],
        prekeyStoreState: SerializedAddressedKeys,
        signedPrekeyStoreState: SerializedAddressedKeys,
        kyberPrekeyStoreState: SerializedAddressedKeys)
    throws -> [Any] {
        guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: address) else {
            throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
        }
        let remoteProtoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)
        guard let base64OwnerKeypair = ownerIdentityData[0] as? String,
        let ownerRegistrationId = ownerIdentityData[1] as? UInt32 else {
            throw NSError(domain: "Invalid owner identity data 1", code: 1, userInfo: nil)
        }
        guard let ownerKeypairBytes = decodeBase64(base64OwnerKeypair) else {
            throw NSError(domain: "Invalid owner key pair data", code: 1, userInfo: nil)
        }
        let ownerKeypair = try IdentityKeyPair(bytes: ownerKeypairBytes)
        let store = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerKeypair, registrationId: ownerRegistrationId)
        for (key, value) in prekeyStoreState {
            if let keyBuffer = decodeBase64(value) {
                try store.storePreKey(try PreKeyRecord(bytes: keyBuffer), id: UInt32(key)!, context: NullContext())
            }
        }
        for (key, value) in signedPrekeyStoreState {
            if let keyBuffer = decodeBase64(value) {
                try store.storeSignedPreKey(try SignedPreKeyRecord(bytes: keyBuffer), id: UInt32(key)!, context: NullContext())
            }
        }
        for (key, value) in kyberPrekeyStoreState {
            if let keyBuffer = decodeBase64(value) {
                try store.storeKyberPreKey(try KyberPreKeyRecord(bytes: keyBuffer), id: UInt32(key)!, context: NullContext())
            }
        }
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        let plaintext = try signalDecryptPreKey(
            message: message,
            from: remoteProtoAddress,
            sessionStore: store,
            identityStore: store,
            preKeyStore: store,
            signedPreKeyStore: store,
            kyberPreKeyStore: store,
            context: NullContext())
        let updatedInMemorySessionStore = try updateSessionStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        let updatedInMemoryIdentityStore = try updateIdentityStoreStateFromInMemoryProtocolStore(store: store, address: remoteProtoAddress)
        let updatedPreKeyStore = try updatePreKeyStoreStateFromInMemoryProtocolStore(store: store)
        let updatedSignedPreKeyStore = try updateSignedPreKeyStoreStateFromInMemoryProtocolStore(store: store)
        let updatedKyberPreKeyStore = try updateKyberPreKeyStoreStateFromInMemoryProtocolStore(store: store)
        return [Data(plaintext), [updatedInMemorySessionStore, updatedInMemoryIdentityStore, updatedPreKeyStore, updatedSignedPreKeyStore, updatedKyberPreKeyStore]]
    }

    private func decryptionErrorMessageForOriginalMessageHelper(
        originalBytes: Data,
        messageType: Int,
        timestamp: Int64,
        originalSenderDeviceId: Int)
    throws -> Data {
        var signalMessageType: CiphertextMessage.MessageType = .preKey
        switch messageType {
            case 2:
            signalMessageType = .whisper
            case 3:
            signalMessageType = .preKey
            case 7:
            signalMessageType = .senderKey
            case 8:
            signalMessageType = .plaintext
            default:
            signalMessageType = .preKey
        }
        return Data(try DecryptionErrorMessage(
            originalMessageBytes: originalBytes,
            type: signalMessageType,
            timestamp: UInt64(timestamp),
            originalSenderDeviceId: UInt32(originalSenderDeviceId))
                    .serialize())
    }

    private func decryptionErrorMessageExtractFromSerializedContentHelper(
        serializedContent: Data)
    throws -> DecryptionErrorMessage {
        return try DecryptionErrorMessage.extractFromSerializedContent(serializedContent)
    }

    private func decryptionErrorMessageGetTimestampHelper(
        serializedContent: Data)
    throws -> Int64 {
        let content = try decryptionErrorMessageExtractFromSerializedContentHelper(serializedContent: serializedContent)
        return Int64(content.timestamp)
    }

    private func decryptionErrorMessageGetDeviceIdHelper(
        serializedContent: Data)
    throws -> Int {
        let content = try decryptionErrorMessageExtractFromSerializedContentHelper(serializedContent: serializedContent)
        return Int(content.deviceId)
    }

    private func decryptionErrorMessageGetRatchetKeyHelper(
        serializedContent: Data)
    throws -> Data? {
        let content = try decryptionErrorMessageExtractFromSerializedContentHelper(serializedContent: serializedContent)
        if let ratchetKey = content.ratchetKey {
            return Data(ratchetKey.serialize())
        }
        return nil
    }

    private func plaintextContentFromDecryptionErrorMessageHelper(
        message: Data)
    throws -> PlaintextContent {
        return try PlaintextContent(bytes: message)
    }

    private func plaintextContentGetBodyHelper(
        message: Data)
    throws -> Data {
        let plaintextContent = try PlaintextContent(bytes: message)
        return Data(plaintextContent.body)
    }

    private func publicKeyCompareHelper(
        serializedPublicKey1: Data,
        otherSerializedPublicKey2: Data)
    throws -> Int32 {
        let publicKey1 = try PublicKey(serializedPublicKey1)
        let publicKey2 = try PublicKey(otherSerializedPublicKey2)
        return publicKey1.compare(publicKey2)
    }

    private func publicKeyGetPublicKeyBytesHelper(
        serializedPublicKey: Data)
    throws -> Data {
        let publicKey = try PublicKey(serializedPublicKey)
        return Data(publicKey.keyBytes)
    }

    private func identityKeyVerifyAlternateIdentityWithPublicKeyHelper(
        serializedPublicKey: Data,
        message: Data,
        signature: Data)
    throws -> Bool {
        let publicKey = try PublicKey(serializedPublicKey)
        return try publicKey.verifySignature(message: message, signature: signature)
    }

    private func identityKeyVerifyAlternateIdentityWithIdentityKeyHelper(
        serializedIdentityKey: Data,
        otherPublicKey: Data,
        message: Data)
    throws -> Bool {
        let identityKey = try IdentityKey(bytes: serializedIdentityKey)
        let otherIdentityKey = try IdentityKey(bytes: otherPublicKey)
        return try identityKey.verifyAlternateIdentity(otherIdentityKey, signature: message)
    }

    private func sessionRecordArchiveCurrentStateHelper(
        record: Data)
    throws -> Data {
        let rec = try SessionRecord(bytes: record)
        rec.archiveCurrentState()
        return Data(rec.serialize())
    }

    private func sessionRecordGetRemoteRegistrationIdHelper(
        record: Data)
    throws -> UInt32 {
        let rec = try SessionRecord(bytes: record)
        return try rec.remoteRegistrationId()
    }

    private func sessionRecordHasUsableSenderChainHelper(
        record: Data,
        now: Int64)
    throws -> Bool {
        let rec = try SessionRecord(bytes: record)
        let instant = Date(timeIntervalSince1970: TimeInterval(now) / 1000)
        return rec.hasCurrentState(now: instant)
    }

    private func sessionRecordCurrentRatchetKeyMatchesHelper(
        record: Data,
        pubKey: [UInt8])
    throws -> Bool {
        let ecPublicKey = try PublicKey(Data(pubKey))
        let rec = try SessionRecord(bytes: record)
        return try rec.currentRatchetKeyMatches(ecPublicKey)
    }

    private func hkdfDeriveSecretsHelper(
        outputLength: Int,
        inputKeyMaterial: Data,
        info: Data,
        salt: Data)
    throws -> [UInt8] {
        return try hkdf(
            outputLength: outputLength,
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info)
    }

    private func serviceIdServiceIdStringHelper(
        fixedWidthServiceId: [UInt8])
    throws -> String {
        return try signalServiceIdServiceIdString(value: fixedWidthServiceId)
    }

    private func serviceIdServiceIdLogHelper(
        fixedWidthServiceId: [UInt8])
    throws -> String {
        return try signalServiceIdServiclogString(value: fixedWidthServiceId)
    }

    private func serviceIdParseFromServiceIdStringHelper(
        serviceIdString: String)
    throws -> [UInt8] {
        return try serviceIdParseFromServiceIdString(serviceIdString: serviceIdString)
    }

    private func serviceIdServiceIdBinaryHelper(
        fixedWidthServiceId: Data)
    throws -> [UInt8] {
        var bytes: SignalServiceIdFixedWidthBinaryBytes = convertDataToServiceIdStorage(data: fixedWidthServiceId)
        return try signalServiceIdServiceIdBinary(value: &bytes)
    }

    private func serviceIdParseFromServiceIdBinaryHelper(
        serviceIdBinary: Data)
    throws -> [UInt8] {
        return try serviceIdParseFromServiceIdBinary(serviceIdBinary: serviceIdBinary)
    }

    private func privateKeyGetPublicKeyHelper(
        serializedPrivateKey: [UInt8])
    throws -> [UInt8]? {
        let privateKey = try PrivateKey(serializedPrivateKey)
        let publicKey = privateKey.publicKey
        return publicKey.serialize()
    }

    func preKeyRecordGetPublicKeyBody(record: Data) throws -> [UInt8] {
        let rec = try PreKeyRecord(bytes: record)
        return rec.publicKey.serialize()
    }

    func preKeyRecordGetPrivateKeyBody(record: Data) throws -> [UInt8] {
        let rec = try PreKeyRecord(bytes: record)
        return rec.privateKey.serialize()
    }

    func preKeyRecordGetIdBody(record: Data) throws -> UInt32 {
        let rec = try PreKeyRecord(bytes: record)
        return rec.id
    }

    func preKeyRecordNewBody(id: UInt32, serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8]) throws -> Data {
        let publicKey = try PublicKey(serializedPublicKey)
        let privateKey = try PrivateKey(serializedPrivateKey)
        return Data(
            try PreKeyRecord(id: id, publicKey: publicKey, privateKey: privateKey).serialize())
    }

    func signedPreKeyRecordGetTimestampBody(record: Data) throws -> UInt64 {
        let rec = try SignedPreKeyRecord(bytes: record)
        return rec.timestamp
    }

    func signedPreKeyRecordGetSignatureBody(record: Data) throws -> Data {
        let rec = try SignedPreKeyRecord(bytes: record)
        return Data(rec.signature)
    }

    func signedPreKeyRecordGetPublicKeyBody(record: Data) throws -> [UInt8] {
        let rec = try SignedPreKeyRecord(bytes: record)
        return rec.publicKey.serialize()
    }

    func signedPreKeyRecordGetPrivateKeyBody(record: Data) throws -> [UInt8] {
        let rec = try SignedPreKeyRecord(bytes: record)
        return rec.privateKey.serialize()
    }

    func signedPreKeyRecordGetIdBody(record: Data) throws -> UInt32 {
        let rec = try SignedPreKeyRecord(bytes: record)
        return rec.id
    }

    func signedPreKeyRecordNewBody(id: UInt32, timestamp: UInt64, serializedPublicKey: [UInt8], serializedPrivateKey: [UInt8], signature: Data) throws -> Data {
        let privateKey = try PrivateKey(serializedPrivateKey)
        return Data(
            try SignedPreKeyRecord(
                id: id, timestamp: timestamp, privateKey: privateKey, signature: signature)
            .serialize())
    }

    func privateKeySignBody(serializedPrivateKey: [UInt8], message: [UInt8]) throws -> Data {
        let privateKey = try PrivateKey(serializedPrivateKey)
        return Data(privateKey.generateSignature(message: message))
    }

    func privateKeyGenerateBody() -> [UInt8] {
        let keypair = IdentityKeyPair.generate()
        return keypair.privateKey.serialize()
    }

    func kyberPreKeyRecordGetTimestampBody(record: [UInt8]) throws -> UInt64 {
        let rec = try KyberPreKeyRecord(bytes: record)
        return rec.timestamp
    }

    func kyberPreKeyRecordGetSignatureBody(record: [UInt8]) throws -> Data {
        let rec = try KyberPreKeyRecord(bytes: record)
        return Data(rec.signature)
    }

    func kyberPreKeyRecordGetSecretKeyBody(record: [UInt8]) throws -> Data {
        let rec = try KyberPreKeyRecord(bytes: record)
        return Data(rec.keyPair.secretKey.serialize())
    }

    func kyberPreKeyRecordGetPublicKeyBody(record: [UInt8]) throws -> Data {
        let rec = try KyberPreKeyRecord(bytes: record)
        return Data(rec.keyPair.publicKey.serialize())
    }

    func kyberPreKeyRecordGetIdBody(record: [UInt8]) throws -> UInt32 {
        let rec = try KyberPreKeyRecord(bytes: record)
        return rec.id
    }

    func generateKyberRecordBody(keyId: CGFloat, timestamp: CGFloat, privateKeySerialized: [UInt8]) throws -> [UInt8] {
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
            signature: signature)
        return kyberRecord.serialize()
    }

    private func decodeBase64(_ base64String: String) -> Data? {
        return Data(base64Encoded: base64String)
    }

    private func serviceIdParseFromServiceIdString(serviceIdString: String) throws -> [UInt8] {
        var output: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        let result = serviceIdString.withCString {
            cString in
            signal_service_id_parse_from_service_id_string(&output, cString)
        }
        if result != nil {
            throw SignalFfiError.serviceIdStringConversionFailed
        }
        let outputArray = withUnsafePointer(to: &output) {
            Array(UnsafeBufferPointer(start: $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size) {
                $0
            }
                                      , count: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size))
        }
        return outputArray
    }

    private func convertDataToSignalBorrowedBuffer(data: Data) -> SignalBorrowedBuffer {
        return data.withUnsafeBytes {
            bytes in
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
            Array(UnsafeBufferPointer(start: $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size) {
                $0
            }
                                      , count: MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size))
        }
        return outputArray
    }

    internal func invokeFnReturningInteger<Result: FixedWidthInteger>(fn: (UnsafeMutablePointer<Result>?) -> SignalFfiErrorRef?) throws -> Result {
        var output: Result = 0
        try checkError(fn(&output))
        return output
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

    private func getDeviceIdAndServiceId(address: String) -> (String, UInt32)? {
        let components = address.split(separator: ".")
        guard components.count == 2,
        let deviceId = UInt32(components[1]) else {
            return nil
        }
        let serviceId = String(components[0])
        return (serviceId, deviceId)
    }

    private func convertDataToServiceIdStorage(data: Data) -> SignalServiceIdFixedWidthBinaryBytes {
        var storage: SignalServiceIdFixedWidthBinaryBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        _ = data.withUnsafeBytes {
            bytes in
            memcpy(&storage, bytes.baseAddress!, min(data.count, MemoryLayout<SignalServiceIdFixedWidthBinaryBytes>.size))
        }
        return storage
    }

    private func updateSessionStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPreKeysList, address: ProtocolAddress) throws -> [String: String] {
        let sessionRecords = try store.loadExistingSessions(for: [address], context: NullContext())
        var updatedStore = [String: String]()
        for sessionRecord in sessionRecords {
            let serializedSessionRecord = sessionRecord.serialize()
            let serializedSessionRecordData = Data(serializedSessionRecord)
            updatedStore[address.name + "." + String(address.deviceId)] = serializedSessionRecordData.base64EncodedString(options: [])
        }
        return updatedStore
    }

    func base64Encode(_ data: Data) -> String {
        return data.base64EncodedString(options: .endLineWithLineFeed)
    }

    private func updateIdentityStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPreKeysList, address: ProtocolAddress) throws -> [String: String] {
        guard let identityKey = try store.identity(for: address, context: NullContext()) else {
            throw NSError(domain: "Identity key not found", code: 1, userInfo: nil)
        }
        var updatedStore = [String: String]()
        let serializedIdentityKey = Data(identityKey.serialize())
        updatedStore[address.name + "." + String(address.deviceId)] = serializedIdentityKey.base64EncodedString(options: [])
        return updatedStore
    }

    private func updatePreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPreKeysList) throws -> SerializedAddressedKeys {
        var updatedStore: SerializedAddressedKeys = [:]
        let preKeys = try store.loadPreKeys(context: NullContext())
        for entry in preKeys {
            updatedStore[String(entry.id)] = base64Encode(Data(entry.serialize()))
        }
        return updatedStore
    }

    private func updateSignedPreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPreKeysList) throws -> SerializedAddressedKeys {
        var updatedStore: SerializedAddressedKeys = [:]
        let signedPreKeys = try store.loadSignedPreKeys(context: NullContext())
        for entry in signedPreKeys {
            updatedStore[String(entry.id)] = base64Encode(Data(entry.serialize()))
        }
        return updatedStore
    }

    private func updateKyberPreKeyStoreStateFromInMemoryProtocolStore(store: InMemorySignalProtocolStoreWithPreKeysList) throws -> SerializedAddressedKeys {
        var updatedStore: SerializedAddressedKeys = [:]
        let kyberPreKeys = try store.loadKyberPreKeys(context: NullContext())
        for entry in kyberPreKeys {
            updatedStore[String(entry.id)] = base64Encode(Data(entry.serialize()))
        }
        return updatedStore
    }

    internal func invokeFnReturningArray(fn: (UnsafeMutablePointer<SignalOwnedBuffer>?) -> SignalFfiErrorRef?) throws -> [UInt8] {
        var output = SignalOwnedBuffer()
        try checkError(fn(&output))
        let result = Array(UnsafeBufferPointer(start: output.base, count: output.length))
        signal_free_buffer(output.base, output.length)
        return result
    }

    private func signalServiceIdServiceIdBinary(value: inout SignalServiceIdFixedWidthBinaryBytes) throws -> [UInt8] {
        return try invokeFnReturningArray {
            outBuffer in
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
        guard let error = error else {
            return
        }
        let errType = signal_error_get_type(error)
        let errStr = try! invokeFnReturningString {
            signal_error_get_message(error, $0)
        }
        defer {
            signal_error_free(error)
        }
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
        /*END          bridge functions implementation              END*/
    }

}
