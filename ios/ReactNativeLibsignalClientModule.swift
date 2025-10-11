import ExpoModulesCore
import LibSignalClient
import SignalFfi
import Foundation
import CryptoKit
import CommonCrypto
// TODO: uncomment after closing https://github.com/p-num/react-native-libsignal-client/issues/48
// @testable import LibSignalClient

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

public class CipherContext {
    public enum Operation {
        case encrypt
        case decrypt

        var ccValue: CCOperation {
            switch self {
            case .encrypt: return CCOperation(kCCEncrypt)
            case .decrypt: return CCOperation(kCCDecrypt)
            }
        }
    }

    public enum Algorithm {
        case aes

        var ccValue: CCOperation {
            switch self {
            case .aes: return CCAlgorithm(kCCAlgorithmAES)
            }
        }
    }

    public struct Options: OptionSet {
        public let rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }

        public static let pkcs7Padding = Options(rawValue: kCCOptionPKCS7Padding)
        public static let ecbMode = Options(rawValue: kCCOptionECBMode)
    }

    private var cryptor: CCCryptorRef?

    deinit {
        if let cryptor {
            CCCryptorRelease(cryptor)
            self.cryptor = nil
        }
    }

    public init(operation: Operation, algorithm: Algorithm, options: Options, key: Data, iv: Data) throws {
        let result = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreate(
                    operation.ccValue,
                    algorithm.ccValue,
                    CCOptions(options.rawValue),
                    keyBytes.baseAddress,
                    keyBytes.count,
                    ivBytes.baseAddress,
                    &cryptor
                )
            }
        }
        guard result == CCStatus(kCCSuccess) else {
            throw NSError(domain: "Invalid arguments provided \(result)", code: 1, userInfo: nil)
        }
    }

    public func outputLength(forUpdateWithInputLength inputLength: Int) throws -> Int {
        guard let cryptor else {
            throw NSError(domain: "Unexpectedly attempted to read a finalized cipher", code: 1, userInfo: nil)
        }

        return CCCryptorGetOutputLength(cryptor, inputLength, false)
    }

    public func outputLengthForFinalize() throws -> Int {
        guard let cryptor else {
            throw NSError(domain: "Unexpectedly attempted to read a finalized cipher", code: 1, userInfo: nil)
        }

        return CCCryptorGetOutputLength(cryptor, 0, true)
    }

    public func update(_ data: Data) throws -> Data {
        let outputLength = try outputLength(forUpdateWithInputLength: data.count)
        var outputBuffer = Data(repeating: 0, count: outputLength)
        let actualOutputLength = try self.update(input: data, output: &outputBuffer)
        outputBuffer.count = actualOutputLength
        return outputBuffer
    }

    /// Update the cipher with provided input, writing decrypted output into the provided output buffer.
    ///
    /// - parameter input: The encrypted input to decrypt.
    /// - parameter inputLength: If non-nil, only this many bytes of the input will be read.
    ///     Otherwise the entire input will be read.
    /// - parameter output: The output buffer to write the decrypted bytes into.
    /// - parameter offsetInOutput: Decrypted bytes will be written into the output buffer starting at
    ///     this offset. Defaults to 0 (bytes written into the start of the output buffer)
    /// - parameter outputLength: If non-nil, only this many bytes of output will be written to the output
    ///     buffer. If nil, the length of the output buffer (minus `offsetInOutput`) will be used. NOTE: should
    ///     not be larger than the length of the buffer minus `offsetInOutput`.
    ///
    /// - returns The actual number of bytes written to `output`.
    public func update(
        input: Data,
        inputLength: Int? = nil,
        output: inout Data,
        offsetInOutput: Int = 0,
        outputLength: Int? = nil
    ) throws -> Int {
        guard let cryptor else {
            throw NSError(domain: "Unexpectedly attempted to update a finalized cipher", code: 1, userInfo: nil)
        }

        let outputLength = outputLength ?? (output.count - offsetInOutput)
        var actualOutputLength = 0
        let result = input.withUnsafeBytes { inputPointer in
            output.withUnsafeMutableBytes { outputPointer in
                return CCCryptorUpdate(
                    cryptor,
                    inputPointer.baseAddress,
                    inputLength ?? input.count,
                    outputPointer.baseAddress.map { $0 + offsetInOutput },
                    outputLength,
                    &actualOutputLength
                )
            }
        }
        guard result == CCStatus(kCCSuccess) else {
            throw NSError(domain: "Unexpected result \(result)", code: 1, userInfo: nil)
        }
        return actualOutputLength
    }

    public func finalize() throws -> Data {
        let outputLength = try self.outputLengthForFinalize()
        var outputBuffer = Data(repeating: 0, count: outputLength)
        let actualOutputLength = try finalize(output: &outputBuffer)
        outputBuffer.count = actualOutputLength
        return outputBuffer
    }

    /// Finalize the cipher, writing decrypted output into the provided output buffer.
    ///
    /// - parameter output: The output buffer to write the decrypted bytes into.
    /// - parameter offsetInOutput: Decrypted bytes will be written into the output buffer starting at
    ///     this offset. Defaults to 0 (bytes written into the start of the output buffer)
    /// - parameter outputLength: If non-nil, only this many bytes of output will be written to the output
    ///     buffer. If nil, the length of the output buffer (minus `offsetInOutput`) will be used. NOTE: should
    ///     not be larger than the length of the buffer minus `offsetInOutput`.
    ///
    /// - returns The actual number of bytes written to `output`.
    public func finalize(
        output: inout Data,
        offsetInOutput: Int = 0,
        outputLength: Int? = nil
    ) throws -> Int {
        guard let cryptor = cryptor else {
            throw NSError(domain: "Unexpectedly attempted to finalize a finalized cipher", code: 1, userInfo: nil)
        }

        defer {
            CCCryptorRelease(cryptor)
            self.cryptor = nil
        }

        let outputLength = outputLength ?? (output.count - offsetInOutput)
        var actualOutputLength = 0
        let result = output.withUnsafeMutableBytes { outputPointer in
            return CCCryptorFinal(
                cryptor,
                outputPointer.baseAddress.map { $0 + offsetInOutput },
                outputLength,
                &actualOutputLength
            )
        }
        guard result == CCStatus(kCCSuccess) else {
            throw NSError(domain: "Unexpected result \(result)", code: 1, userInfo: nil)
        }
        return actualOutputLength
    }
}



struct ReactNativeLibsignalClientLogType {
    let level: String
    let messages: [String]
}

class ReactNativeLibsignalClientLogger {
    private static var callbacks: [(ReactNativeLibsignalClientLogType) -> String] = []

    static func initiate() {
        Native.initializeLogger(level: 2, loggerClass: ReactNativeLibsignalClientLogger.self)
    }

    static func log(level: Int, message: String, additionalMessage: String? = nil) {
        let lvl = determineLogLevel(level: level)
        log(level: lvl, msg: message, args: additionalMessage != nil ? [additionalMessage!] : [])
    }

    private static func log(level: String, msg: String, args: [String]) {
        let messages = [msg] + args
        let log = ReactNativeLibsignalClientLogType(level: level, messages: messages)
        notifyCallbacks(log: log)
    }

    static func addCallback(_ callback: @escaping (ReactNativeLibsignalClientLogType) -> String) {
        callbacks.append(callback)
    }

    private static func notifyCallbacks(log: ReactNativeLibsignalClientLogType) {
        for callback in callbacks {
            _ = callback(log)
        }
    }

    private static func determineLogLevel(level: Int) -> String {
        switch level {
        case 2: return "VERBOSE"
        case 3: return "DEBUG"
        case 4: return "INFO"
        case 5: return "WARN"
        case 6: return "ERROR"
        case 7: return "ASSERT"
        default: return "UNKNOWN"
        }
    }
}

class Native {
    static func initializeLogger(level: Int, loggerClass: Any.Type) {
        print("Logger initialized with level \(level) for class \(loggerClass)")
    }
}

public class ReactNativeLibsignalClientModule: Module {
    private var logListener: ((ReactNativeLibsignalClientLogType) -> String)?


    public func definition() -> ModuleDefinition {
        


        Name("ReactNativeLibsignalClient")
            OnCreate {
            self.logListener = { [weak self] log in
                guard let self = self else { return "null" }
                var logData: [String: String] = [:]
                logData["msg"] = log.messages.joined(separator: ", ")
                logData["level"] = log.level

                self.sendEvent("onLogGenerated", logData)
                return "null"
            }

            if let listener = self.logListener {
                ReactNativeLibsignalClientLogger.addCallback(listener)
            }

            ReactNativeLibsignalClientLogger.initiate()
        }

        Events("onLogGenerated")
        /*START          bridge functions definitions              START*/
        Function("serverPublicParamsVerifySignature") { (serializedSrvPubParams: Data, msg: Data, sig: Data) -> Bool in
            return try! serverPublicParamsVerifySignatureHelper(serializedSrvPubParams: serializedSrvPubParams, msg: msg, sig: sig)
        }

        Function("groupPublicParamsGetGroupIdentifier") { (serializedGpPubParams: Data) -> [UInt8] in
            return try! groupPublicParamsGetGroupIdentifierHelper(serializedGpPubParams: serializedGpPubParams)
        }

        Function("groupSecretParamsGenerateDeterministic") { (rand: Data) -> [UInt8] in
            return try! groupSecretParamsGenerateDeterministicHelper(rawrand: [UInt8](rand))
        }
        
        Function("groupSecretParamsDeriveFromMasterKey") { (serializedGpMasterKey: Data) -> [UInt8] in
            return try! groupSecretParamsDeriveFromMasterKeyHelper(serializedGpMasterKey: serializedGpMasterKey)
        }

        Function("groupSecretParamsGetPublicParams") { (gpSecParams: Data) -> [UInt8] in
            return try! groupSecretParamsGetPublicParamsHelper(gpSecParams: gpSecParams)
        }

        Function("groupSecretParamsGetMasterKey") { (gpSecParams: Data) -> [UInt8] in
            return try! groupSecretParamsGetMasterKeyHelper(gpSecParams: gpSecParams)
        }

        Function("generateRandomBytes") { (len: Int) -> [UInt8] in
            return try! generateRandomBytesHelper(len: len)
        }

        Function("profileKeyGetCommitment") { (serializedProfileKey: Data, fixedWidthAci: Data) -> [UInt8] in
            return try! profileKeyGetCommitmentHelper(serializedProfileKey: serializedProfileKey, fixedWidthAci: fixedWidthAci)
        }

        Function("profileKeyGetVersion") { (serializedProfileKey: Data, fixedWidthAci: Data) -> [UInt8] in
            return try! profileKeyGetVersionHelper(serializedProfileKey: serializedProfileKey, fixedWidthAci: fixedWidthAci)
        }
        Function("profileKeyDeriveAccessKey") { (serializedProfileKey: Data) -> [UInt8] in
            return try! profileKeyDeriveAccessKeyHelper(serializedProfileKey: serializedProfileKey)
        }

        Function("groupSecretParamsEncryptServiceId") { (sGroupSecretParams: Data, fixedWidthServiceId: Data) -> [UInt8] in
            return try! groupSecretParamsEncryptServiceIdHelper(sGroupSecretParams: sGroupSecretParams, fixedWidthServiceId: fixedWidthServiceId)
        }

        Function("groupSecretParamsDecryptServiceId") { (sGroupSecretParams: Data, rawCipherText: Data) -> [UInt8] in
            return try! groupSecretParamsDecryptServiceIdHelper(sGroupSecretParams: sGroupSecretParams, rawCipherText: rawCipherText)
        }

        Function("groupSecretParamsEncryptProfileKey") { (sGroupSecretParams: Data, rawProfileKey: Data, fixedWidthAci: Data) -> [UInt8] in
            return try! groupSecretParamsEncryptProfileKeyHelper(sGroupSecretParams: sGroupSecretParams, rawProfileKey: rawProfileKey, fixedWidthAci: fixedWidthAci)
        }

        Function("groupSecretParamsDecryptProfileKey") { (sGroupSecretParams: Data, rawProfileKeyCipherText: Data, fixedWidthAci: Data) -> [UInt8] in
            return try! groupSecretParamsDecryptProfileKeyHelper(sGroupSecretParams: sGroupSecretParams, rawProfileKeyCipherText: rawProfileKeyCipherText, fixedWidthAci: fixedWidthAci)
        }

        Function("encryptBlobWithPaddingDeterministic") { (sGroupSecretParams: Data, randomNess: Data, plainText: Data, paddingLen: Int) -> [UInt8] in
            return try! encryptBlobWithPaddingDeterministicHelper(sGroupSecretParams: sGroupSecretParams, randomNess: randomNess, plainText: plainText, paddingLen: paddingLen)
        }

        Function("decryptBlobWithPadding") { (sGroupSecretParams: Data, blobCipherText: Data) -> [UInt8] in
            return try! decryptBlobWithPaddingHelper(sGroupSecretParams: sGroupSecretParams, blobCipherText: blobCipherText)
        }

        Function("expiringProfileKeyCredentialGetExpirationTime") { (sExpiringProfileKeyCredential: Data) -> Int64 in
            return try! expiringProfileKeyCredentialGetExpirationTimeHelper(sExpiringProfileKeyCredential: sExpiringProfileKeyCredential)
        }
        Function("profileKeyCredentialPresentationGetUuidCiphertext") { (sProfileKeyCredentialPresentation: Data) -> [UInt8] in
            return try! profileKeyCredentialPresentationGetUuidCiphertextHelper(sProfileKeyCredentialPresentation: sProfileKeyCredentialPresentation)
        }

        Function("profileKeyCredentialPresentationGetProfileKeyCiphertext") { (sProfileKeyCredentialPresentation: Data) -> [UInt8] in
            return try! profileKeyCredentialPresentationGetProfileKeyCiphertextHelper(sProfileKeyCredentialPresentation: sProfileKeyCredentialPresentation)
        }

        Function("profileKeyCredentialRequestContextGetRequest") { (sProfileKeyCredentialRequestContext: Data) -> [UInt8] in
            return try! profileKeyCredentialRequestContextGetRequestHelper(sProfileKeyCredentialRequestContext: sProfileKeyCredentialRequestContext)
        }

        Function("serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic") { (sServerPublicParams: Data, randomness: Data, fixedWidthAci: Data, sProfileKey: Data) -> [UInt8] in
            return try! serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministicHelper(
                sServerPublicParams: sServerPublicParams,
                randomness: randomness,
                fixedWidthAci: fixedWidthAci,
                sProfileKey: sProfileKey
            )
        }

        Function("serverPublicParamsReceiveExpiringProfileKeyCredential") { (sServerPublicParams: Data, sProfileKeyCredReqCtx: Data, sExpProfileKeyCredResponse: Data, ts: Int64) -> [UInt8] in
            return try! serverPublicParamsReceiveExpiringProfileKeyCredentialHelper(
                sServerPublicParams: sServerPublicParams,
                sProfileKeyCredReqCtx: sProfileKeyCredReqCtx,
                sExpProfileKeyCredResponse: sExpProfileKeyCredResponse,
                ts: ts
            )
        }
        Function("serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic") { (sServerPublicParams: Data, randomness: Data, sGpSecParams: Data, sExpProfKeyCred: Data) -> [UInt8] in
            return try! serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministicHelper(
                sServerPublicParams: sServerPublicParams,
                randomness: randomness,
                sGpSecParams: sGpSecParams,
                sExpProfKeyCred: sExpProfKeyCred
            )
        }

        Function("authCredentialPresentationGetUuidCiphertext") { (sAuthCredPres: Data) -> [UInt8] in
            return try! authCredentialPresentationGetUuidCiphertextHelper(sAuthCredPres: sAuthCredPres)
        }

        Function("authCredentialPresentationGetPniCiphertext") { (sAuthCredPres: Data) -> [UInt8] in
            return try! authCredentialPresentationGetPniCiphertextHelper(sAuthCredPres: sAuthCredPres)
        }

        Function("authCredentialPresentationGetRedemptionTime") { (sAuthCredPres: Data) -> Int64 in
            return try! authCredentialPresentationGetRedemptionTimeHelper(sAuthCredPres: sAuthCredPres)
        }

        Function("serverPublicParamsReceiveAuthCredentialWithPniAsServiceId") { (sSrvPubParams: Data, fixedWidthAci: Data, fixedWidthPni: Data, redemptionTime: UInt64, authCredPniResp: Data) -> [UInt8] in
            return try! serverPublicParamsReceiveAuthCredentialWithPniAsServiceIdHelper(
                sSrvPubParams: sSrvPubParams,
                fixedWidthAci: fixedWidthAci,
                fixedWidthPni: fixedWidthPni,
                redemptionTime: redemptionTime,
                authCredPniResp: authCredPniResp
            )
        }

        Function("serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic") { (sSrvPubParams: Data, randomness: Data, sGpSecParams: Data, authCredPni: Data) -> [UInt8] in
            return try! serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministicHelper(
                sSrvPubParams: sSrvPubParams,
                randomness: randomness,
                sGpSecParams: sGpSecParams,
                authCredPni: authCredPni
            )
        }

        Function("generateIdentityKeyPair") {
            return IdentityKeyPair.generate().serialize()
        }
        Function("identityKeyPairSerialize") {
            (serializedPublicKey: Data, serializedPrivateKey: Data) -> Data in
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
            (serializedMessage: Data) -> UInt32 in
            return try preKeySignalMessageGetRegistrationIdHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetSignedPreKeyId") {
            (serializedMessage: Data) -> UInt32 in
            return try preKeySignalMessageGetSignedPreKeyIdHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetVersion") {
            (serializedMessage: Data) -> UInt32 in
            return try preKeySignalMessageGetVersionHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetPreKeyId") {
            (serializedMessage: Data) -> UInt32? in
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
                serializedMessage: Data,
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
                serializedMessage: Data,
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
        Function("publicKeyVerify") {
            (serializedPublicKey: Data, message: Data, signature: Data) throws -> Bool in
            return try publicKeyVerifyHelper(serializedPublicKey: serializedPublicKey, message: message, signature: signature)
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
            (record: Data, pubKey: Data) throws -> Bool in
            return try sessionRecordCurrentRatchetKeyMatchesHelper(record: record, pubKey: pubKey)
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
            (serializedPrivateKey: Data) -> Data? in
            return try privateKeyGetPublicKeyHelper(serializedPrivateKey: serializedPrivateKey)
        }
        Function("generateKyberRecord") {
            (keyId: CGFloat, timestamp: CGFloat, privateKeySerialized: Data) -> Data in
            return try generateKyberRecordBody(keyId: keyId, timestamp: timestamp, privateKeySerialized: privateKeySerialized)
        }
        Function("kyberPreKeyRecordGetId") {
            (record: Data) -> UInt32 in
            return try kyberPreKeyRecordGetIdBody(record: record)
        }
        Function("kyberPreKeyRecordGetPublicKey") {
            (record: Data) -> Data in
            return try kyberPreKeyRecordGetPublicKeyBody(record: record)
        }
        Function("kyberPreKeyRecordGetSecretKey") {
            (record: Data) -> Data in
            return try kyberPreKeyRecordGetSecretKeyBody(record: record)
        }
        Function("kyberPreKeyRecordGetSignature") {
            (record: Data) -> Data in
            return try kyberPreKeyRecordGetSignatureBody(record: record)
        }
        Function("kyberPreKeyRecordGetTimestamp") {
            (record: Data) -> UInt64 in
            return try kyberPreKeyRecordGetTimestampBody(record: record)
        }
        Function("privateKeyGenerate") {
            () -> Data in
            return privateKeyGenerateBody()
        }
        Function("privateKeySign") {
            (serializedPrivateKey: Data, message: Data ) -> Data in
            return try privateKeySignBody(serializedPrivateKey: serializedPrivateKey, message: message)
        }
        Function("signedPreKeyRecordNew") {
            (id: UInt32, timestamp: UInt64, serializedPublicKey: Data, serializedPrivateKey: Data, signature: Data) -> Data in
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
            (id: UInt32, serializedPublicKey: Data, serializedPrivateKey: Data) -> Data in
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
        Function("generateRegistrationId") {
            () -> UInt32 in
            return UInt32.random(in: 1...0x3fff)
        }
        Function("preKeyRecordGetPublicKey") {
            (record: Data) -> [UInt8] in
            return try preKeyRecordGetPublicKeyBody(record: record)
        }
        Function("serverSecretParamsGenerateDeterministic") { (rndm: Data) -> [UInt8] in
            return try! serverSecretParamsGenerateDeterministicHelper(randomNess: rndm)
        }
        Function("serverSecretParamsGetPublicParams") { (sSrvSecParams: Data) -> [UInt8] in
            return try! serverSecretParamsGetPublicParamsHelper(sSrvSecParams: sSrvSecParams)
        }
        Function("serverSecretParamsSignDeterministic") { (sSrvSecParams: Data, rndm: Data, msg: Data) -> [UInt8] in
            return try! serverSecretParamsSignDeterministicHelper(sSrvSecParams: sSrvSecParams, rndm: rndm, msg: msg)
        }
        Function("serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic") { (sSrvSecParams: Data, rndm: Data, sAci: Data, sPni: Data, redemptionTime: Double) -> [UInt8] in
            return try! serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministicHelper(sSrvSecParams: sSrvSecParams, rndm: rndm, sAci: sAci, sPni: sPni, redemptionTime: redemptionTime)
        }
        Function("serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic") { (sSrvSecParams: Data, rndm: Data, sAci: Data, sPni: Data, redemptionTime: Double) -> [UInt8] in
            return try! serverSecretParamsIssueAuthCredentialWithPniZkcDeterministicHelper(sSrvSecParams: sSrvSecParams, rndm: rndm, sAci: sAci, sPni: sPni, redemptionTime: redemptionTime)
        }
        Function("serverSecretParamsVerifyAuthCredentialPresentation") { (sSrvSecParams: Data, sGpPublicParams: Data, sAuthCredPresent: Data, instant: Double) in
            try! serverSecretParamsVerifyAuthCredentialPresentationHelper(sSrvSecParams: sSrvSecParams, sGpPublicParams: sGpPublicParams, sAuthCredPresent: sAuthCredPresent, instant: instant)
        }
        Function("groupSecretParamsEncryptCiphertext") { (sGpSecParams: Data, sServiceId: Data) -> [UInt8] in
            return try! groupSecretParamsEncryptCiphertextHelper(sGpSecParams: sGpSecParams, sServiceId: sServiceId)
        }
        Function("serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic") { (sSrvSecParams: Data, rand: Data, sProfCredRequest: Data, sAci: Data, sProfileKeyCommitment: Data, expiration: UInt64) -> [UInt8] in
            return try! serverSecretParamsIssueExpiringProfileKeyCredentialDeterministicHelper(sSrvSecParams: sSrvSecParams, rand: rand, sProfCredRequest: sProfCredRequest, sAci: sAci, sProfileKeyCommitment: sProfileKeyCommitment, expiration: expiration)
        }
        Function("serverSecretParamsVerifyProfileKeyCredentialPresentation") { (sSrvSecParams: Data, sGpPublicParams: Data, sProfileKeyCredentialPresentation: Data, instant: Double) in
            try! serverSecretParamsVerifyProfileKeyCredentialPresentationHelper(sSrvSecParams: sSrvSecParams, sGpPublicParams: sGpPublicParams, sProfileKeyCredentialPresentation: sProfileKeyCredentialPresentation, instant: instant)
        }
        Function("groupSecretParamsEncryptBlobWithPaddingDeterministic") { (sGroupSecretParams: Data, randomNess: Data, plainText: Data, paddingLen: Int) -> [UInt8] in
            return try! groupSecretParamsEncryptBlobWithPaddingDeterministicHelper(sGroupSecretParams: sGroupSecretParams, randomNess: [UInt8](randomNess), plainText: plainText, paddingLen: paddingLen)
        }
        Function("groupSecretParamsDecryptBlobWithPadding") { (sGroupSecretParams: Data, blobCipherText: Data) -> [UInt8] in
            return try! groupSecretParamsDecryptBlobWithPaddingHelper(sGroupSecretParams: sGroupSecretParams, blobCipherText: blobCipherText)
        }
        Function("Aes256GcmEncrypt") { (key: Data, iv: Data, plainText: Data, aad: Data?) -> Data in
            var mutableCiphertext = plainText 
            let gcmDec = try! Aes256GcmEncryption(key: key, nonce: iv, associatedData: aad ?? Data())
            try! gcmDec.encrypt(&mutableCiphertext)  
            let aes256GcmEncryptedDataResult = try Aes256GcmEncryptedData(nonce: iv, ciphertext: mutableCiphertext, authenticationTag: gcmDec.computeTag())
            var result = Data(capacity:aes256GcmEncryptedDataResult.ciphertext.count + aes256GcmEncryptedDataResult.authenticationTag.count)
            result += aes256GcmEncryptedDataResult.ciphertext
            result += aes256GcmEncryptedDataResult.authenticationTag
            return result
         }
        Function("Aes256GcmDecrypt") { (key: Data, iv: Data, ciphertext: Data, aad: Data?) -> Data in
            let finalCiphertext = ciphertext.dropLast(16)
            let finalAuthenticationTag = ciphertext.suffix(16)
            let aes256GcmEncryptedDataResult = try Aes256GcmEncryptedData(nonce: iv, ciphertext: finalCiphertext, authenticationTag: finalAuthenticationTag)
            let result = try aes256GcmEncryptedDataResult.decrypt(key: key,associatedData: aad ?? Data())
            return result
        }
        Function("Aes256CbcEncrypt") { (key: Data, iv: Data, plaintext: Data) -> Data in
            let cipherContext = try CipherContext(
                operation: .encrypt,
                algorithm: .aes,
                options: .pkcs7Padding,
                key: key,
                iv: iv
            )
            let ciphertextPart1 = try cipherContext.update(plaintext)
            let ciphertextPart2 = try cipherContext.finalize()
            return ciphertextPart1 + ciphertextPart2
        }
        Function("Aes256CbcDecrypt") { (key: Data, iv: Data, ciphertext: Data) -> Data in
            let cipherContext = try CipherContext(
                operation: .decrypt,
                algorithm: .aes,
                options: .pkcs7Padding,
                key: key,
                iv: iv
            )
            let plaintextPart1 = try cipherContext.update(ciphertext)
            let plaintextPart2 = try cipherContext.finalize()
            return plaintextPart1 + plaintextPart2
        }
        Function("groupSendFullTokenGetExpiration") { (sgpfulltoken: Data) -> UInt64 in
            let gpFullToken = try GroupSendFullToken(contents: [UInt8](sgpfulltoken))
            return UInt64(gpFullToken.expiration.timeIntervalSince1970)
        }

        Function("groupSendFullTokenVerify") { (sgpfulltoken: Data, fixedWidthIds: Data, time: UInt64, gpsenddrivedkp: Data) throws in
            let gpFullToken = try GroupSendFullToken(contents: [UInt8](sgpfulltoken))
            let serviceIds = try parseFixedWidthServiceIds(raw: [UInt8](fixedWidthIds))
            let groupSendKeyPair = try GroupSendDerivedKeyPair(contents: [UInt8](gpsenddrivedkp))
            try gpFullToken.verify(userIds: serviceIds, now: Date(timeIntervalSince1970: TimeInterval(time)), keyPair: groupSendKeyPair)
        }

        Function("groupSendTokenToFullToken") { (sgpsendtoken: Data, expTime: UInt64) -> Data in
            let groupSendToken = try GroupSendEndorsement.Token(contents: [UInt8](sgpsendtoken))
            return Data(groupSendToken.toFullToken(expiration: Date(timeIntervalSince1970: TimeInterval(expTime))).serialize())
        }

        Function("groupSendDerivedKeyPairForExpiration") { (expTime: UInt64, svSecParams: Data) -> Data in
            let serverSecParams = try ServerSecretParams(contents: [UInt8](svSecParams))
            return Data(GroupSendDerivedKeyPair.forExpiration(Date(timeIntervalSince1970: TimeInterval(expTime)), params: serverSecParams).serialize())
        }

        Function("groupSendEndorsementCombine") { (sendorsements: [String]) -> Data in
            
            let endorsements = try sendorsements.map { base64String in
                        guard let decodedData = Data(base64Encoded: base64String) else {
                            throw NSError(domain: "DecodingError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 string"])
                        }
                        return try GroupSendEndorsement(contents: [UInt8](decodedData))
            }
        
            return try Data(GroupSendEndorsement.combine(endorsements).serialize())
        }

        Function("groupSendEndorsementRemove") { (sgpsendendorsement: Data, toRemove: Data) -> Data in
            let endorsement = try GroupSendEndorsement(contents: [UInt8](sgpsendendorsement))
            let toRemoveEndorsement = try GroupSendEndorsement(contents: [UInt8](toRemove))
            return Data(endorsement.byRemoving(toRemoveEndorsement).serialize())
        }

        Function("groupSendEndorsementToToken") { (sgpsendendorsement: Data, sGpSecParams: Data) -> Data in
            let endorsement = try GroupSendEndorsement(contents: [UInt8](sgpsendendorsement))
            let params = try GroupSecretParams(contents: [UInt8](sGpSecParams))
            return Data(endorsement.toToken(groupParams: params).serialize())
        }

        Function("groupSendEndorsementsResponseIssueDeterministic") { (uuidCipherTexts: Data, gpsenddrivedkp: Data, rndm: Data) throws -> Data in
            let serviceIds = try parseUuidCipherTexts(raw: [UInt8](uuidCipherTexts))
            let keyPair = try GroupSendDerivedKeyPair(contents: [UInt8](gpsenddrivedkp))
            return Data(try GroupSendEndorsementsResponse.issue(groupMembers: serviceIds, keyPair: keyPair).serialize())
        }

        Function("groupSendEndorsementsResponseGetExpiration") { (gpSendEndResponse: Data) -> UInt64 in
            let response = try GroupSendEndorsementsResponse(contents: [UInt8](gpSendEndResponse))
            return UInt64(response.expiration.timeIntervalSince1970)
        }

        Function("groupSendEndorsementsResponseReceiveAndCombineWithServiceIds") { (gpSendEndResponse: Data, svcIds: Data, userId: Data, time: UInt64, gpSecParams: Data, srvPubParams: Data) throws -> [Data] in
            let response = try GroupSendEndorsementsResponse(contents: [UInt8](gpSendEndResponse))
            let serviceIds = try parseFixedWidthServiceIds(raw: [UInt8](svcIds))
            var bytes = convertDataToServiceIdStorage(data: userId)
            let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
            let uuid = UUID(uuid: (
                byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
                byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
                byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
                byteArray[12], byteArray[13], byteArray[14], byteArray[15]
            ))
                
            let userServiceId = Aci(fromUUID: uuid) 
            let userServiceBinary = byteArray

            guard let localUserIndex = serviceIds.firstIndex(where: { $0.serviceIdBinary == userServiceBinary }) else {
                throw NSError(domain: "Error", code: 1, userInfo: [NSLocalizedDescriptionKey: "Local user not present in the members' service IDs list"])
            }
            let params = try GroupSecretParams(contents: [UInt8](gpSecParams))
            let publicParams = try ServerPublicParams(contents: [UInt8](srvPubParams))
            let endorsements = try response.receive(groupMembers: serviceIds, localUser: userServiceId, groupParams: params, serverParams: publicParams).endorsements

            let combined = Data(try GroupSendEndorsement.combine(
                endorsements[..<localUserIndex] + endorsements[(localUserIndex + 1)...]
            ).serialize())
            
            return endorsements.map { Data(try! $0.serialize()) } + [combined]
        }

        Function("groupSendEndorsementsResponseReceiveAndCombineWithCiphertexts") { (gpSendEndResponse: Data, svcUuidIds: Data, userId: Data, time: UInt64, srvPubParams: Data) throws -> [Data] in
            let response = try GroupSendEndorsementsResponse(contents: [UInt8](gpSendEndResponse))
            let serviceIds = try parseUuidCipherTexts(raw: [UInt8](svcUuidIds))
            let userServiceId = try UuidCiphertext(contents: [UInt8](userId))
            let publicParams = try ServerPublicParams(contents: [UInt8](srvPubParams))

            guard let localUserIndex = serviceIds.firstIndex(where: { $0.serialize() == userServiceId.serialize() }) else {
                throw NSError(domain: "Error", code: 1, userInfo: [NSLocalizedDescriptionKey: "Local user not present in the members' service IDs list"])
            }
            
            let endorsements = try response.receive(groupMembers: serviceIds, localUser: userServiceId, serverParams: publicParams).endorsements
            
            let combined = Data(try GroupSendEndorsement.combine(
                Array(endorsements[..<localUserIndex]) + Array(endorsements[(localUserIndex + 1)...])
            ).serialize())
            return endorsements.map { Data(try! $0.serialize()) } + [combined]
        }

        Function("groupCipherEncryptMessage") { (senderAddress: String, sDistId: String, msg: Data, sSenderKeyRecord: Data) throws -> [Any] in
            guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: senderAddress) else {
                throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
            }
            let protoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)
            
            guard let distId = UUID(uuidString: sDistId) else {
                throw NSError(domain: "InvalidUUIDError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid UUID format for sDistId"])
            }
            
            let sndKeyRec = try SenderKeyRecord(bytes: [UInt8](sSenderKeyRecord))
            
    
            let senderKeyStore = InMemorySignalProtocolStore()
            try senderKeyStore.storeSenderKey(from: protoAddress, distributionId: distId, record: sndKeyRec, context: NullContext())
                        
            let cipherText = try groupEncrypt([UInt8](msg) , from:protoAddress, distributionId: distId, store: senderKeyStore ,context: NullContext())
            
            guard let newSenderKeyRecord = try senderKeyStore.loadSenderKey(from: protoAddress, distributionId: distId, context: NullContext()) else {
                throw NSError(domain: "LoadSenderKeyError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to load new sender key record"])
            }            
            let serializedCipherText = Data(cipherText.serialize())
            let serializedSenderKeyRecord = Data(newSenderKeyRecord.serialize())
            let messageType = Int(cipherText.messageType.rawValue)

            return [[serializedCipherText, messageType], serializedSenderKeyRecord]
        }

        Function("groupCipherDecryptMessage") { (senderAddress: String, msg: Data, sSenderKeyRecord: Data) throws -> [Any] in
    
            guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: senderAddress) else {
                throw NSError(domain: "InvalidAddressError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid address format"])
            }
            let protoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)

            let sndKeyRec = try SenderKeyRecord(bytes: [UInt8](sSenderKeyRecord))
            
            let senderKeyMessage = try SenderKeyMessage(bytes: [UInt8](msg))
            
            let senderKeyStore = InMemorySignalProtocolStore()
            try senderKeyStore.storeSenderKey(
                from: protoAddress,
                distributionId: senderKeyMessage.distributionId,
                record: sndKeyRec,
                context: NullContext()
            )
            let decryptedMessage = try groupDecrypt(
                [UInt8](msg),
                from: protoAddress,
                store: senderKeyStore,
                context: NullContext()
            )

            guard let newSenderKeyRecord = try senderKeyStore.loadSenderKey(
                from: protoAddress,
                distributionId: senderKeyMessage.distributionId,
                context: NullContext()
            ) else {
                throw NSError(domain: "LoadSenderKeyError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to load new sender key record"])
            }
            
            let serializedDecryptedMessage = Data(decryptedMessage)
            let serializedSenderKeyRecord = Data(newSenderKeyRecord.serialize())
            
            return [serializedDecryptedMessage, serializedSenderKeyRecord]
        }


        Function("unidentifiedSenderMessageContentNew") { (msgCiphertext: Data,
                cipherTextType: Int,
                sSenderCertificate: Data,
                contentHint: UInt32,
                groupId: Data?) -> Data in
            do {
                let senderCertificate = try SenderCertificate(sSenderCertificate)
                var signalMessageType: CiphertextMessage.MessageType = .preKey
                switch cipherTextType {
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
                let unidentifiedContent = try UnidentifiedSenderMessageContent(
                    msgCiphertext,
                    type: signalMessageType,
                    from: senderCertificate,
                    contentHint: UnidentifiedSenderMessageContent.ContentHint(rawValue: contentHint),
                    groupId: groupId ?? Data()
                )

                return Data(unidentifiedContent.serialize())
            } catch {
                throw NSError(domain: "UnidentifiedSenderError", code: 1, userInfo: [NSLocalizedDescriptionKey:  "Failed to create unidentified sender message content: \(error)"])
            }
        }



        Function("HmacSHA256") { (key: Data, data: Data) -> Data? in
            do {
                var hmac = HMAC<SHA256>(key: .init(data: [UInt8](key)))
                hmac.update(data: [UInt8](data))
                let digest = hmac.finalize()
                return Data(digest)
            } catch {
                throw NSError(domain: "HMAC calculation error: \(error)", code: 1, userInfo: nil)
                return nil
            }
        }

        Function("ConstantTimeEqual") {(lhs: Data, rhs: Data) -> Bool in
            guard lhs.count == rhs.count else {
                return false
            }

            // avoid possible nil baseAddress by ensuring buffers aren't empty
            if lhs.isEmpty {
                return rhs.isEmpty
            }

            return lhs.withUnsafeBytes { b1 in
                rhs.withUnsafeBytes { b2 in
                    timingsafe_bcmp(b1.baseAddress, b2.baseAddress, b1.count)
                }
            } == 0       
        }



        Function("sealedSenderDecryptToUsmc") { (cipherText: Data, ownerData: [Any]) throws -> Data in
            guard let base64OwnerKeypair = ownerData[0] as? String,
                let ownerRegistrationId = ownerData[1] as? UInt32 else {
                throw NSError(domain: "InvalidIdentityKeyStateFormat", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid identityKeyState format"])
            }
            
            guard let ownerKeypairData = Data(base64Encoded: base64OwnerKeypair) else {
                throw NSError(domain: "Base64DecodingError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 encoding for owner keypair"])
            }
            
            let ownerKeypair = try IdentityKeyPair(bytes: [UInt8](ownerKeypairData))
            let sigProtocStore = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerKeypair, registrationId: ownerRegistrationId)
            
            let content = try UnidentifiedSenderMessageContent(
                message: [UInt8](cipherText),
                identityStore: sigProtocStore,
                context: NullContext()
            )
            
            return Data(try content.serialize())
        }


        Function("unidentifiedSenderMessageContentGetContents"){(serializedContent: Data) in 
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.contents
        }
        Function("unidentifiedSenderMessageContentGetMsgType"){(serializedContent: Data) in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.messageType.rawValue
        }
        Function("unidentifiedSenderMessageContentGetSenderCert"){(serializedContent: Data) in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.senderCertificate.serialize()
        }
        Function("unidentifiedSenderMessageContentGetContentHint"){(serializedContent: Data) in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.contentHint.rawValue
        }
        Function("unidentifiedSenderMessageContentGetGroupId"){(serializedContent: Data) in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.groupId ?? [UInt8]()
        }

        Function("sealedSenderMultiRecipientEncrypt") { 
            (ownerIdentityData: [Any], srecipients: [String],sessionStoreState: [String: String], 
            excludedRecipients: Data, uidentcontent: Data, identityStoreState: [[String]]) in
            


            let recipients = try srecipients.map { recipient in
                guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: recipient) else {
                    throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
                }
                return try ProtocolAddress(name: serviceId, deviceId: deviceId)
            }


            let excludedServiceIds = try parseFixedWidthServiceIds(raw: [UInt8](excludedRecipients))

            guard let base64OwnerKeypair = ownerIdentityData[0] as? String,
                let ownerRegistrationId = ownerIdentityData[1] as? UInt32 else {
                throw NSError(domain: "InvalidOwnerIdentityData", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid owner identity data format"])
            }

            guard let ownerKeypairData = Data(base64Encoded: base64OwnerKeypair) else {
                throw NSError(domain: "Base64DecodingError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 encoding for owner keypair"])
            }

            let ownerIdentityKey = try IdentityKeyPair(bytes: [UInt8](ownerKeypairData))
            let sigStore = try InMemorySignalProtocolStore(identity: ownerIdentityKey, registrationId: ownerRegistrationId)

            let store = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerIdentityKey, registrationId: ownerRegistrationId)
            for (key, value) in sessionStoreState {
                guard let (inStoreName, inStoreDeviceId) = getDeviceIdAndServiceId(address: key) else {
                    throw NSError(domain: "Invalid address format", code: 5, userInfo: nil)
                }
                let keyBuffer = Data(base64Encoded: value, options: .ignoreUnknownCharacters)!
                let protoAddress = try ProtocolAddress(name: inStoreName, deviceId: UInt32(inStoreDeviceId))
                let sessionRecord = try SessionRecord(bytes: keyBuffer)
                try store.storeSession(sessionRecord, for: protoAddress, context: NullContext())
            }


            for identityPair in identityStoreState {
                guard identityPair.count == 2 else { continue }
                guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: identityPair[0]) else {
                    throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
                }
                let protocolAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)
                
                guard let identityKeyData = Data(base64Encoded: identityPair[1]) else {
                    throw NSError(domain: "Base64DecodingError", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 encoding for identity key"])
                }
                
                let identityKey = try IdentityKey(bytes: [UInt8](identityKeyData)) 
                try sigStore.saveIdentity(identityKey, for: protocolAddress, context: NullContext())
            }


            let randomUUID = UUID()
            do {
                let messageContent = try UnidentifiedSenderMessageContent(
                    bytes: [UInt8](uidentcontent)
                )   

                let encryptedMessage = try sealedSenderMultiRecipientEncrypt(
                    messageContent,
                    for: recipients,
                    excludedRecipients: excludedServiceIds,        
                    identityStore: sigStore,
                    sessionStore:store ,
                    context: NullContext()
                )

                return Data(encryptedMessage)
            } catch {
                throw NSError(domain: "UnidentifiedSenderMessageContent calculation error: \(error)", code: 1, userInfo: nil)
                return Data()
            }

           


           
        }

        Function("sealedSenderEncrypt", sealedSenderEncryptTemp)
        // TODO: uncomment after closing https://github.com/p-num/react-native-libsignal-client/issues/48
        // Function("sealedSenderMultiRecipientMessageForSingleRecipient", sealedSenderMultiRecipientMessageForSingleRecipientImplementation)
        Function("serverCertificateNew", serverCertificateNewTemp)
        Function("senderCertificateNew", senderCertificateNewTemp)
        Function("senderKeyDistributionMessageCreate", senderKeyDistributionMessageCreateTemp)
        Function("senderKeyDistributionMessageGetDistributionId") { (serializedMessage: Data) throws -> String in
            let message = try SenderKeyDistributionMessage(bytes: [UInt8](serializedMessage))
            return message.distributionId.uuidString
        }
        Function("senderKeyDistributionMessageProcess") { 
            (senderAddress: String, serializedMessage: Data, currentSerializedKey: Data) throws -> Data in

            guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: senderAddress) else {
                throw NSError(domain: "InvalidAddressFormat", code: 1, userInfo: nil)
            }
            let protoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)

            let message = try SenderKeyDistributionMessage(bytes: [UInt8](serializedMessage))
            let senderKey = try SenderKeyRecord(bytes: [UInt8](currentSerializedKey))

            let senderKeyStore = InMemorySignalProtocolStore()
            try senderKeyStore.storeSenderKey(from: protoAddress, distributionId: message.distributionId, record: senderKey, context: NullContext())

            try! processSenderKeyDistributionMessage(
                        message,
                        from: protoAddress,
                        store: senderKeyStore,
                        context: NullContext()
                    )
            guard let newSenderKeyRecord = try senderKeyStore.loadSenderKey(from: protoAddress, distributionId: message.distributionId, context: NullContext()) else {
                throw NSError(domain: "SenderKeyError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to load sender key record"])
            }

            return Data(newSenderKeyRecord.serialize())
        }
        Function("serverCertificateGetCertificate") { (serializedCertificate: Data) throws -> Data in
            let certificate = try ServerCertificate([UInt8](serializedCertificate))
            return Data(certificate.certificateBytes)
        }

                
        Function("senderCertificateGetCertificate") { (serializedCertificate: Data) throws -> Data in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return Data(certificate.certificateBytes)
        }

        
        Function("senderCertificateGetSignature") { (serializedCertificate: Data) throws -> Data in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return Data(certificate.signatureBytes)
        }

        
        Function("senderCertificateGetExpiration") { (serializedCertificate: Data) throws -> UInt64 in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return UInt64(certificate.expiration)
        }

        
        Function("senderCertificateGetKey") { (serializedCertificate: Data) throws -> Data in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return Data(try certificate.publicKey.serialize())
        }

        
        Function("senderCertificateGetSenderE164") { (serializedCertificate: Data) throws -> String? in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return certificate.senderE164
        }

        
        Function("senderCertificateGetSenderUuid") { (serializedCertificate: Data) throws -> String in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return certificate.senderUuid
        }

        
        Function("senderCertificateGetDeviceId") { (serializedCertificate: Data) throws -> Int in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return Int(certificate.deviceId)
        }

        
        Function("senderCertificateGetServerCertificate") { (serializedCertificate: Data) throws -> Data in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            return Data(try certificate.serverCertificate.serialize())
        }

        
        Function("senderCertificateValidate") { (trustRoot: Data, serializedCertificate: Data, timestamp: UInt64) -> Bool in
            do {
                let certificate = try SenderCertificate([UInt8](serializedCertificate))
                let publicKey = try PublicKey([UInt8](trustRoot))
                try certificate.validate(trustRoot: publicKey, time: timestamp)
                return true
            } catch {
                return false
            }
        }


        Function("serverCertificateGetKey") { (serializedCertificate: Data) throws -> Data in
            let certificate = try ServerCertificate([UInt8](serializedCertificate))
            return Data(try certificate.publicKey.serialize())
        }

        Function("serverCertificateGetKeyId") { (serializedCertificate: Data) throws -> UInt32 in
            let certificate = try ServerCertificate([UInt8](serializedCertificate))
            return certificate.keyId
        }

        Function("serverCertificateGetSignature") { (serializedCertificate: Data) throws -> Data in
            let certificate = try ServerCertificate([UInt8](serializedCertificate))
            return Data(certificate.signatureBytes)
        }

        Function("senderKeyDistributionMessageGetChainKey") { (serializedMessage: Data) throws -> Data in
            let message = try SenderKeyDistributionMessage(bytes: [UInt8](serializedMessage))
            return Data(message.chainKey)
        }

        Function("senderKeyDistributionMessageGetIteration") { (serializedMessage: Data) throws -> UInt32 in
            let message = try SenderKeyDistributionMessage(bytes: [UInt8](serializedMessage))
            return message.iteration
        }

        Function("senderKeyDistributionMessageGetChainId") { (serializedMessage: Data) throws -> UInt32 in
            let message = try SenderKeyDistributionMessage(bytes: [UInt8](serializedMessage))
            return message.chainId
        }
        Function("senderKeyMessageGetDistributionId") { (serializedMessage: Data) throws -> String in
            let message = try SenderKeyMessage(bytes: [UInt8](serializedMessage))
            return message.distributionId.uuidString
        }
        Function("senderKeyMessageVerifySignature") { (serializedMessage: Data, serializedSenderIdentityKey: Data) -> Bool in
            do {
                let message = try SenderKeyMessage(bytes: [UInt8](serializedMessage))
                let senderIdentityKey = try PublicKey([UInt8](serializedSenderIdentityKey))
                try message.verifySignature(against: senderIdentityKey)
                return true
            } catch {
                return false
            }
        }

        Function("genericServerSecretParamsGetPublicParams") { (genericServerSecParamsRaw: Data) -> [UInt8] in
            return try! genericServerSecretParamsGetPublicParamsHelper(genericServerSecParamsRaw: genericServerSecParamsRaw)
        }

        Function("backupAuthCredentialRequestContextNew") { (backupKeyr: Data, acir: String) -> Data in
            guard let aci = UUID(uuidString: acir) else {
                throw NSError(domain: "InvalidUUIDError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid UUID format for acir"])
            }
            return Data(try BackupAuthCredentialRequestContext.create(backupKey: [UInt8](backupKeyr), aci: aci).serialize())
        }

        Function("backupAuthCredentialRequestContextGetRequest") { (backupReqCtxRaw: Data) -> Data in
            let requestContext = try BackupAuthCredentialRequestContext(contents: [UInt8](backupReqCtxRaw))
            return Data(try requestContext.getRequest().serialize())
        }

        Function("backupAuthCredentialRequestContextReceiveResponse") { (backupReqCtxRaw: Data, backupResRaw: Data, redemptionTime: UInt64, genericServerPubParamsRaw: Data) -> Data in
            let requestContext = try BackupAuthCredentialRequestContext(contents: [UInt8](backupReqCtxRaw))
            let response = try BackupAuthCredentialResponse(contents: [UInt8](backupResRaw))
            let genericServerParams = try GenericServerPublicParams(contents: [UInt8](genericServerPubParamsRaw))
            
            return Data(try requestContext.receiveResponse(
                response: response,
                timestamp: redemptionTime,
                params: genericServerParams
            ).serialize())
        }

        Function("backupAuthCredentialRequestIssueDeterministic") { (backupReqRaw: Data, timestamp: UInt64, backuplevel: Int, credentialType: Int, genericServerSecParamsRaw: Data, randomness: Data) -> Data in
            let request = try BackupAuthCredentialRequest(contents: [UInt8](backupReqRaw))
            let genericServerParams = try GenericServerSecretParams(contents: [UInt8](genericServerSecParamsRaw))
            
            guard randomness.count == 32 else {
                throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
            }
            let randomnessBytes = randomness.withUnsafeBytes { pointer in
                pointer.load(as: SignalRandomnessBytes.self)
            }
            
            return Data(try request.issueCredential(
                timestamp: timestamp,
                backupLevel: BackupLevel.fromValue(backuplevel),
                credentialType: BackupCredentialType.fromValue(credentialType),
                params: genericServerParams,
                randomness: Randomness(randomnessBytes)
            ).serialize())
        }

        Function("backupAuthCredentialPresentationVerify") { (bckCredPresRaw: Data, timestamp: UInt64, genericServerSecParamsRaw: Data) in
            let presentation = try BackupAuthCredentialPresentation(contents: [UInt8](bckCredPresRaw))
            let genericServerParams = try GenericServerSecretParams(contents: [UInt8](genericServerSecParamsRaw))
            
            try presentation.verify(timestamp: timestamp, params: genericServerParams)
        }

        Function("backupAuthCredentialPresentationGetBackupId") { (bckCredPresRaw: Data) -> Data in
            let presentation = try BackupAuthCredentialPresentation(contents: [UInt8](bckCredPresRaw))
            return Data(presentation.backupId)
        }

        Function("backupAuthCredentialPresentationGetBackupLevel") { (bckCredPresRaw: Data) -> Int in
            let presentation = try BackupAuthCredentialPresentation(contents: [UInt8](bckCredPresRaw))
            return presentation.backupLevel.toNumber()
        }

        Function("backupAuthCredentialPresentationGetType") { (bckCredPresRaw: Data) -> Int in
            let presentation = try BackupAuthCredentialPresentation(contents: [UInt8](bckCredPresRaw))
            return presentation.credentialType.toNumber()
        }

        Function("backupAuthCredentialPresentDeterministic") { (bckAuthCredRaw: Data, genericServerPubParamsRaw: Data, randomness: Data) -> Data in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            let genericServerParams = try GenericServerPublicParams(contents: [UInt8](genericServerPubParamsRaw))
            
            guard randomness.count == 32 else {
                throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
            }
            let randomnessBytes = randomness.withUnsafeBytes { pointer in
                pointer.load(as: SignalRandomnessBytes.self)
            }
            
            return Data(try credential.present(
                params: genericServerParams,
                randomness: Randomness(randomnessBytes)
            ).serialize())
        }

        Function("backupAuthCredentialGetBackupId") { (bckAuthCredRaw: Data) -> Data in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            return Data(credential.backupId)
        }

        Function("backupAuthCredentialGetBackupLevel") { (bckAuthCredRaw: Data) -> Int in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            return credential.backupLevel.toNumber()
        }

        Function("backupAuthCredentialGetType") { (bckAuthCredRaw: Data) -> Int in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            return credential.credentialType.toNumber()
        }

        Function("genericServerSecretParamsGenerateDeterministic") { (randomness: Data) -> Data in
            guard randomness.count == 32 else {
                throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
            }
            let randomnessBytes = randomness.withUnsafeBytes { pointer in
                pointer.load(as: SignalRandomnessBytes.self)
            }
            return Data(try GenericServerSecretParams.generate(randomness: Randomness(randomnessBytes)).serialize())
        }

        Function("genericServerSecretParamsGetPublicParams") { (genericServerSecParamsRaw: Data) -> Data in
            let secretParams = try GenericServerSecretParams(contents: [UInt8](genericServerSecParamsRaw))
            return Data(try secretParams.getPublicParams().serialize())
        }

        /*END          bridge functions definitions              END*/
    }

    /*START          bridge functions implementation              START*/
    private func senderKeyDistributionMessageCreateTemp(
        senderAddress: String,
        distId: String,
        sKeyRecord: Data
    ) throws ->  [Any] {
        
        guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: senderAddress) else {
            throw NSError(domain: "InvalidAddressFormat", code: 1, userInfo: nil)
        }
        
        let senderProtocolAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)
        let senderKeyStore = InMemorySignalProtocolStore()
        
        guard let distributionId = UUID(uuidString: distId) else {
            throw NSError(domain: "InvalidUUIDError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid UUID format for distId"])
        }
        
        if !sKeyRecord.isEmpty {
            let rec = try SenderKeyRecord(bytes: [UInt8](sKeyRecord))
            try senderKeyStore.storeSenderKey(from: senderProtocolAddress, distributionId: distributionId, record: rec, context: NullContext())
        }
        
        let senderKeyDistributionMessage = try! SenderKeyDistributionMessage(from: senderProtocolAddress, distributionId: distributionId, store: senderKeyStore, context: NullContext())

        let updatedRec = try? senderKeyStore.loadSenderKey(from: senderProtocolAddress, distributionId: distributionId, context: NullContext())
        let updatedRecSer = updatedRec?.serialize() ?? []

        return [Data(senderKeyDistributionMessage.serialize()), Data(updatedRecSer)]
    }
    private func senderCertificateNewTemp(
        localSenderUuid: String,
        senderE164: String,
        senderDeviceId: UInt32,
        senderKey: Data,
        expiration: UInt64,
        signerCert: Data,
        signerKey: Data
    ) throws -> Data {
        
        let senderPubKey = try PublicKey([UInt8](senderKey))
        let signerCertif = try ServerCertificate([UInt8](signerCert))
        let signerPrivKey = try PrivateKey([UInt8](signerKey))

        let senderOpE164: String? = senderE164.isEmpty ? nil : senderE164
        let sender_addr = try! SealedSenderAddress(
            e164: senderOpE164,
            uuidString: localSenderUuid,
            deviceId: senderDeviceId
        )
        let certificate = try SenderCertificate(
            sender: sender_addr,
            publicKey: senderPubKey,
            expiration: expiration,
            signerCertificate:signerCertif,
            signerKey:signerPrivKey
        )

        return Data(certificate.serialize())
    }
    private func serverCertificateNewTemp(keyId: UInt32, serverKey: Data, trustKey: Data) throws -> Data {
        let trustRoot = try PrivateKey([UInt8](trustKey))
        let serverKeyPub = try PublicKey([UInt8](serverKey))

        let certificate = try! ServerCertificate(keyId: keyId,publicKey: serverKeyPub, trustRoot: trustRoot )

        return Data(certificate.serialize())
    }
    // TODO: uncomment after closing https://github.com/p-num/react-native-libsignal-client/issues/48
    // private func sealedSenderMultiRecipientMessageForSingleRecipientImplementation(message: Data) throws -> Data {
    //     return try Data(LibSignalClient.sealedSenderMultiRecipientMessageForSingleRecipient([UInt8](message)))
    // }

    private func sealedSenderEncryptTemp(destAddress: String, unidentifiedContent: Data, identityKeyState: [Any]) throws -> Data {
        guard let (serviceId, deviceId) = getDeviceIdAndServiceId(address: destAddress) else {
            throw NSError(domain: "Invalid address format", code: 1, userInfo: nil)
        }
        let protoAddress = try ProtocolAddress(name: serviceId, deviceId: deviceId)

        guard identityKeyState.count == 2,
            let base64IdentityKey = identityKeyState[0] as? String,
            let ownerData = identityKeyState[1] as? [Any],
            ownerData.count == 2,
            let base64OwnerKeypair = ownerData[0] as? String,
            let ownerRegistrationId = ownerData[1] as? UInt32 else {
            throw NSError(domain: "InvalidIdentityKeyState", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid identity key state format"])
        }
        guard let ownerKeypairData = Data(base64Encoded: base64OwnerKeypair),
            let identityKeyData = Data(base64Encoded: base64IdentityKey) else {
            throw NSError(domain: "Base64DecodingError", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 encoding"])
        }
        let ownerKeypair = try IdentityKeyPair(bytes: [UInt8](ownerKeypairData))
        let identityKey = try IdentityKey(bytes: [UInt8](identityKeyData))
        let store = InMemorySignalProtocolStoreWithPreKeysList(identity: ownerKeypair, registrationId: ownerRegistrationId)
        try store.saveIdentity(identityKey, for: protoAddress, context: NullContext())
        let randomUUID = UUID()
        let content = try UnidentifiedSenderMessageContent(
            bytes: [UInt8](unidentifiedContent)
        )
        let encryptedContent = try sealedSenderEncrypt(
            content,
            for: protoAddress,
            identityStore: store,
            context: NullContext()
        )

        return Data(encryptedContent)
    }
    private func groupSecretParamsDecryptBlobWithPaddingHelper(sGroupSecretParams: Data, blobCipherText: Data) throws -> [UInt8] {
        let groupSecretParams = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let clientZkCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
        
        let decryptedBlob = try clientZkCipher.decryptBlob(blobCiphertext: [UInt8](blobCipherText))
        
        return decryptedBlob
    }
    private func groupSecretParamsEncryptBlobWithPaddingDeterministicHelper(sGroupSecretParams: Data, randomNess: [UInt8], plainText: Data, paddingLen: Int) throws -> [UInt8] {
        let groupSecretParams = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let clientZkCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
        guard randomNess.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = randomNess.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        let encryptedBlob = try clientZkCipher.encryptBlob(randomness:Randomness(randomnessBytes), plaintext: [UInt8](plainText))
        
        return encryptedBlob
    }
    private func serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministicHelper(sSrvSecParams: Data, rndm: Data, sAci: Data, sPni: Data, redemptionTime: Double) throws -> [UInt8] {
        let srvSecParams = try ServerSecretParams(contents: [UInt8](sSrvSecParams))
        let serverAuthOp = ServerZkAuthOperations(serverSecretParams: srvSecParams)
        var bytes = convertDataToServiceIdStorage(data: sAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        
        let aci = Aci(fromUUID: uuid)
        var bytes2 = convertDataToServiceIdStorage(data: sPni)
        let byteArray2 = try signalServiceIdServiceIdBinary(value: &bytes2)
        let uuid2 = UUID(uuid: (
            byteArray2[1], byteArray2[2], byteArray2[3], 
            byteArray2[4], byteArray2[5], byteArray2[6], byteArray2[7], 
            byteArray2[8], byteArray2[9], byteArray2[10], byteArray2[11], 
            byteArray2[12], byteArray2[13], byteArray2[14], byteArray2[15],byteArray2[16]
        ))
        let pni = Pni(fromUUID: uuid2)
        guard rndm.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = rndm.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        let redemptionTimeUInt64: UInt64 = UInt64(redemptionTime)
        let authCredPniResp = try serverAuthOp.issueAuthCredentialWithPniZkc(randomness: Randomness(randomnessBytes), aci: aci, pni: pni, redemptionTime: redemptionTimeUInt64)
        
        return authCredPniResp.serialize()
    }
    func parseUuidCipherTexts(raw: [UInt8]) throws -> [UuidCiphertext] {
        guard raw.count % 65 == 0 else {
            throw NSError(domain: "Invalid UUID ciphertexts length", code: 1, userInfo: nil)
        }

        var clc: [UuidCiphertext] = []
        let count = raw.count / 65
        for i in 0..<count {
            let start = i * 65
            let end = start + 65
            let cphtx = try UuidCiphertext(contents: Array(raw[start..<end]))
            clc.append(cphtx)
        }
 
        return clc
    }

    func parseFixedWidthServiceIds(raw: [UInt8]) throws -> [ServiceId] {
        guard raw.count % 17 == 0 else {
            throw NSError(domain: "Invalid service ids length", code: 1, userInfo: nil)
        }
        
        return try stride(from: 0, to: raw.count, by: 17).map { i in  
            let slice = Data(raw[i..<(i + 17)])
            var bytes = convertDataToServiceIdStorage(data: slice)
            let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
            let uuid = UUID(uuid: (
                byteArray[0], byteArray[1], byteArray[2], byteArray[3],
                byteArray[4], byteArray[5], byteArray[6], byteArray[7],
                byteArray[8], byteArray[9], byteArray[10], byteArray[11],
                byteArray[12], byteArray[13], byteArray[14], byteArray[15]
            ))
            return Aci(fromUUID: uuid)
        }
    }
    private func serverSecretParamsIssueAuthCredentialWithPniZkcDeterministicHelper(sSrvSecParams: Data, rndm: Data, sAci: Data, sPni: Data, redemptionTime: Double) throws -> [UInt8] {
        let srvSecParams = try ServerSecretParams(contents: [UInt8](sSrvSecParams))
        let serverAuthOp = ServerZkAuthOperations(serverSecretParams: srvSecParams)
        var bytes = convertDataToServiceIdStorage(data: sAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        
        let aci = Aci(fromUUID: uuid)
        var bytes2 = convertDataToServiceIdStorage(data: sPni)
        let byteArray2 = try signalServiceIdServiceIdBinary(value: &bytes2)
        let uuid2 = UUID(uuid: (
            byteArray2[1], byteArray2[2], byteArray2[3], 
            byteArray2[4], byteArray2[5], byteArray2[6], byteArray2[7], 
            byteArray2[8], byteArray2[9], byteArray2[10], byteArray2[11], 
            byteArray2[12], byteArray2[13], byteArray2[14], byteArray2[15], byteArray2[16]
        ))
        let pni = Pni(fromUUID: uuid2)
        guard rndm.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = rndm.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        let redemptionTimeUInt64: UInt64 = UInt64(redemptionTime)
        let authCredPniResp = try serverAuthOp.issueAuthCredentialWithPniZkc(randomness:Randomness(randomnessBytes), aci: aci, pni: pni, redemptionTime:  redemptionTimeUInt64)
        
        return authCredPniResp.serialize()
    }

    private func serverSecretParamsGenerateDeterministicHelper(randomNess: Data) throws -> [UInt8] {
        guard randomNess.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = randomNess.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        let srvSecParams = try ServerSecretParams.generate(randomness:  Randomness(randomnessBytes))
        return srvSecParams.serialize()
    }
    private func serverSecretParamsVerifyAuthCredentialPresentationHelper(sSrvSecParams: Data, sGpPublicParams: Data, sAuthCredPresent: Data, instant: Double) throws {
        let srvSecParams = try ServerSecretParams(contents: [UInt8](sSrvSecParams))
        let serverAuthOp = ServerZkAuthOperations(serverSecretParams: srvSecParams)
        let gpPubParams = try GroupPublicParams(contents: [UInt8](sGpPublicParams))
        let authCredPresentation = try AuthCredentialPresentation(contents: [UInt8](sAuthCredPresent))
        
        try serverAuthOp.verifyAuthCredentialPresentation(groupPublicParams:gpPubParams , authCredentialPresentation: authCredPresentation , now: Date(timeIntervalSince1970: instant))
    }
    private func groupSecretParamsEncryptCiphertextHelper(sGpSecParams: Data, sServiceId: Data) throws -> [UInt8] {
        let gpSecParams = try GroupSecretParams(contents: [UInt8](sGpSecParams))
        var bytes = convertDataToServiceIdStorage(data: sServiceId)
        let serviceIdBinary = try signalServiceIdServiceIdBinary(value: &bytes)
        let serviceId = try ServiceId.parseFrom(serviceIdBinary: serviceIdBinary)

        let clZkGpCipher = ClientZkGroupCipher(groupSecretParams: gpSecParams)
        
        return try clZkGpCipher.encrypt(serviceId).serialize()
    }
    private func serverSecretParamsIssueExpiringProfileKeyCredentialDeterministicHelper(sSrvSecParams: Data, rand: Data, sProfCredRequest: Data, sAci: Data, sProfileKeyCommitment: Data, expiration: UInt64) throws -> [UInt8] {
        let srvSecretParams = try ServerSecretParams(contents: [UInt8](sSrvSecParams))
        let srvProfileOp = ServerZkProfileOperations(serverSecretParams: srvSecretParams)
        let profCredRequest = try ProfileKeyCredentialRequest(contents: [UInt8](sProfCredRequest))
        var bytes = convertDataToServiceIdStorage(data: sAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        let aci = Aci(fromUUID: uuid)
        let profCommitment = try ProfileKeyCommitment(contents: [UInt8](sProfileKeyCommitment))
        guard rand.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = rand.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        let expiringProfileKeyCred = try srvProfileOp.issueExpiringProfileKeyCredential(randomness: Randomness(randomnessBytes), profileKeyCredentialRequest: profCredRequest, userId: aci, profileKeyCommitment: profCommitment, expiration: expiration)
        
        return expiringProfileKeyCred.serialize()
    }
    private func serverSecretParamsVerifyProfileKeyCredentialPresentationHelper(sSrvSecParams: Data, sGpPublicParams: Data, sProfileKeyCredentialPresentation: Data, instant: Double) throws {
        let srvSecretParams = try ServerSecretParams(contents: [UInt8](sSrvSecParams))
        let srvProfileOp = ServerZkProfileOperations(serverSecretParams: srvSecretParams)
        let gpPubParams = try GroupPublicParams(contents: [UInt8](sGpPublicParams))
        let profKeyCredPresentation = try ProfileKeyCredentialPresentation(contents: [UInt8](sProfileKeyCredentialPresentation))
        
        try srvProfileOp.verifyProfileKeyCredentialPresentation(groupPublicParams: gpPubParams, profileKeyCredentialPresentation: profKeyCredPresentation, now: Date(timeIntervalSince1970: instant))
    }
    private func serverSecretParamsGetPublicParamsHelper(sSrvSecParams: Data) throws -> [UInt8] {
        let srvSecParams = try ServerSecretParams(contents:  [UInt8](sSrvSecParams))
        return try srvSecParams.getPublicParams().serialize()
    }
    private func serverSecretParamsSignDeterministicHelper(sSrvSecParams: Data, rndm: Data, msg: Data) throws -> [UInt8] {
        let srvSecParams = try ServerSecretParams(contents: [UInt8](sSrvSecParams))
        return try srvSecParams.sign(message: [UInt8](msg)).serialize()
    }
    private func serverPublicParamsVerifySignatureHelper(serializedSrvPubParams: Data, msg: Data, sig: Data) throws -> Bool {
        let svpublicParams = try ServerPublicParams(contents: [UInt8](serializedSrvPubParams))
        let signature = try NotarySignature(contents: [UInt8](sig))

        do {
            try svpublicParams.verifySignature(message: [UInt8](msg), notarySignature: signature)
            return true
        } catch {
            return false
        }
    }

    private func groupPublicParamsGetGroupIdentifierHelper(serializedGpPubParams: Data) throws -> [UInt8] {
        let groupPublicParams = try GroupPublicParams(contents: [UInt8](serializedGpPubParams))
        return try groupPublicParams.getGroupIdentifier().serialize()
    }

    private func groupSecretParamsDeriveFromMasterKeyHelper(serializedGpMasterKey: Data) throws -> [UInt8] {
        let masterKey = try GroupMasterKey(contents: [UInt8](serializedGpMasterKey))
        let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)
        return groupSecretParams.serialize()
    }

    private func groupSecretParamsGetPublicParamsHelper(gpSecParams: Data) throws -> [UInt8] {
        let groupSecretParams = try GroupSecretParams(contents: [UInt8](gpSecParams))
        let publicParams = try groupSecretParams.getPublicParams()
        return publicParams.serialize()
    }


    private func generateRandomBytesHelper(len: Int) throws -> [UInt8] {
        var randomBytes = [UInt8](repeating: 0, count: len)
        let status = SecRandomCopyBytes(kSecRandomDefault, len, &randomBytes)
        
        guard status == errSecSuccess else {
            throw NSError(domain: "RandomBytesGenerationError", code: Int(status), userInfo: nil)
        }
        
        return randomBytes
    }

    private func profileKeyGetCommitmentHelper(serializedProfileKey: Data, fixedWidthAci: Data) throws -> [UInt8] {
        let pk = try ProfileKey(contents: [UInt8](serializedProfileKey))
        var bytes = convertDataToServiceIdStorage(data: fixedWidthAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        
        let aci = Aci(fromUUID: uuid)
        return try pk.getCommitment(userId: aci).serialize()
    }

    private func profileKeyDeriveAccessKeyHelper(serializedProfileKey: Data) throws -> [UInt8] {
        let pk = try ProfileKey(contents: [UInt8](serializedProfileKey))
        return pk.deriveAccessKey()
    }

    private func groupSecretParamsEncryptServiceIdHelper(sGroupSecretParams: Data, fixedWidthServiceId: Data) throws -> [UInt8] {
        let gsp = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let sIdBinary = try serviceIdServiceIdBinaryHelper(fixedWidthServiceId: fixedWidthServiceId)
        let sId = try ServiceId.parseFrom(serviceIdBinary: sIdBinary)
        let clZkCipher = ClientZkGroupCipher(groupSecretParams: gsp)
        return try clZkCipher.encrypt(sId).serialize()
    }

    private func groupSecretParamsDecryptServiceIdHelper(sGroupSecretParams: Data, rawCipherText: Data) throws -> [UInt8] {
        let gsp = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let cipherText = try UuidCiphertext(contents: [UInt8](rawCipherText))
        let clZkCipher = ClientZkGroupCipher(groupSecretParams: gsp)
        let decryptedServiceId = try clZkCipher.decrypt(cipherText)
        return decryptedServiceId.serviceIdFixedWidthBinary
    }

    private func groupSecretParamsEncryptProfileKeyHelper(sGroupSecretParams: Data, rawProfileKey: Data, fixedWidthAci: Data) throws -> [UInt8] {
        let gsp = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let pk = try ProfileKey(contents: [UInt8](rawProfileKey))
        var bytes = convertDataToServiceIdStorage(data: fixedWidthAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        let aci = Aci(fromUUID: uuid)
        let clZkCipher = ClientZkGroupCipher(groupSecretParams: gsp)
        return try clZkCipher.encryptProfileKey(profileKey: pk, userId: aci).serialize()
    }

    private func groupSecretParamsDecryptProfileKeyHelper(sGroupSecretParams: Data, rawProfileKeyCipherText: Data, fixedWidthAci: Data) throws -> [UInt8] {
        let gsp = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let pkct = try ProfileKeyCiphertext(contents: [UInt8](rawProfileKeyCipherText))
        var bytes = convertDataToServiceIdStorage(data: fixedWidthAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        let aci = Aci(fromUUID: uuid)
        let clZkCipher = ClientZkGroupCipher(groupSecretParams: gsp)
        return try clZkCipher.decryptProfileKey(profileKeyCiphertext: pkct, userId: aci).serialize()
    }

    private func encryptBlobWithPaddingDeterministicHelper(sGroupSecretParams: Data, randomNess: Data, plainText: Data, paddingLen: Int) throws -> [UInt8] {
        let gsp = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let clZkCipher = ClientZkGroupCipher(groupSecretParams: gsp)

        guard randomNess.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = randomNess.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        return try clZkCipher.encryptBlob(randomness: Randomness(randomnessBytes), plaintext: [UInt8](plainText))
    }

    private func decryptBlobWithPaddingHelper(sGroupSecretParams: Data, blobCipherText: Data) throws -> [UInt8] {
        let gsp = try GroupSecretParams(contents: [UInt8](sGroupSecretParams))
        let clZkCipher = ClientZkGroupCipher(groupSecretParams: gsp)
        return try clZkCipher.decryptBlob(blobCiphertext: [UInt8](blobCipherText))
    }

    private func expiringProfileKeyCredentialGetExpirationTimeHelper(sExpiringProfileKeyCredential: Data) throws -> Int64 {
            let expkc = try ExpiringProfileKeyCredential(contents: [UInt8](sExpiringProfileKeyCredential))
            return Int64(expkc.expirationTime.timeIntervalSince1970)
        }
        private func profileKeyCredentialPresentationGetUuidCiphertextHelper(sProfileKeyCredentialPresentation: Data) throws -> [UInt8] {
        let pkcp = try ProfileKeyCredentialPresentation(contents: [UInt8](sProfileKeyCredentialPresentation))
        return try pkcp.getUuidCiphertext().serialize()
    }

    private func profileKeyCredentialPresentationGetProfileKeyCiphertextHelper(sProfileKeyCredentialPresentation: Data) throws -> [UInt8] {
        let pkcp = try ProfileKeyCredentialPresentation(contents: [UInt8](sProfileKeyCredentialPresentation))
        return try pkcp.getProfileKeyCiphertext().serialize()
    }

    private func profileKeyCredentialRequestContextGetRequestHelper(sProfileKeyCredentialRequestContext: Data) throws -> [UInt8] {
        let pkcrc = try ProfileKeyCredentialRequestContext(contents: [UInt8](sProfileKeyCredentialRequestContext))
        return try pkcrc.getRequest().serialize()
    }

    private func serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministicHelper(
        sServerPublicParams: Data,
        randomness: Data,
        fixedWidthAci: Data,
        sProfileKey: Data
    ) throws -> [UInt8] {
        let serverPublicParams = try ServerPublicParams(contents: [UInt8](sServerPublicParams))
        let clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams: serverPublicParams)
        var bytes = convertDataToServiceIdStorage(data: fixedWidthAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        let aci = Aci(fromUUID: uuid)
        let profileKey = try ProfileKey(contents: [UInt8](sProfileKey))
        guard randomness.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = randomness.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        return try clientZkProfileOperation.createProfileKeyCredentialRequestContext(
            randomness: Randomness(randomnessBytes), 
            userId: aci, 
            profileKey: profileKey
        ).serialize()
    }

    private func serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministicHelper(
        sServerPublicParams: Data,
        randomness: Data,
        sGpSecParams: Data,
        sExpProfKeyCred: Data
    ) throws -> [UInt8] {
        let serverPublicParams = try ServerPublicParams(contents: [UInt8](sServerPublicParams))
        let clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams: serverPublicParams)
        let groupSecretParams = try GroupSecretParams(contents: [UInt8](sGpSecParams))
        let expProfKeyCredential = try ExpiringProfileKeyCredential(contents: [UInt8](sExpProfKeyCred))
        guard randomness.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = randomness.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        return try clientZkProfileOperation.createProfileKeyCredentialPresentation(
            randomness: Randomness(randomnessBytes), 
            groupSecretParams: groupSecretParams, 
            profileKeyCredential: expProfKeyCredential
        ).serialize()
    }

    private func authCredentialPresentationGetUuidCiphertextHelper(sAuthCredPres: Data) throws -> [UInt8] {
        let authCredPresentation = try AuthCredentialPresentation(contents: [UInt8](sAuthCredPres))
        return try authCredPresentation.getUuidCiphertext().serialize()
    }

    private func authCredentialPresentationGetPniCiphertextHelper(sAuthCredPres: Data) throws -> [UInt8] {
        let authCredPresentation = try AuthCredentialPresentation(contents: [UInt8](sAuthCredPres))
        let pniCiphertext = try authCredPresentation.getPniCiphertext()
        return pniCiphertext.serialize()
    }

    private func authCredentialPresentationGetRedemptionTimeHelper(sAuthCredPres: Data) throws -> Int64 {
        let authCredPresentation = try AuthCredentialPresentation(contents: [UInt8](sAuthCredPres))
        return try Int64(authCredPresentation.getRedemptionTime().timeIntervalSince1970)
    }

    private func serverPublicParamsReceiveAuthCredentialWithPniAsServiceIdHelper(
        sSrvPubParams: Data,
        fixedWidthAci: Data,
        fixedWidthPni: Data,
        redemptionTime: UInt64,
        authCredPniResp: Data
    ) throws -> [UInt8] {
        

        let serverPublicParams = try ServerPublicParams(contents: [UInt8](sSrvPubParams))
        let clientZkAuthOperation = ClientZkAuthOperations(serverPublicParams: serverPublicParams)
        var bytes = convertDataToServiceIdStorage(data: fixedWidthAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)

        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        let aci = Aci(fromUUID: uuid)
        var bytes2 = convertDataToServiceIdStorage(data: fixedWidthPni)
        let byteArray2 = try signalServiceIdServiceIdBinary(value: &bytes2)
        let uuid2 = UUID(uuid: (
            byteArray2[1], byteArray2[2], byteArray2[3], 
            byteArray2[4], byteArray2[5], byteArray2[6], byteArray2[7], 
            byteArray2[8], byteArray2[9], byteArray2[10], byteArray2[11], 
            byteArray2[12], byteArray2[13], byteArray2[14], byteArray2[15], byteArray2[16]
        ))
        let pni = Pni(fromUUID: uuid2)

        let authCredentialPniResponse = try AuthCredentialWithPniResponse(contents: [UInt8](authCredPniResp))
        return try clientZkAuthOperation.receiveAuthCredentialWithPniAsServiceId(
            aci: aci, 
            pni: pni, 
            redemptionTime: redemptionTime, 
            authCredentialResponse: authCredentialPniResponse
        ).serialize()

    }

    private func serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministicHelper(
        sSrvPubParams: Data,
        randomness: Data,
        sGpSecParams: Data,
        authCredPni: Data
    ) throws -> [UInt8] {
        let serverPublicParams = try ServerPublicParams(contents: [UInt8](sSrvPubParams))
        let clientZkAuthOperation = ClientZkAuthOperations(serverPublicParams: serverPublicParams)
        let gpSecretParams = try GroupSecretParams(contents: [UInt8](sGpSecParams))
        let authCredentialPni = try AuthCredentialWithPni(contents: [UInt8](authCredPni))
        guard randomness.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = randomness.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }
        return try clientZkAuthOperation.createAuthCredentialPresentation(
            randomness: Randomness(randomnessBytes), 
            groupSecretParams: gpSecretParams, 
            authCredential: authCredentialPni
        ).serialize()
    }

    private func serverPublicParamsReceiveExpiringProfileKeyCredentialHelper(
        sServerPublicParams: Data,
        sProfileKeyCredReqCtx: Data,
        sExpProfileKeyCredResponse: Data,
        ts: Int64
    ) throws -> [UInt8] {
        let serverPublicParams = try ServerPublicParams(contents: [UInt8](sServerPublicParams))
        let clientZkProfileOperation = ClientZkProfileOperations(serverPublicParams: serverPublicParams)
        let pkCredReqCtx = try ProfileKeyCredentialRequestContext(contents: [UInt8](sProfileKeyCredReqCtx))
        let pkExpCredResp = try ExpiringProfileKeyCredentialResponse(contents: [UInt8](sExpProfileKeyCredResponse))
        return try clientZkProfileOperation.receiveExpiringProfileKeyCredential(
            profileKeyCredentialRequestContext: pkCredReqCtx, 
            profileKeyCredentialResponse: pkExpCredResp
        ).serialize()
    }

    private func profileKeyGetVersionHelper(serializedProfileKey: Data, fixedWidthAci: Data) throws -> [UInt8] {
        let pk = try ProfileKey(contents: [UInt8](serializedProfileKey))
        var bytes = convertDataToServiceIdStorage(data: fixedWidthAci)
        let byteArray = try signalServiceIdServiceIdBinary(value: &bytes)
        let uuid = UUID(uuid: (
            byteArray[0], byteArray[1], byteArray[2], byteArray[3], 
            byteArray[4], byteArray[5], byteArray[6], byteArray[7], 
            byteArray[8], byteArray[9], byteArray[10], byteArray[11], 
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        ))
        
        let aci = Aci(fromUUID: uuid)
        return try pk.getProfileKeyVersion(userId: aci).serialize()
    }


    private func groupSecretParamsGetMasterKeyHelper(gpSecParams: Data) throws -> [UInt8] {
        let groupSecretParams = try GroupSecretParams(contents: [UInt8](gpSecParams))
        let masterKey = try groupSecretParams.getMasterKey()
        return masterKey.serialize()
    }
    private func groupSecretParamsGenerateDeterministicHelper(rawrand: [UInt8]) throws -> [UInt8] {
        let rand = Data(rawrand)
        guard rand.count == 32 else {
            throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
        }
        let randomnessBytes = rand.withUnsafeBytes { pointer in
            pointer.load(as: SignalRandomnessBytes.self)
        }

        let groupSecretParams = try GroupSecretParams.generate(randomness: Randomness(randomnessBytes))
        return groupSecretParams.serialize()
    }
    private func identityKeyPairSerializeHelper(serializedPublicKey: Data, serializedPrivateKey: Data) throws -> Data {
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

    private func preKeySignalMessageGetSignedPreKeyIdHelper(serializedMessage: Data) throws -> UInt32 {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return message.signedPreKeyId
    }

    private func preKeySignalMessageGetVersionHelper(serializedMessage: Data) throws -> UInt32 {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return try message.version()
    }

    private func preKeySignalMessageGetRegistrationIdHelper(serializedMessage: Data) throws -> UInt32 {
        let message = try PreKeySignalMessage(bytes: serializedMessage)
        return try message.registrationId()
    }

    private func preKeySignalMessageGetPreKeyIdHelper(serializedMessage: Data) throws -> UInt32? {
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
        serializedMessage: Data,
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
        serializedMessage: Data,
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
        let content = try DecryptionErrorMessage(bytes: serializedContent)
        return Int64(content.timestamp)
    }

    private func decryptionErrorMessageGetDeviceIdHelper(
        serializedContent: Data)
    throws -> Int {
        let content = try DecryptionErrorMessage(bytes: serializedContent)
        return Int(content.deviceId)
    }

    private func decryptionErrorMessageGetRatchetKeyHelper(
        serializedContent: Data)
    throws -> Data? {
        let content = try DecryptionErrorMessage(bytes: serializedContent)
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

    private func publicKeyVerifyHelper(
        serializedPublicKey: Data,
        message: Data,
        signature: Data)
    throws -> Bool {
        let publicKey = try PublicKey(serializedPublicKey)
        return try publicKey.verifySignature(message: message, signature: signature)
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
        pubKey: Data)
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
        serializedPrivateKey: Data)
    throws -> Data? {
        let privateKey = try PrivateKey(serializedPrivateKey)
        let publicKey = privateKey.publicKey
        return Data(publicKey.serialize())
    }

    func preKeyRecordGetPublicKeyBody(record: Data) throws -> [UInt8] {
        let rec = try PreKeyRecord(bytes: record)
        return try rec.publicKey().serialize()
    }

    func preKeyRecordGetPrivateKeyBody(record: Data) throws -> [UInt8] {
        let rec = try PreKeyRecord(bytes: record)
        return try rec.privateKey().serialize()
    }

    func preKeyRecordGetIdBody(record: Data) throws -> UInt32 {
        let rec = try PreKeyRecord(bytes: record)
        return rec.id
    }

    func preKeyRecordNewBody(id: UInt32, serializedPublicKey: Data, serializedPrivateKey: Data) throws -> Data {
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
        return try rec.publicKey().serialize()
    }

    func signedPreKeyRecordGetPrivateKeyBody(record: Data) throws -> [UInt8] {
        let rec = try SignedPreKeyRecord(bytes: record)
        return try rec.privateKey().serialize()
    }

    func signedPreKeyRecordGetIdBody(record: Data) throws -> UInt32 {
        let rec = try SignedPreKeyRecord(bytes: record)
        return rec.id
    }

    func signedPreKeyRecordNewBody(id: UInt32, timestamp: UInt64, serializedPublicKey: Data, serializedPrivateKey: Data, signature: Data) throws -> Data {
        let privateKey = try PrivateKey(serializedPrivateKey)
        return Data(
            try SignedPreKeyRecord(
                id: id, timestamp: timestamp, privateKey: privateKey, signature: signature)
            .serialize())
    }

    func privateKeySignBody(serializedPrivateKey: Data, message: Data) throws -> Data {
        let privateKey = try PrivateKey(serializedPrivateKey)
        return Data(privateKey.generateSignature(message: message))
    }

    func privateKeyGenerateBody() -> Data {
        let keypair = IdentityKeyPair.generate()
        return Data(keypair.privateKey.serialize())
    }

    func kyberPreKeyRecordGetTimestampBody(record: Data) throws -> UInt64 {
        let rec = try KyberPreKeyRecord(bytes: record)
        return rec.timestamp
    }

    func kyberPreKeyRecordGetSignatureBody(record: Data) throws -> Data {
        let rec = try KyberPreKeyRecord(bytes: record)
        return Data(rec.signature)
    }

    func kyberPreKeyRecordGetSecretKeyBody(record: Data) throws -> Data {
        let rec = try KyberPreKeyRecord(bytes: record)
        return Data(try rec.keyPair().secretKey.serialize())
    }

    func kyberPreKeyRecordGetPublicKeyBody(record: Data) throws -> Data {
        let rec = try KyberPreKeyRecord(bytes: record)
        return Data(try rec.keyPair().publicKey.serialize())
    }

    func kyberPreKeyRecordGetIdBody(record: Data) throws -> UInt32 {
        let rec = try KyberPreKeyRecord(bytes: record)
        return rec.id
    }

    func generateKyberRecordBody(keyId: CGFloat, timestamp: CGFloat, privateKeySerialized: Data) throws -> Data {
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
        return Data(kyberRecord.serialize())
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

    private func genericServerSecretParamsGetPublicParamsHelper(genericServerSecParamsRaw: Data) throws -> [UInt8] {
        let secretParams = try GenericServerSecretParams(contents: [UInt8](genericServerSecParamsRaw))
        return try secretParams.getPublicParams().serialize()
    }
    
    /*END          bridge functions implementation              END*/
}

// Add extension for BackupLevel and BackupCredentialType conversion
extension BackupLevel {
    func toNumber() -> Int {
        switch self {
        case .free:
            return 200
        case .paid:
            return 201
        default:
            return 0
        }
    }
    
    static func fromValue(_ value: Int) -> BackupLevel {
        switch value {
        case 200:
            return .free
        case 201:
            return .paid
        default:
            return .free
        }
    }
}

extension BackupCredentialType {
    func toNumber() -> Int {
        switch self {
        case .messages:
            return 1
        case .media:
            return 2
        default:
            return 0
        }
    }
    
    static func fromValue(_ value: Int) -> BackupCredentialType {
        switch value {
        case 1:
            return .messages
        case 2:
            return .media
        default:
            return .messages
        }
    }
}
