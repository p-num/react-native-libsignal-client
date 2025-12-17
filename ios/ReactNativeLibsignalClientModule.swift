import ExpoModulesCore
import LibSignalClient
import SignalFfi
import Foundation
import CryptoSwift
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

private extension Data {
    /// Quick bridge to `[UInt8]` expected by CryptoSwift.
    var bytes: [UInt8] { Array(self) }
}

/// Generic crypto errors you may want to surface upstream.
enum CryptoError: Error {
    case invalidKeyLength
    case invalidIvLength
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

#if DEBUG
/// Error thrown when presentation getters are called but not supported.
/// This is expected in production - use credential getters instead.
private func makePresentationGetterError() -> NSError {
    NSError(
        domain: "BackupAuthCredentialPresentationError",
        code: 2,
        userInfo: [NSLocalizedDescriptionKey: "Presentation getters are not supported on iOS. Use credential getters instead."]
    )
}

/// Thread-safe LRU cache for BackupAuthCredentialPresentation metadata.
/// Swift's LibSignalClient doesn't expose getters on BackupAuthCredentialPresentation,
/// so we cache the credential's metadata when creating a presentation.
/// This cache is only active in DEBUG builds for testing purposes.
private final class BackupPresentationMetadataCache {
    struct Metadata {
        let backupId: Data
        let backupLevel: Int
        let credentialType: Int
    }
    
    private let maxSize: Int
    private var cache: [Data: Metadata] = [:]
    private var accessOrder: [Data] = []  // LRU tracking
    private let lock = NSLock()
    
    init(maxSize: Int = 32) {
        self.maxSize = maxSize
    }
    
    func set(_ metadata: Metadata, for key: Data) {
        lock.lock()
        defer { lock.unlock() }
        
        // Remove from access order if exists
        if let idx = accessOrder.firstIndex(of: key) {
            accessOrder.remove(at: idx)
        }
        
        // Add to cache and access order
        cache[key] = metadata
        accessOrder.append(key)
        
        // Evict oldest if over capacity
        while cache.count > maxSize, let oldest = accessOrder.first {
            accessOrder.removeFirst()
            cache.removeValue(forKey: oldest)
        }
    }
    
    func get(_ key: Data) -> Metadata? {
        lock.lock()
        defer { lock.unlock() }
        
        guard let metadata = cache[key] else { return nil }
        
        // Move to end of access order (most recently used)
        if let idx = accessOrder.firstIndex(of: key) {
            accessOrder.remove(at: idx)
            accessOrder.append(key)
        }
        
        return metadata
    }
}

private let backupPresentationCache = BackupPresentationMetadataCache()
#endif

public class ReactNativeLibsignalClientModule: Module {
    private var logListener: ((ReactNativeLibsignalClientLogType) -> String)?
    private var handles: [String: Any] = [:]


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
        Function("serverPublicParamsVerifySignature") { (serializedSrvPubParams: Data,
                                                        msg: Data,
                                                        sig: Data) throws -> Bool in
            do {
                return try serverPublicParamsVerifySignatureHelper(
                    serializedSrvPubParams: serializedSrvPubParams,
                    msg: msg,
                    sig: sig
                )
            } catch {
                ReactNativeLibsignalClientLogger.log(level: 6,
                    message: "serverPublicParamsVerifySignature failed",
                    additionalMessage: "\(error)")
                throw error
            }
        }

        Function("groupPublicParamsGetGroupIdentifier") { (serializedGpPubParams: Data) throws -> [UInt8] in
        do {
            return try groupPublicParamsGetGroupIdentifierHelper(serializedGpPubParams: serializedGpPubParams)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupPublicParamsGetGroupIdentifier failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsGenerateDeterministic") { (rand: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsGenerateDeterministicHelper(rawrand: [UInt8](rand))
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsGenerateDeterministic failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

                
        Function("groupSecretParamsDeriveFromMasterKey") { (serializedGpMasterKey: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsDeriveFromMasterKeyHelper(serializedGpMasterKey: serializedGpMasterKey)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsDeriveFromMasterKey failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsGetPublicParams") { (gpSecParams: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsGetPublicParamsHelper(gpSecParams: gpSecParams)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsGetPublicParams failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsGetMasterKey") { (gpSecParams: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsGetMasterKeyHelper(gpSecParams: gpSecParams)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsGetMasterKey failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("generateRandomBytes") { (len: Int) throws -> [UInt8] in
        do {
            return try generateRandomBytesHelper(len: len)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "generateRandomBytes failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("profileKeyGetCommitment") { (serializedProfileKey: Data,
                                                fixedWidthAci: Data) throws -> [UInt8] in
        do {
            return try profileKeyGetCommitmentHelper(serializedProfileKey: serializedProfileKey,
                                                    fixedWidthAci: fixedWidthAci)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "profileKeyGetCommitment failed",
                additionalMessage: "\(error)")
            throw error
        }
        }
        Function("profileKeyGetVersion") { (serializedProfileKey: Data,
                                            fixedWidthAci: Data) throws -> [UInt8] in
        do {
            return try profileKeyGetVersionHelper(serializedProfileKey: serializedProfileKey,
                                                fixedWidthAci: fixedWidthAci)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "profileKeyGetVersion failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("profileKeyDeriveAccessKey") { (serializedProfileKey: Data) throws -> [UInt8] in
        do {
            return try profileKeyDeriveAccessKeyHelper(serializedProfileKey: serializedProfileKey)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "profileKeyDeriveAccessKey failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsEncryptServiceId") { (sGroupSecretParams: Data,
                                                        fixedWidthServiceId: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsEncryptServiceIdHelper(sGroupSecretParams: sGroupSecretParams,
                                                                fixedWidthServiceId: fixedWidthServiceId)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsEncryptServiceId failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsDecryptServiceId") { (sGroupSecretParams: Data,
                                                        rawCipherText: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsDecryptServiceIdHelper(sGroupSecretParams: sGroupSecretParams,
                                                                rawCipherText: rawCipherText)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsDecryptServiceId failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsEncryptProfileKey") { (sGroupSecretParams: Data,
                                                        rawProfileKey: Data,
                                                        fixedWidthAci: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsEncryptProfileKeyHelper(sGroupSecretParams: sGroupSecretParams,
                                                                rawProfileKey: rawProfileKey,
                                                                fixedWidthAci: fixedWidthAci)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsEncryptProfileKey failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("groupSecretParamsDecryptProfileKey") { (sGroupSecretParams: Data,
                                                        rawProfileKeyCipherText: Data,
                                                        fixedWidthAci: Data) throws -> [UInt8] in
        do {
            return try groupSecretParamsDecryptProfileKeyHelper(sGroupSecretParams: sGroupSecretParams,
                                                                rawProfileKeyCipherText: rawProfileKeyCipherText,
                                                                fixedWidthAci: fixedWidthAci)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "groupSecretParamsDecryptProfileKey failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("encryptBlobWithPaddingDeterministic") { (sGroupSecretParams: Data,
                                                            randomNess: Data,
                                                            plainText: Data,
                                                            paddingLen: Int) throws -> [UInt8] in
        do {
            return try encryptBlobWithPaddingDeterministicHelper(sGroupSecretParams: sGroupSecretParams,
                                                                randomNess: randomNess,
                                                                plainText: plainText,
                                                                paddingLen: paddingLen)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "encryptBlobWithPaddingDeterministic failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("decryptBlobWithPadding") { (sGroupSecretParams: Data,
                                            blobCipherText: Data) throws -> [UInt8] in
        do {
            return try decryptBlobWithPaddingHelper(sGroupSecretParams: sGroupSecretParams,
                                                    blobCipherText: blobCipherText)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "decryptBlobWithPadding failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("expiringProfileKeyCredentialGetExpirationTime") { (sExpiringProfileKeyCredential: Data) throws -> Int64 in
        do {
            return try expiringProfileKeyCredentialGetExpirationTimeHelper(sExpiringProfileKeyCredential: sExpiringProfileKeyCredential)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "expiringProfileKeyCredentialGetExpirationTime failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("profileKeyCredentialPresentationGetUuidCiphertext") { (sProfileKeyCredentialPresentation: Data) throws -> [UInt8] in
        do {
            return try profileKeyCredentialPresentationGetUuidCiphertextHelper(sProfileKeyCredentialPresentation: sProfileKeyCredentialPresentation)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "profileKeyCredentialPresentationGetUuidCiphertext failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("profileKeyCredentialPresentationGetProfileKeyCiphertext") { (sProfileKeyCredentialPresentation: Data) throws -> [UInt8] in
        do {
            return try profileKeyCredentialPresentationGetProfileKeyCiphertextHelper(sProfileKeyCredentialPresentation: sProfileKeyCredentialPresentation)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "profileKeyCredentialPresentationGetProfileKeyCiphertext failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("profileKeyCredentialRequestContextGetRequest") { (sProfileKeyCredentialRequestContext: Data) throws -> [UInt8] in
        do {
            return try profileKeyCredentialRequestContextGetRequestHelper(sProfileKeyCredentialRequestContext: sProfileKeyCredentialRequestContext)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "profileKeyCredentialRequestContextGetRequest failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic") { (sServerPublicParams: Data,
                                                                                                randomness: Data,
                                                                                                fixedWidthAci: Data,
                                                                                                sProfileKey: Data) throws -> [UInt8] in
        do {
            return try serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministicHelper(
                sServerPublicParams: sServerPublicParams,
                randomness: randomness,
                fixedWidthAci: fixedWidthAci,
                sProfileKey: sProfileKey)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "serverPublicParamsCreateProfileKeyCredentialRequestContextDeterministic failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("serverPublicParamsReceiveExpiringProfileKeyCredential") { (sServerPublicParams: Data,
                                                                            sProfileKeyCredReqCtx: Data,
                                                                            sExpProfileKeyCredResponse: Data,
                                                                            ts: Int64) throws -> [UInt8] in
        do {
            return try serverPublicParamsReceiveExpiringProfileKeyCredentialHelper(
                sServerPublicParams: sServerPublicParams,
                sProfileKeyCredReqCtx: sProfileKeyCredReqCtx,
                sExpProfileKeyCredResponse: sExpProfileKeyCredResponse,
                ts: ts)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "serverPublicParamsReceiveExpiringProfileKeyCredential failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic") { (sServerPublicParams: Data,
                                                                                                    randomness: Data,
                                                                                                    sGpSecParams: Data,
                                                                                                    sExpProfKeyCred: Data) throws -> [UInt8] in
        do {
            return try serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministicHelper(
                sServerPublicParams: sServerPublicParams,
                randomness: randomness,
                sGpSecParams: sGpSecParams,
                sExpProfKeyCred: sExpProfKeyCred)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "serverPublicParamsCreateExpiringProfileKeyCredentialPresentationDeterministic failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("authCredentialPresentationGetUuidCiphertext") { (sAuthCredPres: Data) throws -> [UInt8] in
        do {
            return try authCredentialPresentationGetUuidCiphertextHelper(sAuthCredPres: sAuthCredPres)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "authCredentialPresentationGetUuidCiphertext failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("authCredentialPresentationGetPniCiphertext") { (sAuthCredPres: Data) throws -> [UInt8] in
        do {
            return try authCredentialPresentationGetPniCiphertextHelper(sAuthCredPres: sAuthCredPres)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "authCredentialPresentationGetPniCiphertext failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("authCredentialPresentationGetRedemptionTime") { (sAuthCredPres: Data) throws -> Int64 in
        do {
            return try authCredentialPresentationGetRedemptionTimeHelper(sAuthCredPres: sAuthCredPres)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "authCredentialPresentationGetRedemptionTime failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("serverPublicParamsReceiveAuthCredentialWithPniAsServiceId") { (sSrvPubParams: Data,
                                                                                fixedWidthAci: Data,
                                                                                fixedWidthPni: Data,
                                                                                redemptionTime: UInt64,
                                                                                authCredPniResp: Data) throws -> [UInt8] in
        do {
            return try serverPublicParamsReceiveAuthCredentialWithPniAsServiceIdHelper(
                sSrvPubParams: sSrvPubParams,
                fixedWidthAci: fixedWidthAci,
                fixedWidthPni: fixedWidthPni,
                redemptionTime: redemptionTime,
                authCredPniResp: authCredPniResp)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "serverPublicParamsReceiveAuthCredentialWithPniAsServiceId failed",
                additionalMessage: "\(error)")
            throw error
        }
        }

        Function("serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic") { (sSrvPubParams: Data,
                                                                                            randomness: Data,
                                                                                            sGpSecParams: Data,
                                                                                            authCredPni: Data) throws -> [UInt8] in
        do {
            return try serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministicHelper(
                sSrvPubParams: sSrvPubParams,
                randomness: randomness,
                sGpSecParams: sGpSecParams,
                authCredPni: authCredPni)
        } catch {
            ReactNativeLibsignalClientLogger.log(level: 6,
                message: "serverPublicParamsCreateAuthCredentialWithPniPresentationDeterministic failed",
                additionalMessage: "\(error)")
            throw error
        }
        }
        Function("identityKeyPairSerialize") {
            (serializedPublicKey: Data, serializedPrivateKey: Data) throws -> Data in
            return try identityKeyPairSerializeHelper(serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey)
        }
        Function("identityKeyPairDeserialize") {
            (serializedIdentityKeyPair: Data) throws -> [[UInt8]] in
            return try identityKeyPairDeserializeHelper(serializedIdentityKeyPair: serializedIdentityKeyPair)
        }
        Function("identityKeyPairSignAlternateIdentity") {
            (serializedPublicKey: Data, serializedPrivateKey: Data, serializedAlternateIdentityKey: Data) throws -> [UInt8] in
            return try identityKeyPairSignAlternateIdentityHelper(serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey, serializedAlternateIdentityKey: serializedAlternateIdentityKey)
        }
        Function("sessionCipherEncryptMessage") {
            (base64Message: String, address: String, sessionStoreState: [String: String], identityKeyState: [Any], now: Int64) throws -> [Any] in
            return try sessionCipherEncryptMessageHelper(
                base64Message: base64Message,
                address: address,
                sessionStoreState: sessionStoreState,
                identityKeyState: identityKeyState,
                now: now)
        }
        Function("preKeySignalMessageGetRegistrationId") {
            (serializedMessage: Data) throws -> UInt32 in
            return try preKeySignalMessageGetRegistrationIdHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetSignedPreKeyId") {
            (serializedMessage: Data) throws -> UInt32 in
            return try preKeySignalMessageGetSignedPreKeyIdHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetVersion") {
            (serializedMessage: Data) throws -> UInt32 in
            return try preKeySignalMessageGetVersionHelper(serializedMessage: serializedMessage)
        }
        Function("preKeySignalMessageGetPreKeyId") {
            (serializedMessage: Data) throws -> UInt32? in
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
            throws -> Data in
            return try decryptionErrorMessageForOriginalMessageHelper(
                originalBytes: originalBytes,
                messageType: messageType,
                timestamp: timestamp,
                originalSenderDeviceId: originalSenderDeviceId)
        }
        Function("decryptionErrorMessageExtractFromSerializedContent") {
            (serializedContent: Data) throws -> Data in
            let content = try decryptionErrorMessageExtractFromSerializedContentHelper(serializedContent: serializedContent)
            return Data(content.serialize())
        }
        Function("decryptionErrorMessageGetTimestamp") {
            (serializedContent: Data) throws -> Int64 in
            return try decryptionErrorMessageGetTimestampHelper(serializedContent: serializedContent)
        }
        Function("decryptionErrorMessageGetDeviceId") {
            (serializedContent: Data) throws -> Int in
            return try decryptionErrorMessageGetDeviceIdHelper(serializedContent: serializedContent)
        }
        Function("decryptionErrorMessageGetRatchetKey") {
            (serializedContent: Data) throws -> Data? in
            return try decryptionErrorMessageGetRatchetKeyHelper(serializedContent: serializedContent)
        }
        Function("plaintextContentFromDecryptionErrorMessage") { (message: Data) throws -> Data in
        let plaintextContent = try plaintextContentFromDecryptionErrorMessageHelper(message: message)
        return Data(plaintextContent.serialize())
        }

        Function("plaintextContentGetBody") { (message: Data) throws -> Data in
        try plaintextContentGetBodyHelper(message: message)
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
        Function("identityKeyVerifyAlternateIdentity") {
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
            (outputLength: Int, inputKeyMaterial: Data, info: Data, salt: Data?) throws -> [UInt8] in
            return try hkdfDeriveSecretsHelper(
                outputLength: outputLength,
                inputKeyMaterial: inputKeyMaterial,
                info: info,
                salt: salt ?? Data())
        }
        Function("serviceIdServiceIdString") {
            (fixedWidthServiceId: Data) throws -> String in
            return try serviceIdServiceIdStringHelper(fixedWidthServiceId: [UInt8](fixedWidthServiceId))
        }
        Function("serviceIdServiceIdLog") {
            (fixedWidthServiceId: Data) throws -> String in
            return try serviceIdServiceIdLogHelper(fixedWidthServiceId: [UInt8](fixedWidthServiceId))
        }
        Function("serviceIdParseFromServiceIdString") {
            (serviceIdString: String) throws -> Data in
            return Data(try serviceIdParseFromServiceIdStringHelper(serviceIdString: serviceIdString))
        }
        Function("serviceIdServiceIdBinary") {
            (fixedWidthServiceId: Data) throws -> Data in
            return Data(try serviceIdServiceIdBinaryHelper(fixedWidthServiceId: fixedWidthServiceId))
        }
        Function("serviceIdParseFromServiceIdBinary") {
            (serviceIdBinary: Data) throws -> Data in
            return Data(try serviceIdParseFromServiceIdBinaryHelper(serviceIdBinary: serviceIdBinary))
        }
        Function("privateKeyGetPublicKey") {
            (serializedPrivateKey: Data) throws -> Data? in
            return try privateKeyGetPublicKeyHelper(serializedPrivateKey: serializedPrivateKey)
        }
        Function("generateKyberRecord") {
            (keyId: CGFloat, timestamp: CGFloat, privateKeySerialized: Data) throws -> Data in
            return try generateKyberRecordBody(keyId: keyId, timestamp: timestamp, privateKeySerialized: privateKeySerialized)
        }
        Function("kyberPreKeyRecordGetId") {
            (record: Data) throws -> UInt32 in
            return try kyberPreKeyRecordGetIdBody(record: record)
        }
        Function("kyberPreKeyRecordGetPublicKey") {
            (record: Data) throws -> Data in
            return try kyberPreKeyRecordGetPublicKeyBody(record: record)
        }
        Function("kyberPreKeyRecordGetSecretKey") {
            (record: Data) throws -> Data in
            return try kyberPreKeyRecordGetSecretKeyBody(record: record)
        }
        Function("kyberPreKeyRecordGetSignature") {
            (record: Data) throws -> Data in
            return try kyberPreKeyRecordGetSignatureBody(record: record)
        }
        Function("kyberPreKeyRecordGetTimestamp") {
            (record: Data) throws -> UInt64 in
            return try kyberPreKeyRecordGetTimestampBody(record: record)
        }
        Function("privateKeyGenerate") {
            () throws -> Data in
            return privateKeyGenerateBody()
        }
        Function("privateKeySign") {
            (serializedPrivateKey: Data, message: Data ) throws -> Data in
            return try privateKeySignBody(serializedPrivateKey: serializedPrivateKey, message: message)
        }
        Function ("privateKeyAgree") {
            (serializedPrivateKey: Data, serializedPublicKey: Data) throws -> [UInt8] in
            let publicKey = try PublicKey([UInt8](serializedPublicKey))
            let privateKey = try PrivateKey([UInt8](serializedPrivateKey))
            return privateKey.keyAgreement(with: publicKey)
        }
        Function("signedPreKeyRecordNew") {
            (id: UInt32, timestamp: UInt64, serializedPublicKey: Data, serializedPrivateKey: Data, signature: Data) throws -> Data in
            return try signedPreKeyRecordNewBody(id: id, timestamp: timestamp, serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey, signature: signature)
        }
        Function("signedPreKeyRecordGetId") {
            (record: Data) throws -> UInt32 in
            return try signedPreKeyRecordGetIdBody(record: record)
        }
        Function("signedPreKeyRecordGetPrivateKey") {
            (record: Data) throws -> [UInt8] in
            return try signedPreKeyRecordGetPrivateKeyBody(record: record)
        }
        Function("signedPreKeyRecordGetPublicKey") {
            (record: Data) throws -> [UInt8] in
            return try signedPreKeyRecordGetPublicKeyBody(record: record)
        }
        Function("signedPreKeyRecordGetSignature") {
            (record: Data) throws -> Data in
            return try signedPreKeyRecordGetSignatureBody(record: record)
        }
        Function("signedPreKeyRecordGetTimestamp") {
            (record: Data) throws -> UInt64 in
            return try signedPreKeyRecordGetTimestampBody(record: record)
        }
        Function("preKeyRecordNew") {
            (id: UInt32, serializedPublicKey: Data, serializedPrivateKey: Data) throws -> Data in
            return try preKeyRecordNewBody(id: id, serializedPublicKey: serializedPublicKey, serializedPrivateKey: serializedPrivateKey)
        }
        Function("preKeyRecordGetId") {
            (record: Data) throws -> UInt32 in
            return try preKeyRecordGetIdBody(record: record)
        }
        Function("preKeyRecordGetPrivateKey") {
            (record: Data) throws -> [UInt8] in
            return try preKeyRecordGetPrivateKeyBody(record: record)
        }
        Function("generateRegistrationId") {
            () throws -> UInt32 in
            return UInt32.random(in: 1...0x3fff)
        }
        Function("preKeyRecordGetPublicKey") {
            (record: Data) throws -> [UInt8] in
            return try preKeyRecordGetPublicKeyBody(record: record)
        }
        Function("serverSecretParamsGenerateDeterministic") { (rndm: Data) throws -> [UInt8] in
        try serverSecretParamsGenerateDeterministicHelper(randomNess: rndm)
        }

        Function("serverSecretParamsGetPublicParams") { (sSrvSecParams: Data) throws -> [UInt8] in
        try serverSecretParamsGetPublicParamsHelper(sSrvSecParams: sSrvSecParams)
        }

        Function("serverSecretParamsSignDeterministic") { (sSrvSecParams: Data, rndm: Data, msg: Data) throws -> [UInt8] in
        try serverSecretParamsSignDeterministicHelper(sSrvSecParams: sSrvSecParams, rndm: rndm, msg: msg)
        }

        Function("serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministic") {
        (sSrvSecParams: Data, rndm: Data, sAci: Data, sPni: Data, redemptionTime: Double) throws -> [UInt8] in
        try serverSecretParamsIssueAuthCredentialWithPniAsServiceIdDeterministicHelper(
            sSrvSecParams: sSrvSecParams,
            rndm: rndm,
            sAci: sAci,
            sPni: sPni,
            redemptionTime: redemptionTime)
        }

        Function("serverSecretParamsIssueAuthCredentialWithPniZkcDeterministic") {
        (sSrvSecParams: Data, rndm: Data, sAci: Data, sPni: Data, redemptionTime: Double) throws -> [UInt8] in
        try serverSecretParamsIssueAuthCredentialWithPniZkcDeterministicHelper(
            sSrvSecParams: sSrvSecParams,
            rndm: rndm,
            sAci: sAci,
            sPni: sPni,
            redemptionTime: redemptionTime)
        }

        Function("serverSecretParamsVerifyAuthCredentialPresentation") {
        (sSrvSecParams: Data, sGpPublicParams: Data, sAuthCredPresent: Data, instant: Double) throws in
        try serverSecretParamsVerifyAuthCredentialPresentationHelper(
            sSrvSecParams: sSrvSecParams,
            sGpPublicParams: sGpPublicParams,
            sAuthCredPresent: sAuthCredPresent,
            instant: instant)
        }

        Function("groupSecretParamsEncryptCiphertext") { (sGpSecParams: Data, sServiceId: Data) throws -> [UInt8] in
        try groupSecretParamsEncryptCiphertextHelper(sGpSecParams: sGpSecParams, sServiceId: sServiceId)
        }

        Function("serverSecretParamsIssueExpiringProfileKeyCredentialDeterministic") {
        (sSrvSecParams: Data, rand: Data, sProfCredRequest: Data, sAci: Data,
        sProfileKeyCommitment: Data, expiration: UInt64) throws -> [UInt8] in
        try serverSecretParamsIssueExpiringProfileKeyCredentialDeterministicHelper(
            sSrvSecParams: sSrvSecParams,
            rand: rand,
            sProfCredRequest: sProfCredRequest,
            sAci: sAci,
            sProfileKeyCommitment: sProfileKeyCommitment,
            expiration: expiration)
        }

        Function("serverSecretParamsVerifyProfileKeyCredentialPresentation") {
        (sSrvSecParams: Data, sGpPublicParams: Data, sProfileKeyCredentialPresentation: Data, instant: Double) throws in
        try serverSecretParamsVerifyProfileKeyCredentialPresentationHelper(
            sSrvSecParams: sSrvSecParams,
            sGpPublicParams: sGpPublicParams,
            sProfileKeyCredentialPresentation: sProfileKeyCredentialPresentation,
            instant: instant)
        }

        Function("groupSecretParamsEncryptBlobWithPaddingDeterministic") {
        (sGroupSecretParams: Data, randomNess: Data, plainText: Data, paddingLen: Int) throws -> [UInt8] in
        try groupSecretParamsEncryptBlobWithPaddingDeterministicHelper(
            sGroupSecretParams: sGroupSecretParams,
            randomNess: [UInt8](randomNess),
            plainText: plainText,
            paddingLen: paddingLen)
        }

        Function("groupSecretParamsDecryptBlobWithPadding") {
        (sGroupSecretParams: Data, blobCipherText: Data) throws -> [UInt8] in
        try groupSecretParamsDecryptBlobWithPaddingHelper(
            sGroupSecretParams: sGroupSecretParams,
            blobCipherText: blobCipherText)
        }
        Function("Aes256GcmEncrypt") { (key: Data, iv: Data, plainText: Data, aad: Data?) throws -> Data in
            guard key.count == 32 else { throw CryptoError.invalidKeyLength }
            guard (12...16).contains(iv.count) else { throw CryptoError.invalidIvLength }

            let gcm = GCM(
                iv: iv.bytes,
                additionalAuthenticatedData: aad?.bytes ?? [],
                mode: .combined            // ciphertext+tag in one buffer :contentReference[oaicite:0]{index=0}
            )
            let aes  = try AES(key: key.bytes, blockMode: gcm, padding: .noPadding)
            let combined = try aes.encrypt(plainText.bytes)   // Data(ciphertext || tag)
            return Data(combined)
        }
        Function("Aes256CtrEncrypt") { (key: Data, iv: Data, plainText: Data) throws -> Data in
            let aes = try CryptoSwift.AES(key: [UInt8](key), blockMode: CryptoSwift.CTR(iv: [UInt8](iv)),padding: .noPadding)
            let encryptedBytes = try aes.encrypt([UInt8](plainText))
            return Data(encryptedBytes)
        }
        Function("Aes256CtrDecrypt") { (key: Data, iv: Data, ciphertext: Data) throws -> Data in
            let aes = try CryptoSwift.AES(key: [UInt8](key), blockMode: CryptoSwift.CTR(iv: [UInt8](iv)), padding: .noPadding)
            let decryptedBytes = try aes.decrypt([UInt8](ciphertext))
            return Data(decryptedBytes)
        }
        Function("Aes256GcmDecrypt") { (key: Data, iv: Data, ciphertext: Data, aad: Data?) throws -> Data in
            let gcm = GCM(
                iv: iv.bytes,
                additionalAuthenticatedData: aad?.bytes ?? [],
                mode: .combined            // CryptoSwift separates tag internally :contentReference[oaicite:1]{index=1}
            )
            let aes = try AES(key: key.bytes, blockMode: gcm, padding: .noPadding)
            let decrypted = try aes.decrypt(ciphertext.bytes)
            return Data(decrypted)
        }
        Function("Aes256CbcEncrypt") { (key: Data, iv: Data, plaintext: Data) throws -> Data in
            let aes = try AES(
                key: key.bytes,
                blockMode: CBC(iv: iv.bytes),
                padding: .pkcs7            // PKCS#7 == PKCS#5 for 16-byte blocks :contentReference[oaicite:2]{index=2}
            )
            return Data(try aes.encrypt(plaintext.bytes))
        }
        Function("Aes256CbcDecrypt") { (key: Data, iv: Data, ciphertext: Data) throws -> Data in
            let aes = try AES(
                key: key.bytes,
                blockMode: CBC(iv: iv.bytes),
                padding: .pkcs7
            )
            return Data(try aes.decrypt(ciphertext.bytes))
        }
        Function("groupSendFullTokenGetExpiration") { (sgpfulltoken: Data) throws -> UInt64 in
            let gpFullToken = try GroupSendFullToken(contents: [UInt8](sgpfulltoken))
            return UInt64(gpFullToken.expiration.timeIntervalSince1970)
        }

        Function("groupSendFullTokenVerify") { (sgpfulltoken: Data, fixedWidthIds: Data, time: UInt64, gpsenddrivedkp: Data) throws in
            let gpFullToken = try GroupSendFullToken(contents: [UInt8](sgpfulltoken))
            let serviceIds = try parseFixedWidthServiceIds(raw: [UInt8](fixedWidthIds))
            let groupSendKeyPair = try GroupSendDerivedKeyPair(contents: [UInt8](gpsenddrivedkp))
            try gpFullToken.verify(userIds: serviceIds, now: Date(timeIntervalSince1970: TimeInterval(time)), keyPair: groupSendKeyPair)
        }

        Function("groupSendTokenToFullToken") { (sgpsendtoken: Data, expTime: UInt64) throws -> Data in
            let groupSendToken = try GroupSendEndorsement.Token(contents: [UInt8](sgpsendtoken))
            return Data(groupSendToken.toFullToken(expiration: Date(timeIntervalSince1970: TimeInterval(expTime))).serialize())
        }

        Function("groupSendDerivedKeyPairForExpiration") { (expTime: UInt64, svSecParams: Data) throws -> Data in
            let serverSecParams = try ServerSecretParams(contents: [UInt8](svSecParams))
            return Data(GroupSendDerivedKeyPair.forExpiration(Date(timeIntervalSince1970: TimeInterval(expTime)), params: serverSecParams).serialize())
        }

        Function("groupSendEndorsementCombine") { (sendorsements: [String]) throws -> Data in
            
            let endorsements = try sendorsements.map { base64String in
                        guard let decodedData = Data(base64Encoded: base64String) else {
                            throw NSError(domain: "DecodingError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 string"])
                        }
                        return try GroupSendEndorsement(contents: [UInt8](decodedData))
            }
        
            return Data(GroupSendEndorsement.combine(endorsements).serialize())
        }

        Function("groupSendEndorsementRemove") { (sgpsendendorsement: Data, toRemove: Data) throws -> Data in
            let endorsement = try GroupSendEndorsement(contents: [UInt8](sgpsendendorsement))
            let toRemoveEndorsement = try GroupSendEndorsement(contents: [UInt8](toRemove))
            return Data(endorsement.byRemoving(toRemoveEndorsement).serialize())
        }

        Function("groupSendEndorsementToToken") { (sgpsendendorsement: Data, sGpSecParams: Data) throws -> Data in
            let endorsement = try GroupSendEndorsement(contents: [UInt8](sgpsendendorsement))
            let params = try GroupSecretParams(contents: [UInt8](sGpSecParams))
            return Data(endorsement.toToken(groupParams: params).serialize())
        }

        Function("groupSendEndorsementsResponseIssueDeterministic") { (uuidCipherTexts: Data, gpsenddrivedkp: Data, rndm: Data) throws -> Data in
            let serviceIds = try parseUuidCipherTexts(raw: [UInt8](uuidCipherTexts))
            let keyPair = try GroupSendDerivedKeyPair(contents: [UInt8](gpsenddrivedkp))
            return Data(GroupSendEndorsementsResponse.issue(groupMembers: serviceIds, keyPair: keyPair).serialize())
        }

        Function("groupSendEndorsementsResponseGetExpiration") { (gpSendEndResponse: Data) throws -> UInt64 in
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

            let combined = Data(GroupSendEndorsement.combine(
                endorsements[..<localUserIndex] + endorsements[(localUserIndex + 1)...]
            ).serialize())
            
            return endorsements.map { Data($0.serialize()) } + [combined]
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
            
            let combined = Data(GroupSendEndorsement.combine(
                Array(endorsements[..<localUserIndex]) + Array(endorsements[(localUserIndex + 1)...])
            ).serialize())
            return endorsements.map { Data($0.serialize()) } + [combined]
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
                groupId: Data?) throws -> Data in
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



        Function("HmacSHA256") { (key: Data, data: Data) throws -> Data in
            let hmac = try HMAC(key: [UInt8](key), variant: HMAC.Variant.sha2(.sha256)).authenticate([UInt8](data))
            return Data(hmac)        
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
            
            return Data(content.serialize())
        }


        Function("unidentifiedSenderMessageContentGetContents") { (serializedContent: Data) throws -> [UInt8] in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.contents
        }
        Function("unidentifiedSenderMessageContentGetMsgType") { (serializedContent: Data) throws -> Int in
            let content = try! UnidentifiedSenderMessageContent(bytes:serializedContent)
            return Int(content.messageType.rawValue)
        }
        Function("unidentifiedSenderMessageContentGetSenderCert") { (serializedContent: Data) throws -> [UInt8] in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.senderCertificate.serialize()
        }
        Function("unidentifiedSenderMessageContentGetContentHint") { (serializedContent: Data) throws -> UInt32 in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.contentHint.rawValue
        }
        Function("unidentifiedSenderMessageContentGetGroupId") { (serializedContent: Data) throws -> [UInt8] in
            let content = try UnidentifiedSenderMessageContent(bytes:serializedContent)
            return content.groupId ?? [UInt8]()
        }

        Function("sealedSenderMultiRecipientEncrypt") { 
            (ownerIdentityData: [Any], srecipients: [String],sessionStoreState: [String: String], 
            excludedRecipients: Data, uidentcontent: Data, identityStoreState: [[String]]) throws -> Data in
            


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
            let sigStore = InMemorySignalProtocolStore(identity: ownerIdentityKey, registrationId: ownerRegistrationId)

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
                let _ = try sigStore.saveIdentity(identityKey, for: protocolAddress, context: NullContext())
            }

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

            try processSenderKeyDistributionMessage(
                message,
                from: protoAddress,
                store: senderKeyStore,
                context: NullContext())
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
            return Data(certificate.publicKey.serialize())
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
            return Data(certificate.serverCertificate.serialize())
        }

        
        Function("senderCertificateValidate") { (trustRoot: Data, serializedCertificate: Data, timestamp: UInt64) throws -> Bool in
            let certificate = try SenderCertificate([UInt8](serializedCertificate))
            let publicKey = try PublicKey([UInt8](trustRoot))
            return try certificate.validate(trustRoot: publicKey, time: timestamp)
        }


        Function("serverCertificateGetKey") { (serializedCertificate: Data) throws -> Data in
            let certificate = try ServerCertificate([UInt8](serializedCertificate))
            return Data(certificate.publicKey.serialize())
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
        Function("senderKeyMessageVerifySignature") { (serializedMessage: Data, serializedSenderIdentityKey: Data) throws -> Bool in
            do {
                let message = try SenderKeyMessage(bytes: [UInt8](serializedMessage))
                let senderIdentityKey = try PublicKey([UInt8](serializedSenderIdentityKey))
                return try message.verifySignature(against: senderIdentityKey)
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
            return Data(BackupAuthCredentialRequestContext.create(backupKey: [UInt8](backupKeyr), aci: aci).serialize())
        }

        Function("backupAuthCredentialRequestContextGetRequest") { (backupReqCtxRaw: Data) -> Data in
            let requestContext = try BackupAuthCredentialRequestContext(contents: [UInt8](backupReqCtxRaw))
            return Data(requestContext.getRequest().serialize())
        }

        Function("backupAuthCredentialRequestContextReceiveResponse") { (backupReqCtxRaw: Data, backupResRaw: Data, redemptionTime: UInt64, genericServerPubParamsRaw: Data) -> Data in
            let requestContext = try BackupAuthCredentialRequestContext(contents: [UInt8](backupReqCtxRaw))
            let response = try BackupAuthCredentialResponse(contents: [UInt8](backupResRaw))
            let genericServerParams = try GenericServerPublicParams(contents: [UInt8](genericServerPubParamsRaw))
            let redemptionDate = Date(timeIntervalSince1970: TimeInterval(redemptionTime))
            
            return Data(try requestContext.receive(
                response,
                timestamp: redemptionDate,
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
            let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
            
            return Data(request.issueCredential(
                timestamp: date,
                backupLevel: BackupLevel.fromValue(backuplevel),
                type: BackupCredentialType.fromValue(credentialType),
                params: genericServerParams,
                randomness: Randomness(randomnessBytes)
            ).serialize())
        }

        Function("backupAuthCredentialPresentationVerify") { (bckCredPresRaw: Data, timestamp: UInt64, genericServerSecParamsRaw: Data) in
            let presentation = try BackupAuthCredentialPresentation(contents: [UInt8](bckCredPresRaw))
            let genericServerParams = try GenericServerSecretParams(contents: [UInt8](genericServerSecParamsRaw))
            let redemptionDate = Date(timeIntervalSince1970: TimeInterval(timestamp))
            
            try presentation.verify(now: redemptionDate, serverParams: genericServerParams)
        }

        Function("backupAuthCredentialPresentationGetBackupId") { (bckCredPresRaw: Data) -> Data in
            #if DEBUG
            // Look up from cache (populated when presentation was created)
            if let cached = backupPresentationCache.get(bckCredPresRaw) {
                return cached.backupId
            }
            // In DEBUG, cache miss means presentation wasn't created in this session
            assertionFailure("Presentation not found in cache. Was it created in this session?")
            throw makePresentationGetterError()
            #else
            throw NSError(
                domain: "BackupAuthCredentialPresentationError",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Presentation getters are not supported on iOS. Use credential getters instead."]
            )
            #endif
        }

        Function("backupAuthCredentialPresentationGetBackupLevel") { (bckCredPresRaw: Data) -> Int in
            #if DEBUG
            // Look up from cache (populated when presentation was created)
            if let cached = backupPresentationCache.get(bckCredPresRaw) {
                return cached.backupLevel
            }
            // In DEBUG, cache miss means presentation wasn't created in this session
            assertionFailure("Presentation not found in cache. Was it created in this session?")
            throw makePresentationGetterError()
            #else
            throw NSError(
                domain: "BackupAuthCredentialPresentationError",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Presentation getters are not supported on iOS. Use credential getters instead."]
            )
            #endif
        }

        Function("backupAuthCredentialPresentationGetType") { (bckCredPresRaw: Data) -> Int in
            #if DEBUG
            // Look up from cache (populated when presentation was created)
            if let cached = backupPresentationCache.get(bckCredPresRaw) {
                return cached.credentialType
            }
            // In DEBUG, cache miss means presentation wasn't created in this session
            assertionFailure("Presentation not found in cache. Was it created in this session?")
            throw makePresentationGetterError()
            #else
            throw NSError(
                domain: "BackupAuthCredentialPresentationError",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Presentation getters are not supported on iOS. Use credential getters instead."]
            )
            #endif
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
            
            let presentationBytes = Data(credential.present(
                serverParams: genericServerParams,
                randomness: Randomness(randomnessBytes)
            ).serialize())
            
            #if DEBUG
            // Cache the credential's metadata so presentation getters can retrieve it
            // (Swift LibSignalClient doesn't expose getters on BackupAuthCredentialPresentation)
            // Only cached in DEBUG for testing - production should use credential getters directly
            backupPresentationCache.set(
                BackupPresentationMetadataCache.Metadata(
                    backupId: Data(credential.backupID),
                    backupLevel: credential.backupLevel.toNumber(),
                    credentialType: credential.type.toNumber()
                ),
                for: presentationBytes
            )
            #endif
            
            return presentationBytes
        }

        Function("backupAuthCredentialGetBackupId") { (bckAuthCredRaw: Data) -> Data in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            return Data(credential.backupID)
        }

        Function("backupAuthCredentialGetBackupLevel") { (bckAuthCredRaw: Data) -> Int in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            return credential.backupLevel.toNumber()
        }

        Function("backupAuthCredentialGetType") { (bckAuthCredRaw: Data) -> Int in
            let credential = try BackupAuthCredential(contents: [UInt8](bckAuthCredRaw))
            return credential.type.toNumber()
        }

        Function("genericServerSecretParamsGenerateDeterministic") { (randomness: Data) -> Data in
            guard randomness.count == 32 else {
                throw NSError(domain: "Invalid input size", code: 1, userInfo: nil)
            }
            let randomnessBytes = randomness.withUnsafeBytes { pointer in
                pointer.load(as: SignalRandomnessBytes.self)
            }
            return Data(GenericServerSecretParams.generate(randomness: Randomness(randomnessBytes)).serialize())
        }



        // BackupKey functions
        Function("backupKeyDeriveBackupId") { (bckKeyRaw: Data, serviceIdBinary: Data) -> Data in
            let backupKey = try BackupKey(contents: [UInt8](bckKeyRaw))
            let serviceId = try parseAciFromFixedWidth([UInt8](serviceIdBinary))
            return Data(backupKey.deriveBackupId(aci: serviceId))
        }

        Function("backupKeyDeriveEcKey") { (bckKeyRaw: Data, serviceIdBinary: Data) -> Data in
            let backupKey = try BackupKey(contents: [UInt8](bckKeyRaw))
            let serviceId = try parseAciFromFixedWidth([UInt8](serviceIdBinary))
            return Data(backupKey.deriveEcKey(aci: serviceId).serialize())
        }

        Function("backupKeyDeriveLocalBackupMetadataKey") { (bckKeyRaw: Data) -> Data in
            let backupKey = try BackupKey(contents: [UInt8](bckKeyRaw))
            return Data(backupKey.deriveLocalBackupMetadataKey())
        }

        Function("backupKeyDeriveMediaId") { (bckKeyRaw: Data, mediaName: String) -> Data in
            let backupKey = try BackupKey(contents: [UInt8](bckKeyRaw))
            return Data(try backupKey.deriveMediaId(mediaName))
        }

        Function("backupKeyDeriveMediaEncryptionKey") { (bckKeyRaw: Data, mediaId: Data) -> Data in
            let backupKey = try BackupKey(contents: [UInt8](bckKeyRaw))
            return Data(try backupKey.deriveMediaEncryptionKey([UInt8](mediaId)))
        }

        Function("backupKeyDeriveThumbnailTransitEncryptionKey") { (bckKeyRaw: Data, mediaId: Data) -> Data in
            let backupKey = try BackupKey(contents: [UInt8](bckKeyRaw))
            return Data(try backupKey.deriveThumbnailTransitEncryptionKey([UInt8](mediaId)))
        }

        // AccountEntropyPool functions
        Function("accountEntropyPoolGenerate") { () -> String in
            return AccountEntropyPool.generate()
        }

        Function("accountEntropyPoolIsValid") { (entPool: String) -> Bool in
            return AccountEntropyPool.isValid(entPool)
        }

        Function("accountEntropyPoolDeriveSvrKey") { (entPool: String) -> Data in
            return Data(try AccountEntropyPool.deriveSvrKey(entPool))
        }

        Function("accountEntropyPoolDeriveBackupKey") { (entPool: String) -> Data in
            return Data(try AccountEntropyPool.deriveBackupKey(entPool).serialize())
        }

        // MessageBackupKey functions
        Function("messageBackupKeyFromAccountEntropyPool") { (entPool: String, aciBinary: Data) -> Data in
            let aci = try parseAciFromFixedWidth([UInt8](aciBinary))
            
            let backupKey = try AccountEntropyPool.deriveBackupKey(entPool)
            let backupId = backupKey.deriveBackupId(aci: aci)
            
            return Data(backupKey.serialize() + backupId)
        }

        Function("messageBackupKeyFromBackupKeyAndBackupId") { (bckKeyRaw: Data, bckIdRaw: Data) -> Data in
            return bckKeyRaw + bckIdRaw
        }

        Function("messageBackupKeyGetHmacKey") { (msgBckKey: Data) -> Data in
            let messageBackupKey = try deserializeMessageBackupKey([UInt8](msgBckKey))
            return Data(messageBackupKey.hmacKey)
        }

        Function("messageBackupKeyGetAesKey") { (msgBckKey: Data) -> Data in
            let messageBackupKey = try deserializeMessageBackupKey([UInt8](msgBckKey))
            return Data(messageBackupKey.aesKey)
        }

        // MessageBackup validation functions
        Function("messageBackupValidatorValidate") { (msgBckKey: Data, path: String, len: Int64, purpose: Int) -> [String] in
            let messageBackupKey = try deserializeMessageBackupKey([UInt8](msgBckKey))
            let purposeEnum = try purposeFromInt(purpose)
            let fileURL = URL(fileURLWithPath: path.replacingOccurrences(of: "file:/", with: ""))
            
            let result = try validateMessageBackup(
                key: messageBackupKey,
                purpose: purposeEnum,
                length: UInt64(len),
                makeStream: { try FileHandle(forReadingFrom: fileURL) }
            )
            
            return result.fields
        }

        Function("onlineBackupValidatorNew") { (bckInfo: Data, purpose: Int) -> String in
            let purposeEnum = try purposeFromInt(purpose)
            let validator = try OnlineBackupValidator(backupInfo: [UInt8](bckInfo), purpose: purposeEnum)
            
            let shortId = generateShortId()
            self.handles[shortId] = validator
            return shortId
        }

        Function("onlineBackupValidatorAddFrame") { (handle: String, frame: Data) in
            guard let validator = self.handles[handle] as? OnlineBackupValidator else {
                throw NSError(domain: "Invalid handle", code: 1, userInfo: nil)
            }
            try validator.addFrame([UInt8](frame))
        }

        Function("onlineBackupValidatorFinalize") { (handle: String) in
            guard let validator = self.handles[handle] as? OnlineBackupValidator else {
                throw NSError(domain: "Invalid handle", code: 1, userInfo: nil)
            }
            try validator.finalize()
            self.handles.removeValue(forKey: handle)
        }

        // ComparableBackup is only available in simulator builds (not device/archive builds)
        // See: https://github.com/signalapp/libsignal ComparableBackup.swift
        #if !os(iOS) || targetEnvironment(simulator)
        Function("comparableBackupReadUnencrypted") { (filePath: String, len: Int64, purpose: Int) -> String in
            let purposeEnum = try purposeFromInt(purpose)
            let fileURL = URL(fileURLWithPath: filePath.replacingOccurrences(of: "file:/", with: ""))
            
            let comparableBackup = try ComparableBackup(
                purpose: purposeEnum,
                length: UInt64(len),
                stream: try FileHandle(forReadingFrom: fileURL)
            )
            
            let shortId = generateShortId()
            self.handles[shortId] = comparableBackup
            return shortId
        }

        Function("comparableBackupGetInfo") { (handle: String) -> [Any] in
            guard let comparableBackup = self.handles[handle] as? ComparableBackup else {
                throw NSError(domain: "Invalid handle", code: 1, userInfo: nil)
            }
            self.handles.removeValue(forKey: handle)
            
            return [comparableBackup.comparableString(), comparableBackup.unknownFields.fields]
        }
        #else
        // Provide stub functions that throw on device builds
        Function("comparableBackupReadUnencrypted") { (_: String, _: Int64, _: Int) -> String in
            throw NSError(domain: "ComparableBackup", code: 1, userInfo: [NSLocalizedDescriptionKey: "ComparableBackup is only available in the simulator, not device builds."])
        }

        Function("comparableBackupGetInfo") { (_: String) -> [Any] in
            throw NSError(domain: "ComparableBackup", code: 1, userInfo: [NSLocalizedDescriptionKey: "ComparableBackup is only available in the simulator, not device builds."])
        }
        #endif

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
        
        let senderKeyDistributionMessage = try SenderKeyDistributionMessage(from: senderProtocolAddress, distributionId: distributionId, store: senderKeyStore, context: NullContext())

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
        let sender_addr = try SealedSenderAddress(
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

        let certificate = try ServerCertificate(keyId: keyId,publicKey: serverKeyPub, trustRoot: trustRoot )

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
        let _ = try store.saveIdentity(identityKey, for: protoAddress, context: NullContext())
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
    private func identityKeyPairDeserializeHelper(serializedIdentityKeyPair: Data) throws -> [[UInt8]] {
        let identityKeyPair = try IdentityKeyPair(bytes: serializedIdentityKeyPair)
        return [identityKeyPair.privateKey.serialize(), identityKeyPair.publicKey.serialize()]
    }
    private func identityKeyPairSignAlternateIdentityHelper(serializedPublicKey: Data, serializedPrivateKey: Data, serializedAlternateIdentityKey: Data) throws -> [UInt8] {
        let publicKey = try PublicKey(serializedPublicKey)
        let privateKey = try PrivateKey(serializedPrivateKey)
        let identityKeyPair = IdentityKeyPair(publicKey: publicKey, privateKey: privateKey)
        let alternateIdentityKey = try IdentityKey(bytes: serializedAlternateIdentityKey)
        return identityKeyPair.signAlternateIdentity(alternateIdentityKey)
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
        let cipher = try signalEncrypt(
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
        let errorMessage = try DecryptionErrorMessage(bytes: message)
        return PlaintextContent(errorMessage)
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
        return try LibSignalClient.hkdf(
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
        return secretParams.getPublicParams().serialize()
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

func deserializeMessageBackupKey(_ ser: [UInt8]) throws -> MessageBackupKey {
    guard ser.count == 48 else {
        throw NSError(domain: "Invalid message backup key", code: 1, userInfo: nil)
    }
    
    let backupKeyBytes = Array(ser[0..<32])
    let backupIdBytes = Array(ser[32..<48])
    
    let backupKey = try BackupKey(contents: backupKeyBytes)
    return try MessageBackupKey(backupKey: backupKey, backupId: backupIdBytes)
}

func purposeFromInt(_ purpose: Int) throws -> MessageBackupPurpose {
    switch purpose {
    case 0:
        return .deviceTransfer
    case 1:
        return .remoteBackup
    default:
        throw NSError(domain: "Invalid purpose", code: 1, userInfo: nil)
    }
}

func generateShortId(length: Int = 8) -> String {
    let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return String((0..<length).map { _ in letters.randomElement()! })
}

func parseAciFromFixedWidth(_ bytes: [UInt8]) throws -> Aci {
    guard bytes.count == 17 else {
        throw NSError(domain: "Invalid ACI length", code: 1, userInfo: nil)
    }
    guard bytes[0] == 0 else {
        throw NSError(domain: "Not an ACI", code: 1, userInfo: nil)
    }
    
    let uuidTuple = (
        bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12],
        bytes[13], bytes[14], bytes[15], bytes[16]
    )
    let uuid = UUID(uuid: uuidTuple)
    return Aci(fromUUID: uuid)
}


