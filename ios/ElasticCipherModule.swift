import ExpoModulesCore
import CryptoSwift
import CommonCrypto
import Foundation

public class ElasticCipherModule: Module {
    private var handles: [String: Any] = [:]
    private let queue = DispatchQueue(label: "expo.modules.libsignalclient.elasticcipher")

    private func newHandle() -> String {
        UUID().uuidString
    }

    private func invalidHandleError(_ handle: String) -> NSError {
        NSError(domain: "ElasticCipher", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid handle: \(handle)"])
    }

    private static let incrementalMacOutputSize = Int(CC_SHA256_DIGEST_LENGTH) // 32

    private func computeIncrementalMacChunkSize(dataSize: Int) throws -> Int {
        // Mirrors libsignal's calculate_chunk_size::<Sha256>()
        // MINIMUM_CHUNK_SIZE = 64 KiB
        // MAXIMUM_CHUNK_SIZE = 2 MiB
        // TARGET_TOTAL_DIGEST_SIZE = 8 KiB
        guard dataSize >= 0 else {
            throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid dataSize"])
        }

        let minimumChunkSize = 64 * 1024
        let maximumChunkSize = 2 * 1024 * 1024
        let targetTotalDigestSize = 8 * 1024
        let digestSize = Self.incrementalMacOutputSize
        let targetChunkCount = targetTotalDigestSize / digestSize // 256 for SHA-256

        let minTotal = targetChunkCount * minimumChunkSize
        if dataSize < minTotal {
            return minimumChunkSize
        }

        let maxTotal = targetChunkCount * maximumChunkSize
        if dataSize < maxTotal {
            // ceil(dataSize / targetChunkCount)
            return (dataSize + targetChunkCount - 1) / targetChunkCount
        }

        return maximumChunkSize
    }

    private final class HmacBox {
        enum Variant {
            case sha256
            case sha512
        }

        let variant: Variant
        var ctx = CCHmacContext()

        init(variant: Variant, key: Data) {
            self.variant = variant
            let algorithm: CCHmacAlgorithm = (variant == .sha256) ? CCHmacAlgorithm(kCCHmacAlgSHA256) : CCHmacAlgorithm(kCCHmacAlgSHA512)
            key.withUnsafeBytes { keyRaw in
                CCHmacInit(&ctx, algorithm, keyRaw.baseAddress, keyRaw.count)
            }
        }

        func update(_ data: Data) {
            data.withUnsafeBytes { raw in
                CCHmacUpdate(&ctx, raw.baseAddress, raw.count)
            }
        }

        func finalize() -> Data {
            let digestLength = (variant == .sha256) ? Int(CC_SHA256_DIGEST_LENGTH) : Int(CC_SHA512_DIGEST_LENGTH)
            var out = [UInt8](repeating: 0, count: digestLength)
            CCHmacFinal(&ctx, &out)
            return Data(out)
        }
    }

    private final class HashBox {
        enum Variant {
            case sha256
            case sha512
        }

        let variant: Variant
        var sha256 = CC_SHA256_CTX()
        var sha512 = CC_SHA512_CTX()

        init(variant: Variant) {
            self.variant = variant
            switch variant {
            case .sha256:
                CC_SHA256_Init(&sha256)
            case .sha512:
                CC_SHA512_Init(&sha512)
            }
        }

        func update(_ data: Data) {
            data.withUnsafeBytes { raw in
                switch variant {
                case .sha256:
                    CC_SHA256_Update(&sha256, raw.baseAddress, CC_LONG(raw.count))
                case .sha512:
                    CC_SHA512_Update(&sha512, raw.baseAddress, CC_LONG(raw.count))
                }
            }
        }

        func finalize() -> Data {
            switch variant {
            case .sha256:
                var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                CC_SHA256_Final(&out, &sha256)
                return Data(out)
            case .sha512:
                var out = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
                CC_SHA512_Final(&out, &sha512)
                return Data(out)
            }
        }
    }

    private final class IncrementalMacBox {
        var ctx = CCHmacContext()
        let chunkSize: Int
        var unusedLength: Int

        init(key: Data, chunkSize: Int) {
            self.chunkSize = chunkSize
            self.unusedLength = chunkSize
            key.withUnsafeBytes { keyRaw in
                CCHmacInit(&ctx, CCHmacAlgorithm(kCCHmacAlgSHA256), keyRaw.baseAddress, keyRaw.count)
            }
        }

        private func updateChunk(_ bytes: UnsafeRawPointer?, length: Int) -> Data? {
            guard length > 0 else { return nil }

            CCHmacUpdate(&ctx, bytes, length)
            unusedLength -= length
            if unusedLength == 0 {
                unusedLength = chunkSize
                var ctxCopy = ctx
                var out = [UInt8](repeating: 0, count: ElasticCipherModule.incrementalMacOutputSize)
                CCHmacFinal(&ctxCopy, &out)
                return Data(out)
            }
            return nil
        }

        func update(_ data: Data) -> Data {
            guard !data.isEmpty else { return Data() }

            var produced = Data()
            data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                var offset = 0
                var remaining = raw.count
                while remaining > 0 {
                    let toWrite = min(remaining, unusedLength)
                    if let mac = updateChunk(base.advanced(by: offset), length: toWrite) {
                        produced.append(mac)
                    }
                    offset += toWrite
                    remaining -= toWrite
                }
            }
            return produced
        }

        func pendingBytesSize() -> Int {
            chunkSize - unusedLength
        }

        func finalize() -> Data {
            var out = [UInt8](repeating: 0, count: ElasticCipherModule.incrementalMacOutputSize)
            CCHmacFinal(&ctx, &out)
            return Data(out)
        }
    }

    private final class ValidatingMacBox {
        let incremental: IncrementalMacBox
        var expected: [Data]

        init(key: Data, chunkSize: Int, digest: Data) throws {
            guard chunkSize > 0 else {
                throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid chunkSize"])
            }
            let macSize = ElasticCipherModule.incrementalMacOutputSize
            guard digest.count % macSize == 0 else {
                throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid digest length"])
            }

            var macs: [Data] = []
            macs.reserveCapacity(max(1, digest.count / macSize))
            var idx = 0
            while idx < digest.count {
                macs.append(digest.subdata(in: idx..<(idx + macSize)))
                idx += macSize
            }
            // Reverse so that `last` is the next expected MAC.
            self.expected = macs.reversed()
            self.incremental = IncrementalMacBox(key: key, chunkSize: chunkSize)
        }

        func update(_ data: Data) -> Int {
            let produced = incremental.update(data)
            guard !produced.isEmpty else { return 0 }

            let macSize = ElasticCipherModule.incrementalMacOutputSize
            var wholeChunks = 0
            var idx = 0
            while idx < produced.count {
                guard let nextExpected = expected.last else {
                    return -1
                }
                let mac = produced.subdata(in: idx..<(idx + macSize))
                if mac == nextExpected {
                    _ = expected.popLast()
                    wholeChunks += 1
                } else {
                    return -1
                }
                idx += macSize
            }
            return wholeChunks * incremental.chunkSize
        }

        func finalize() -> Int {
            let pending = incremental.pendingBytesSize()
            let mac = incremental.finalize()
            guard expected.count == 1, expected[0] == mac else {
                return -1
            }
            expected.removeAll(keepingCapacity: false)
            return pending
        }
    }


    public func definition() -> ModuleDefinition {
        Name("ElasticCipher")

        Function("initiateElasticCipher") { (type: String, key: Data, iv: Data, mode: String) throws -> String in
            try self.queue.sync {
                let uuid = self.newHandle()
                let aes: AES
                let blockMode: BlockMode
                let padding: Padding

                switch type {
                case "AES/CBC/PKCS5Padding":
                    blockMode = CBC(iv: iv.bytes)
                    padding = .pkcs7
                case "AES/GCM/NoPadding":
                    // This streaming API cannot safely support AEAD modes (no AAD input and no explicit tag handling).
                    // Use the dedicated Aes256GcmEncrypt/Aes256GcmDecrypt APIs instead.
                    throw NSError(
                        domain: "ElasticCipher",
                        code: 1,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "Unsupported cipher type for streaming ElasticCipher on iOS: AES/GCM/NoPadding. Use Aes256GcmEncrypt/Aes256GcmDecrypt instead."
                        ]
                    )
                case "AES/CTR/NoPadding":
                    blockMode = CTR(iv: iv.bytes)
                    padding = .noPadding
                default:
                    throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unsupported cipher type: \(type)"])
                }

                aes = try AES(key: key.bytes, blockMode: blockMode, padding: padding)

                let cryptor: any Updatable
                if mode == "encrypt" {
                    cryptor = try aes.makeEncryptor()
                } else {
                    cryptor = try aes.makeDecryptor()
                }

                self.handles[uuid] = cryptor
                return uuid
            }
        }

        Function("updateElasticCipher") { (handle: String, data: Data) throws -> Data in
            try self.queue.sync {
                guard var cryptor = self.handles[handle] as? any Updatable else {
                    throw self.invalidHandleError(handle)
                }
                let result = try cryptor.update(withBytes: data.bytes.slice, isLast: false)
                // Cryptor might be a struct or class. If struct, we need to update the stored value.
                // CryptoSwift Cryptors are usually classes (CS.Cryptor), but let's be safe.
                // Actually, Cryptor protocol doesn't enforce class.
                // If it's a value type, we need to write it back.
                self.handles[handle] = cryptor
                return Data(result)
            }
        }

        Function("finalizeElasticCipher") { (handle: String, data: Data) throws -> Data in
            try self.queue.sync {
                guard var cryptor = self.handles[handle] as? any Updatable else {
                    throw self.invalidHandleError(handle)
                }
                let result = try cryptor.update(withBytes: data.bytes.slice, isLast: true)
                self.handles.removeValue(forKey: handle)
                return Data(result)
            }
        }

        Function("destroyElasticCipher") { (handle: String) in
            self.queue.sync {
                self.handles.removeValue(forKey: handle)
            }
        }

        // Incremental HMAC
        Function("IncrementalHmacInit") { (type: String, key: Data) throws -> String in
            try self.queue.sync {
                let variant: HmacBox.Variant
                switch type {
                case "sha256": variant = .sha256
                case "sha512": variant = .sha512
                default:
                    throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unsupported HMAC type: \(type)"])
                }
                let handle = self.newHandle()
                self.handles[handle] = HmacBox(variant: variant, key: key)
                return handle
            }
        }

        Function("HmacSha256Update") { (handle: String, data: Data) throws in
            try self.queue.sync {
                guard let hmac = self.handles[handle] as? HmacBox else {
                    throw self.invalidHandleError(handle)
                }
                hmac.update(data)
            }
        }

        Function("HmacSha512Update") { (handle: String, data: Data) throws in
            try self.queue.sync {
                guard let hmac = self.handles[handle] as? HmacBox else {
                    throw self.invalidHandleError(handle)
                }
                hmac.update(data)
            }
        }

        Function("HmacSha256Digest") { (handle: String) throws -> Data in
            try self.queue.sync {
                guard let hmac = self.handles[handle] as? HmacBox else {
                    throw self.invalidHandleError(handle)
                }
                self.handles.removeValue(forKey: handle)
                return hmac.finalize()
            }
        }

        Function("HmacSha512Digest") { (handle: String) throws -> Data in
            try self.queue.sync {
                guard let hmac = self.handles[handle] as? HmacBox else {
                    throw self.invalidHandleError(handle)
                }
                self.handles.removeValue(forKey: handle)
                return hmac.finalize()
            }
        }

        // Incremental hash
        Function("IncrementalHashInit") { (type: String) throws -> String in
            try self.queue.sync {
                let variant: HashBox.Variant
                switch type {
                case "sha256": variant = .sha256
                case "sha512": variant = .sha512
                default:
                    throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unsupported hash type: \(type)"])
                }
                let handle = self.newHandle()
                self.handles[handle] = HashBox(variant: variant)
                return handle
            }
        }

        Function("HashSha256Update") { (handle: String, data: Data) throws in
            try self.queue.sync {
                guard let hash = self.handles[handle] as? HashBox else {
                    throw self.invalidHandleError(handle)
                }
                hash.update(data)
            }
        }

        Function("HashSha512Update") { (handle: String, data: Data) throws in
            try self.queue.sync {
                guard let hash = self.handles[handle] as? HashBox else {
                    throw self.invalidHandleError(handle)
                }
                hash.update(data)
            }
        }

        Function("HashSha256Digest") { (handle: String) throws -> Data in
            try self.queue.sync {
                guard let hash = self.handles[handle] as? HashBox else {
                    throw self.invalidHandleError(handle)
                }
                self.handles.removeValue(forKey: handle)
                return hash.finalize()
            }
        }

        Function("HashSha512Digest") { (handle: String) throws -> Data in
            try self.queue.sync {
                guard let hash = self.handles[handle] as? HashBox else {
                    throw self.invalidHandleError(handle)
                }
                self.handles.removeValue(forKey: handle)
                return hash.finalize()
            }
        }

        // Incremental / validating MAC (libsignal-compatible, implemented locally)
        Function("IncrementalMacCalculateChunkSize") { (dataSize: Int) throws -> Int in
            try self.queue.sync {
                try self.computeIncrementalMacChunkSize(dataSize: dataSize)
            }
        }

        Function("IncrementalMacInit") { (key: Data, chunkSize: Int) throws -> String in
            try self.queue.sync {
                guard chunkSize > 0 else {
                    throw NSError(domain: "ElasticCipher", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid chunkSize"])
                }
                let handle = self.newHandle()
                self.handles[handle] = IncrementalMacBox(key: key, chunkSize: chunkSize)
                return handle
            }
        }

        Function("IncrementalMacUpdate") { (handle: String, data: Data) throws -> Data in
            try self.queue.sync {
                guard let mac = self.handles[handle] as? IncrementalMacBox else {
                    throw self.invalidHandleError(handle)
                }
                return mac.update(data)
            }
        }

        Function("IncrementalMacFinalize") { (handle: String) throws -> Data in
            try self.queue.sync {
                guard let mac = self.handles[handle] as? IncrementalMacBox else {
                    throw self.invalidHandleError(handle)
                }
                self.handles.removeValue(forKey: handle)
                return mac.finalize()
            }
        }

        Function("ValidatingMacInit") { (key: Data, chunkSize: Int, digest: Data) throws -> String in
            try self.queue.sync {
                let handle = self.newHandle()
                self.handles[handle] = try ValidatingMacBox(key: key, chunkSize: chunkSize, digest: digest)
                return handle
            }
        }

        Function("ValidatingMacUpdate") { (handle: String, data: Data) throws -> Int in
            try self.queue.sync {
                guard let mac = self.handles[handle] as? ValidatingMacBox else {
                    throw self.invalidHandleError(handle)
                }
                return mac.update(data)
            }
        }

        Function("ValidatingMacFinalize") { (handle: String) throws -> Int in
            try self.queue.sync {
                guard let mac = self.handles[handle] as? ValidatingMacBox else {
                    throw self.invalidHandleError(handle)
                }
                self.handles.removeValue(forKey: handle)
                return mac.finalize()
            }
        }
    }
}

private extension Data {
    var bytes: [UInt8] { Array(self) }
}

private extension Array {
    var slice: ArraySlice<Element> {
        return ArraySlice(self)
    }
}
