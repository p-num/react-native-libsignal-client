import ExpoModulesCore
import CryptoSwift
import Foundation

public class ElasticCipherModule: Module {
    private var ciphers: [String: any Updatable] = [:]

    public func definition() -> ModuleDefinition {
        Name("ElasticCipher")

        Function("initiateElasticCipher") { (type: String, key: Data, iv: Data, mode: String) throws -> String in
            let uuid = UUID().uuidString
            let aes: AES
            let blockMode: BlockMode
            let padding: Padding

            switch type {
            case "AES/CBC/PKCS5Padding":
                blockMode = CBC(iv: iv.bytes)
                padding = .pkcs7
            case "AES/GCM/NoPadding":
                // GCM in combined mode for streaming might be tricky, but we'll try standard usage.
                // Assuming IV is 12 bytes for GCM usually.
                blockMode = GCM(iv: iv.bytes, mode: .combined)
                padding = .noPadding
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

            self.ciphers[uuid] = cryptor
            return uuid
        }

        Function("updateElasticCipher") { (handle: String, data: Data) throws -> Data in
            guard var cryptor = self.ciphers[handle] else {
                throw NSError(domain: "ElasticCipher", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid handle"])
            }
            let result = try cryptor.update(withBytes: data.bytes.slice, isLast: false)
            // Cryptor might be a struct or class. If struct, we need to update the stored value.
            // CryptoSwift Cryptors are usually classes (CS.Cryptor), but let's be safe.
            // Actually, Cryptor protocol doesn't enforce class.
            // If it's a value type, we need to write it back.
            self.ciphers[handle] = cryptor
            return Data(result)
        }

        Function("finalizeElasticCipher") { (handle: String, data: Data) throws -> Data in
            guard var cryptor = self.ciphers[handle] else {
                throw NSError(domain: "ElasticCipher", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid handle"])
            }
            let result = try cryptor.update(withBytes: data.bytes.slice, isLast: true)
            self.ciphers.removeValue(forKey: handle)
            return Data(result)
        }

        Function("destroyElasticCipher") { (handle: String) in
            self.ciphers.removeValue(forKey: handle)
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
