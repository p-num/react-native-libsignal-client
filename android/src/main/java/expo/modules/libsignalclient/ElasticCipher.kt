package expo.modules.libsignalclient

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.Optional
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

class ElasticCipher : Module() {
    private val handles = mutableMapOf<String, Any>()

    override fun definition() = ModuleDefinition {
        Name("ElasticCipher")

        Function("initiateElasticCipher", this@ElasticCipher::initiateElasticCipher)
        Function("updateElasticCipher", this@ElasticCipher::updateElasticCipher)
        Function("finalizeElasticCipher", this@ElasticCipher::finalizeElasticCipher)
        Function("destroyElasticCipher", this@ElasticCipher::destroyElasticCipher)
        
        Function("IncrementalHmacInit", this@ElasticCipher::incrementalHmacInit)
        Function("HmacSha256Update", this@ElasticCipher::hmacSha256Update)
        Function("HmacSha512Update", this@ElasticCipher::hmacSha512Update)
        Function("HmacSha256Digest", this@ElasticCipher::hmacSha256Digest)
        Function("HmacSha512Digest", this@ElasticCipher::hmacSha512Digest)
        
        Function("IncrementalHashInit", this@ElasticCipher::incrementalHashInit)
        Function("HashSha256Update", this@ElasticCipher::hashSha256Update)
        Function("HashSha512Update", this@ElasticCipher::hashSha512Update)
        Function("HashSha256Digest", this@ElasticCipher::hashSha256Digest)
        Function("HashSha512Digest", this@ElasticCipher::hashSha512Digest)

        Function("IncrementalMacCalculateChunkSize", this@ElasticCipher::incrementalMacCalculateChunkSize)
        Function("ValidatingMacInit", this@ElasticCipher::validatingMacInit)
        Function("ValidatingMacUpdate", this@ElasticCipher::validatingMacUpdate)
        Function("ValidatingMacFinalize", this@ElasticCipher::validatingMacFinalize)

        Function("IncrementalMacInit", this@ElasticCipher::incrementalMacInit)
        Function("IncrementalMacUpdate", this@ElasticCipher::incrementalMacUpdate)
        Function("IncrementalMacFinalize", this@ElasticCipher::incrementalMacFinalize)
    }

    private fun initiateElasticCipher(type: String, key: ByteArray, iv: ByteArray, mode: String): String {
        val cipher = initiateCipherFromType(type, key, iv, mode)

        val id = generateShortId()
        this.handles[id] = cipher

        return id
    }

    private fun updateElasticCipher(handle: String, data: ByteArray): ByteArray {
        val cipher = this.handles[handle]
        if (cipher == null) {
            throw Error("no elastic cipher with handle: "+handle)
        }
        return (cipher as Cipher).update(data) ?: ByteArray(0)
    }

    private fun finalizeElasticCipher(handle: String, data: ByteArray): ByteArray {
        val cipher = this.handles[handle]
        if (cipher == null) {
            throw Error("no elastic cipher with handle: "+handle)
        }
        this.handles.remove(handle)

        if (!data.isEmpty()) {
            return (cipher as Cipher).doFinal(data) ?: ByteArray(0)
        } else {
            return (cipher as Cipher).doFinal() ?: ByteArray(0)
        }
    }

    private fun destroyElasticCipher(handle: String) {
        this.handles.remove(handle)
    }

    private fun incrementalHmacInit(type: String, key: ByteArray): String {
        val algorithm = when (type) {
            "sha256" -> "HmacSHA256"
            "sha512" -> "HmacSHA512"
            else -> throw IllegalArgumentException("Unsupported HMAC type: $type")
        }
        
        val mac = Mac.getInstance(algorithm)
        val secretKey = SecretKeySpec(key, algorithm)
        mac.init(secretKey)
        
        val id = generateShortId()
        this.handles[id] = mac
        
        return id
    }

    private fun hmacSha256Update(handle: String, data: ByteArray) {
        val mac = this.handles[handle] as Mac
        mac.update(data)
    }

    private fun hmacSha512Update(handle: String, data: ByteArray) {
        val mac = this.handles[handle] as Mac
        mac.update(data)
    }

    private fun hmacSha256Digest(handle: String): ByteArray {
        val mac = this.handles[handle] as Mac
        val result = mac.doFinal()
        this.handles.remove(handle)
        return result
    }

    private fun hmacSha512Digest(handle: String): ByteArray {
        val mac = this.handles[handle] as Mac
        val result = mac.doFinal()
        this.handles.remove(handle)
        return result
    }

    private fun incrementalHashInit(type: String): String {
        val algorithm = when (type) {
            "sha256" -> "SHA-256"
            "sha512" -> "SHA-512"
            else -> throw IllegalArgumentException("Unsupported hash type: $type")
        }
        
        val digest = MessageDigest.getInstance(algorithm)
        
        val id = generateShortId()
        this.handles[id] = digest
        
        return id
    }

    private fun hashSha256Update(handle: String, data: ByteArray) {
        val digest = this.handles[handle] as MessageDigest
        digest.update(data)
    }

    private fun hashSha512Update(handle: String, data: ByteArray) {
        val digest = this.handles[handle] as MessageDigest
        digest.update(data)
    }

    private fun hashSha256Digest(handle: String): ByteArray {
        val digest = this.handles[handle] as MessageDigest
        val result = digest.digest()
        this.handles.remove(handle)
        return result
    }

    private fun hashSha512Digest(handle: String): ByteArray {
        val digest = this.handles[handle] as MessageDigest
        val result = digest.digest()
        this.handles.remove(handle)
        return result
    }

    private fun incrementalMacCalculateChunkSize(dataSize: Int): Int {
        return ValidatingMac.calculateChunkSize(dataSize)
    }

    private fun validatingMacInit(key: ByteArray, sizeChoiceValue: Int, digest: ByteArray): String {
        val validatingMac = ValidatingMac(key, sizeChoiceValue, digest)
        val id = generateShortId()
        this.handles[id] = validatingMac
        return id
    }

    private fun validatingMacUpdate(handle: String, data: ByteArray): Int {
        val mac = this.handles[handle] as ValidatingMac
        return mac.update(data)
    }

    private fun validatingMacFinalize(handle: String): Int {
        val mac = this.handles[handle] as ValidatingMac
        val result = mac._finalize()
        this.handles.remove(handle)
        return result
    }

    private fun incrementalMacInit(key: ByteArray, chunkSize: Int): String {
        val incrementalMac = IncrementalMac(key, chunkSize)
        val id = generateShortId()
        this.handles[id] = incrementalMac
        return id
    }

    private fun incrementalMacUpdate(handle: String, data: ByteArray): ByteArray {
        val mac = this.handles[handle] as IncrementalMac
        return mac.update(data)
    }

    private fun incrementalMacFinalize(handle: String): ByteArray {
        val mac = this.handles[handle] as IncrementalMac
        val result = mac.finalize()
        this.handles.remove(handle)
        return result
    }
}