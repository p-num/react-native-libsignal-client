package expo.modules.libsignalclient

import org.signal.libsignal.internal.Native

class IncrementalMac(key: ByteArray, chunkSize: Int) {
    private val incrementalMac: Long = Native.IncrementalMac_Initialize(key, chunkSize);

    fun update(data: ByteArray): ByteArray {
        return Native.IncrementalMac_Update(this.incrementalMac, data, 0, data.size)
    }

    fun finalize(): ByteArray {
        return Native.IncrementalMac_Finalize(this.incrementalMac)
    }
}
