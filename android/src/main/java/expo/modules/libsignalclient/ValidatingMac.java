package expo.modules.libsignalclient;

import org.signal.libsignal.internal.Native;

public class ValidatingMac {
    private final long validatingMac;

    public ValidatingMac(byte[] key, int chunkSize, byte[] digest) {
        this.validatingMac = Native.ValidatingMac_Initialize(key, chunkSize, digest);
    }

    static public int calculateChunkSize(int dataSize) {
        return Native.IncrementalMac_CalculateChunkSize(dataSize);
    }

    public int update(byte[] chunk) {
        return Native.ValidatingMac_Update(this.validatingMac, chunk, 0, chunk.length);
    }

    public int _finalize() {
        return Native.ValidatingMac_Finalize(this.validatingMac);
    }
}
