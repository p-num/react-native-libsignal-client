package expo.modules.libsignalclient;

import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.state.PreKeyStore;

public class InMemoryPreKeyStoreWithList implements PreKeyStore {

    private final Map<Integer, byte[]> store = new HashMap<>();

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        try {
            if (!store.containsKey(preKeyId)) {
                throw new InvalidKeyIdException("No such prekeyrecord!");
            }

            return new PreKeyRecord(store.get(preKeyId));
        } catch (InvalidMessageException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        store.put(preKeyId, record.serialize());
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return store.containsKey(preKeyId);
    }

    @Override
    public void removePreKey(int preKeyId) {
        store.remove(preKeyId);
    }

    public List<PreKeyRecord> loadPreKeys() {
        try {
            List<PreKeyRecord> results = new LinkedList<>();

            for (byte[] serialized : store.values()) {
                results.add(new PreKeyRecord(serialized));
            }

            return results;
        } catch (InvalidMessageException e) {
            throw new AssertionError(e);
        }
    }
}


