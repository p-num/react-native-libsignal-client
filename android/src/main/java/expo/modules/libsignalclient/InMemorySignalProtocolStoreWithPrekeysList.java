package expo.modules.libsignalclient;

import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.groups.state.InMemorySenderKeyStore;
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.state.impl.*;

public class InMemorySignalProtocolStoreWithPrekeysList implements SignalProtocolStore {
    private final InMemoryPreKeyStoreWithList preKeyStore = new InMemoryPreKeyStoreWithList();
    private final InMemorySessionStore sessionStore = new InMemorySessionStore();
    private final InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();
    private final InMemoryKyberPreKeyStore kyberPreKeyStore = new InMemoryKyberPreKeyStore();
    private final InMemorySenderKeyStore senderKeyStore = new InMemorySenderKeyStore();
    private final InMemoryIdentityKeyStore identityKeyStore;

    public InMemorySignalProtocolStoreWithPrekeysList(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair, registrationId);
    }

    public IdentityKeyPair getIdentityKeyPair() {
        return this.identityKeyStore.getIdentityKeyPair();
    }

    public int getLocalRegistrationId() {
        return this.identityKeyStore.getLocalRegistrationId();
    }

    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        return this.identityKeyStore.saveIdentity(address, identityKey);
    }

    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, IdentityKeyStore.Direction direction) {
        return this.identityKeyStore.isTrustedIdentity(address, identityKey, direction);
    }

    public IdentityKey getIdentity(SignalProtocolAddress address) {
        return this.identityKeyStore.getIdentity(address);
    }

    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        return this.preKeyStore.loadPreKey(preKeyId);
    }

    public void storePreKey(int preKeyId, PreKeyRecord record) {
        this.preKeyStore.storePreKey(preKeyId, record);
    }

    public boolean containsPreKey(int preKeyId) {
        return this.preKeyStore.containsPreKey(preKeyId);
    }

    public void removePreKey(int preKeyId) {
        this.preKeyStore.removePreKey(preKeyId);
    }

    public SessionRecord loadSession(SignalProtocolAddress address) {
        return this.sessionStore.loadSession(address);
    }

    public List<SessionRecord> loadExistingSessions(List<SignalProtocolAddress> addresses) throws NoSessionException {
        return this.sessionStore.loadExistingSessions(addresses);
    }

    public List<Integer> getSubDeviceSessions(String name) {
        return this.sessionStore.getSubDeviceSessions(name);
    }

    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        this.sessionStore.storeSession(address, record);
    }

    public boolean containsSession(SignalProtocolAddress address) {
        return this.sessionStore.containsSession(address);
    }

    public void deleteSession(SignalProtocolAddress address) {
        this.sessionStore.deleteSession(address);
    }

    public void deleteAllSessions(String name) {
        this.sessionStore.deleteAllSessions(name);
    }

    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        return this.signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
    }

    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return this.signedPreKeyStore.loadSignedPreKeys();
    }

    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        this.signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
    }

    public boolean containsSignedPreKey(int signedPreKeyId) {
        return this.signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
    }

    public void removeSignedPreKey(int signedPreKeyId) {
        this.signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
    }

    public void storeSenderKey(SignalProtocolAddress sender, UUID distributionId, SenderKeyRecord record) {
        this.senderKeyStore.storeSenderKey(sender, distributionId, record);
    }

    public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distributionId) {
        return this.senderKeyStore.loadSenderKey(sender, distributionId);
    }

    public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
        return this.kyberPreKeyStore.loadKyberPreKey(kyberPreKeyId);
    }

    public List<KyberPreKeyRecord> loadKyberPreKeys() {
        return this.kyberPreKeyStore.loadKyberPreKeys();
    }

    public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) {
        this.kyberPreKeyStore.storeKyberPreKey(kyberPreKeyId, record);
    }

    public boolean containsKyberPreKey(int kyberPreKeyId) {
        return this.kyberPreKeyStore.containsKyberPreKey(kyberPreKeyId);
    }

    public void markKyberPreKeyUsed(int kyberPreKeyId) {
        this.kyberPreKeyStore.markKyberPreKeyUsed(kyberPreKeyId);
    }

    public boolean hasKyberPreKeyBeenUsed(int kyberPreKeyId) {
        return this.kyberPreKeyStore.hasKyberPreKeyBeenUsed(kyberPreKeyId);
    }

    public List<PreKeyRecord> loadPreKeys() {
        return this.preKeyStore.loadPreKeys();
    }
}
