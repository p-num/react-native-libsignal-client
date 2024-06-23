import { Direction, IdentityKeyStore, KyberPreKeyRecord, KyberPreKeyStore, PreKeyRecord, PreKeyStore, PrivateKey, PublicKey, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore, SignedPreKeyRecord, SignedPreKeyStore } from 'react-native-libsignal-client';
import { ProtocolAddress } from 'react-native-libsignal-client/Address';

class InMemorySessionStore extends SessionStore {
	private state = new Map<string, Uint8Array>();
	async saveSession(
		name: ProtocolAddress,
		record: SessionRecord
	): Promise<void> {
		const idx = `${name.name}::${name.deviceId}`;
		this.state.set(idx, record.serialized);
	}
	async getSession(
		name: ProtocolAddress
	): Promise<SessionRecord | null> {
		const idx = `${name.name}::${name.deviceId}`;
		const serialized = this.state.get(idx);
		if (serialized) {
			return new SessionRecord(serialized)
		}
		return null;
	}
	async getExistingSessions(
		addresses: ProtocolAddress[]
	): Promise<SessionRecord[]> {
		return addresses.map((address) => {
			const idx = `${address.name}::${address.deviceId}`;
			console.log({s: this.state})
			const serialized = this.state.get(idx);
			if (!serialized) {
				throw `no session for ${idx}`;
			}
			return new SessionRecord(serialized);
		});
	}
}

class InMemoryIdentityKeyStore extends IdentityKeyStore {
	private idKeys = new Map<string, PublicKey>();
	private localRegistrationId: number;
	private identityKey: PrivateKey;

	constructor(localRegistrationId?: number) {
		super();
		this.identityKey = PrivateKey.generate();
		this.localRegistrationId = localRegistrationId ?? 5;
	}

	async getIdentityKey(): Promise<PrivateKey> {
		return this.identityKey;
	}
	async getLocalRegistrationId(): Promise<number> {
		return this.localRegistrationId;
	}

	async isTrustedIdentity(
		name: ProtocolAddress,
		key: PublicKey,
		_direction: Direction
	): Promise<boolean> {
		const idx = `${name.name}::${name.deviceId}`;
		const currentKey = this.idKeys.get(idx);
		if (currentKey) {
			return currentKey.compare(key) === 0;
		}
		return true;
	}

	async saveIdentity(
		name: ProtocolAddress,
		key: PublicKey
	): Promise<boolean> {
		const idx = `${name.name}::${name.deviceId}`;
		const currentKey = this.idKeys.get(idx);
		if (currentKey) {
			const changed = currentKey.compare(key) !== 0;
			this.idKeys.set(idx, key);
			return changed;
		}

		this.idKeys.set(idx, key);
		return false;
	}
	async getIdentity(
		name: ProtocolAddress
	): Promise<PublicKey | null> {
		const idx = `${name.name}::${name.deviceId}`;
		return this.idKeys.get(idx) ?? null;
	}
}

class InMemoryPreKeyStore extends PreKeyStore {
	private state = new Map<number, Uint8Array>();
	async savePreKey(
		id: number,
		record: PreKeyRecord
	): Promise<void> {
		this.state.set(id, record.serialized);
	}
	async getPreKey(id: number): Promise<PreKeyRecord> {
		const record = this.state.get(id);
		if (!record) {
			throw new Error(`pre-key ${id} not found`);
		}
		return new PreKeyRecord(record);
	}
	async removePreKey(id: number): Promise<void> {
		this.state.delete(id);
	}
}

class InMemorySignedPreKeyStore extends SignedPreKeyStore {
	private state = new Map<number, Uint8Array>();
	async saveSignedPreKey(
		id: number,
		record: SignedPreKeyRecord
	): Promise<void> {
		this.state.set(id, record.serialized);
	}
	async getSignedPreKey(
		id: number
	): Promise<SignedPreKeyRecord> {
		const record = this.state.get(id);
		if (!record) {
			throw new Error(`pre-key ${id} not found`);
		}
		return new SignedPreKeyRecord(record);
	}
}

class InMemoryKyberPreKeyStore extends KyberPreKeyStore {
	private state = new Map<number, Uint8Array>();
	private used = new Set<number>();
	async saveKyberPreKey(
		id: number,
		record: KyberPreKeyRecord
	): Promise<void> {
		this.state.set(id, record.serialized);
	}
	async getKyberPreKey(
		id: number
	): Promise<KyberPreKeyRecord> {
		const record = this.state.get(id);
		if (!record) {
			throw new Error(`kyber pre-key ${id} not found`);
		}
		return new KyberPreKeyRecord(record);
	}
	async markKyberPreKeyUsed(id: number): Promise<void> {
		this.used.add(id);
	}
	async hasKyberPreKeyBeenUsed(id: number): Promise<boolean> {
		return this.used.has(id);
	}
}

class InMemorySenderKeyStore extends SenderKeyStore {
	private state = new Map<string, SenderKeyRecord>();
	async saveSenderKey(
		sender: ProtocolAddress,
		distributionId: string,
		record: SenderKeyRecord
	): Promise<void> {
		const idx = `${distributionId}::${sender.name}::${sender.deviceId}`;
		this.state.set(idx, record);
	}
	async getSenderKey(
		sender: ProtocolAddress,
		distributionId: string
	): Promise<SenderKeyRecord | null> {
		const idx = `${distributionId}::${sender.name}::${sender.deviceId}`;
		return this.state.get(idx) ?? null;
	}
}

export class TestStores {
	sender: InMemorySenderKeyStore;
	prekey: InMemoryPreKeyStore;
	signed: InMemorySignedPreKeyStore;
	kyber: InMemoryKyberPreKeyStore;
	identity: InMemoryIdentityKeyStore;
	session: InMemorySessionStore;

	constructor() {
		this.sender = new InMemorySenderKeyStore();
		this.prekey = new InMemoryPreKeyStore();
		this.signed = new InMemorySignedPreKeyStore();
		this.kyber = new InMemoryKyberPreKeyStore();
		this.identity = new InMemoryIdentityKeyStore();
		this.session = new InMemorySessionStore();
	}
}
