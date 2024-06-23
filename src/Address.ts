import { Buffer } from '@craftzdog/react-native-buffer';
import 'react-native-get-random-values';
import * as uuid from 'uuid';
import ReactNativeLibsignalClientModule from './ReactNativeLibsignalClientModule';

enum ServiceIdKind {
	Aci = 0,
	Pni = 1,
}

const SERVICE_ID_FIXED_WIDTH_BINARY_LEN = 17;

export abstract class ServiceId extends Object {
	private readonly serviceIdFixedWidthBinary: Uint8Array;

	// This has to be public for `InstanceType<T>`, which we use below.
	constructor(serviceIdFixedWidthBinary: Uint8Array) {
		super();
		// biome-ignore lint/suspicious/noDoubleEquals: <explanation>
		if (serviceIdFixedWidthBinary.length != SERVICE_ID_FIXED_WIDTH_BINARY_LEN) {
			throw new TypeError('invalid Service-Id-FixedWidthBinary');
		}
		this.serviceIdFixedWidthBinary = serviceIdFixedWidthBinary;
	}

	protected static fromUuidBytesAndKind<T extends typeof ServiceId>(
		// Why the explicit constructor signature?
		// Because ServiceId is abstract, and TypeScript won't let us construct an abstract class.
		// Strictly speaking we don't need the 'typeof' and 'InstanceType',
		// but it's more consistent with the factory methods below.
		this: new (
			serviceIdFixedWidthBinary: Uint8Array
		) => InstanceType<T>,
		uuidBytes: ArrayLike<number>,
		kind: ServiceIdKind
	): InstanceType<T> {
		const buffer = Buffer.alloc(SERVICE_ID_FIXED_WIDTH_BINARY_LEN);
		buffer[0] = kind;
		buffer.set(uuidBytes, 1);
		// biome-ignore lint/complexity/noThisInStatic: <explanation>
		return new this(new Uint8Array(buffer));
	}

	getServiceIdBinary(): Uint8Array {
		return ReactNativeLibsignalClientModule.ServiceId_ServiceIdBinary(
			new Uint8Array(this.serviceIdFixedWidthBinary)
		);
	}

	getServiceIdFixedWidthBinary(): Uint8Array {
		return new Uint8Array(this.serviceIdFixedWidthBinary);
	}

	getServiceIdString(): string {
		return ReactNativeLibsignalClientModule.ServiceId_ServiceIdString(
			new Uint8Array(this.serviceIdFixedWidthBinary)
		);
	}

	override toString(): string {
		return ReactNativeLibsignalClientModule.ServiceId_ServiceIdLog(
			new Uint8Array(this.serviceIdFixedWidthBinary)
		);
	}

	private downcastTo<T extends typeof ServiceId>(subclass: T): InstanceType<T> {
		// Omitting `as object` results in TypeScript mistakenly assuming the branch is always taken.
		if ((this as object) instanceof subclass) {
			return this as InstanceType<T>;
		}
		throw new TypeError(
			`expected ${subclass.name}, got ${this.constructor.name}`
		);
	}

	static parseFromServiceIdFixedWidthBinary<T extends typeof ServiceId>(
		this: T,
		serviceIdFixedWidthBinary: Uint8Array
	): InstanceType<T> {
		let result: ServiceId;
		switch (serviceIdFixedWidthBinary[0]) {
			case ServiceIdKind.Aci:
				result = new Aci(serviceIdFixedWidthBinary);
				break;
			case ServiceIdKind.Pni:
				result = new Pni(serviceIdFixedWidthBinary);
				break;
			default:
				throw new TypeError('unknown type in Service-Id-FixedWidthBinary');
		}
		// biome-ignore lint/complexity/noThisInStatic: <explanation>
		return result.downcastTo(this);
	}

	static parseFromServiceIdBinary<T extends typeof ServiceId>(
		this: T,
		serviceIdBinary: Uint8Array
	): InstanceType<T> {
		const result = ServiceId.parseFromServiceIdFixedWidthBinary(
			ReactNativeLibsignalClientModule.ServiceId_ParseFromServiceIdBinary(
				new Uint8Array(serviceIdBinary)
			)
		);
		// biome-ignore lint/complexity/noThisInStatic: <explanation>
		return result.downcastTo(this);
	}

	static parseFromServiceIdString<T extends typeof ServiceId>(
		this: T,
		serviceIdString: string
	): InstanceType<T> {
		const result = ServiceId.parseFromServiceIdFixedWidthBinary(
			ReactNativeLibsignalClientModule.ServiceId_ParseFromServiceIdString(
				serviceIdString
			)
		);
		// biome-ignore lint/complexity/noThisInStatic: <explanation>
		return result.downcastTo(this);
	}

	getRawUuid(): string {
		return uuid.stringify(this.serviceIdFixedWidthBinary, 1);
	}

	getRawUuidBytes(): Uint8Array {
		return new Uint8Array(
			Buffer.from(this.serviceIdFixedWidthBinary.buffer, 1)
		);
	}

	isEqual(other: ServiceId): boolean {
		return Buffer.from(this.serviceIdFixedWidthBinary).equals(
			Buffer.from(other.serviceIdFixedWidthBinary)
		);
	}

	static toConcatenatedFixedWidthBinary(serviceIds: ServiceId[]): Uint8Array {
		const result = Buffer.alloc(
			serviceIds.length * SERVICE_ID_FIXED_WIDTH_BINARY_LEN
		);
		let offset = 0;
		for (const serviceId of serviceIds) {
			result.set(serviceId.serviceIdFixedWidthBinary, offset);
			offset += SERVICE_ID_FIXED_WIDTH_BINARY_LEN;
		}
		return new Uint8Array(result);
	}
}

export class Aci extends ServiceId {
	private readonly __type?: never;

	static fromUuid(uuidString: string): Aci {
		return Aci.fromUuidBytes(uuid.parse(uuidString));
	}

	static fromUuidBytes(uuidBytes: ArrayLike<number>): Aci {
		return Aci.fromUuidBytesAndKind(uuidBytes, ServiceIdKind.Aci);
	}
}

export class Pni extends ServiceId {
	private readonly __type?: never;

	static fromUuid(uuidString: string): Pni {
		return Pni.fromUuidBytes(uuid.parse(uuidString));
	}

	static fromUuidBytes(uuidBytes: ArrayLike<number>): Pni {
		return Pni.fromUuidBytesAndKind(uuidBytes, ServiceIdKind.Pni);
	}
}

export class ProtocolAddress {
	private readonly name: string
	private readonly deviceId: number

	constructor(name: string, deviceId: number) {
		this.name = name;
		this.deviceId = Number(deviceId);
	}
	
	static new(address: string): ProtocolAddress {
		const[name, deviceId] = address.split('.');
		return new ProtocolAddress(
			name, 
			Number(deviceId)
		);
	}

	/**
	 * Returns a ServiceId if this address contains a valid ServiceId, `null` otherwise.
	 *
	 * In a future release ProtocolAddresses will *only* support ServiceIds.
	 */
	serviceId(): ServiceId | null {
		try {
			return ServiceId.parseFromServiceIdString(this.name);
		} catch {
			return null;
		}
	}


	toString(): string {
		return `${this.name}.${this.deviceId}`;
	}
}
