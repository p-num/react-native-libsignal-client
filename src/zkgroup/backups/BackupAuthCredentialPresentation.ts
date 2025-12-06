import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import type GenericServerSecretParams from '../GenericServerSecretParams';
import BackupCredentialType from './BackupCredentialType';
import BackupLevel from './BackupLevel';

export default class BackupAuthCredentialPresentation {
	serialized: Uint8Array;

	constructor(contents: Uint8Array) {
		this.serialized = contents;
	}

	verify(
		serverParams: GenericServerSecretParams,
		now: Date = new Date()
	): void {
		ReactNativeLibsignalClientModule.backupAuthCredentialPresentationVerify(
			this.serialized,
			Math.floor(now.getTime() / 1000),
			serverParams.serialized
		);
	}

	getBackupId(): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.backupAuthCredentialPresentationGetBackupId(
				this.serialized
			)
		);
	}

	getBackupLevel(): BackupLevel {
		const n: number =
			ReactNativeLibsignalClientModule.backupAuthCredentialPresentationGetBackupLevel(
				this.serialized
			);
		if (!(n in BackupLevel)) {
			throw new TypeError(`Invalid BackupLevel ${n}`);
		}
		return n;
	}

	getType(): BackupCredentialType {
		const n: number =
			ReactNativeLibsignalClientModule.backupAuthCredentialPresentationGetType(
				this.serialized
			);
		if (!(n in BackupCredentialType)) {
			throw new TypeError(`Invalid BackupCredentialType ${n}`);
		}
		return n;
	}
}
