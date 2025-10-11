import { RANDOM_LENGTH } from '../internal/Constants';

import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import type GenericServerPublicParams from '../GenericServerPublicParams';
import BackupAuthCredentialPresentation from './BackupAuthCredentialPresentation';
import BackupCredentialType from './BackupCredentialType';
import BackupLevel from './BackupLevel';

export default class BackupAuthCredential {
	serialized: Uint8Array;

	constructor(contents: Uint8Array) {
		this.serialized = contents;
	}

	present(
		serverParams: GenericServerPublicParams
	): BackupAuthCredentialPresentation {
		const random = randomBytes(RANDOM_LENGTH);
		return this.presentWithRandom(serverParams, random);
	}

	presentWithRandom(
		serverParams: GenericServerPublicParams,
		random: Uint8Array
	): BackupAuthCredentialPresentation {
		return new BackupAuthCredentialPresentation(
			new Uint8Array(
				ReactNativeLibsignalClientModule.backupAuthCredentialPresentDeterministic(
					this.serialized,
					serverParams.serialized,
					random
				)
			)
		);
	}

	getBackupId(): Uint8Array {
		return new Uint8Array(
			ReactNativeLibsignalClientModule.backupAuthCredentialGetBackupId(
				this.serialized
			)
		);
	}

	getBackupLevel(): BackupLevel {
		const n: number =
			ReactNativeLibsignalClientModule.backupAuthCredentialGetBackupLevel(
				this.serialized
			);
		if (!(n in BackupLevel)) {
			throw new TypeError(`Invalid BackupLevel ${n}`);
		}
		return n;
	}

	getType(): BackupCredentialType {
		const n: number =
			ReactNativeLibsignalClientModule.backupAuthCredentialGetType(
				this.serialized
			);
		if (!(n in BackupCredentialType)) {
			throw new TypeError(`Invalid BackupCredentialType ${n}`);
		}
		return n;
	}
}
