import { RANDOM_LENGTH } from '../internal/Constants';

import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import { randomBytes } from '../../randomBytes';
import type GenericServerSecretParams from '../GenericServerSecretParams';
import BackupAuthCredentialResponse from './BackupAuthCredentialResponse';
import type BackupCredentialType from './BackupCredentialType';
import type BackupLevel from './BackupLevel';

export default class BackupAuthCredentialRequest {
	serialized: Uint8Array;

	constructor(contents: Uint8Array) {
		this.serialized = contents;
	}

	issueCredential(
		timestamp: number,
		backupLevel: BackupLevel,
		type: BackupCredentialType,
		params: GenericServerSecretParams
	): BackupAuthCredentialResponse {
		const random = randomBytes(RANDOM_LENGTH);
		return this.issueCredentialWithRandom(
			timestamp,
			backupLevel,
			type,
			params,
			random
		);
	}

	issueCredentialWithRandom(
		timestamp: number,
		backupLevel: BackupLevel,
		type: BackupCredentialType,
		params: GenericServerSecretParams,
		random: Uint8Array
	): BackupAuthCredentialResponse {
		return new BackupAuthCredentialResponse(
			new Uint8Array(
				ReactNativeLibsignalClientModule.backupAuthCredentialRequestIssueDeterministic(
					this.serialized,
					timestamp,
					backupLevel,
					type,
					params.serialized,
					random
				)
			)
		);
	}
}
