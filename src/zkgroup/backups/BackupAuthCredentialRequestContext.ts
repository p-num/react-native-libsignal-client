//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';

import type { Uuid } from '../../ReactNativeLibsignalClient.types';
import ReactNativeLibsignalClientModule from '../../ReactNativeLibsignalClientModule';
import type GenericServerPublicParams from '../GenericServerPublicParams';
import BackupAuthCredential from './BackupAuthCredential';
import BackupAuthCredentialRequest from './BackupAuthCredentialRequest';
import type BackupAuthCredentialResponse from './BackupAuthCredentialResponse';

export default class BackupAuthCredentialRequestContext {
	serialized: Uint8Array;

	constructor(contents: Uint8Array) {
		this.serialized = contents;
	}

	static create(
		backupKey: Uint8Array,
		aci: Uuid
	): BackupAuthCredentialRequestContext {
		return new BackupAuthCredentialRequestContext(
			new Uint8Array(
				ReactNativeLibsignalClientModule.backupAuthCredentialRequestContextNew(
					backupKey,
					aci.toString()
				)
			)
		);
	}

	getRequest(): BackupAuthCredentialRequest {
		return new BackupAuthCredentialRequest(
			new Uint8Array(
				ReactNativeLibsignalClientModule.backupAuthCredentialRequestContextGetRequest(
					this.serialized
				)
			)
		);
	}

	receive(
		response: BackupAuthCredentialResponse,
		redemptionTime: number,
		params: GenericServerPublicParams
	): BackupAuthCredential {
		return new BackupAuthCredential(
			new Uint8Array(
				ReactNativeLibsignalClientModule.backupAuthCredentialRequestContextReceiveResponse(
					this.serialized,
					response.serialized,
					redemptionTime,
					params.serialized
				)
			)
		);
	}
}
