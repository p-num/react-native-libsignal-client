export function throwsSync(p: () => unknown): boolean {
	try {
		p();
		return false;
	} catch {
		return true;
	}
}

export async function throwsAsync(p: () => Promise<unknown>): Promise<boolean> {
	try {
		await p();
		return false;
	} catch {
		return true;
	}
}

export function noThrowSync(p: () => unknown): boolean {
	try {
		p();
		return true;
	} catch {
		return false;
	}
}

export function noThrowAsync(p: () => Promise<unknown>): Promise<boolean> {
	return p().then(
		() => true,
		() => false
	);
}

export function assertThrows(
	p: () => Promise<unknown>,
	msg?: string
): Promise<void>;
export function assertThrows(p: () => unknown, msg?: string): void;
export function assertThrows(
	p: (() => unknown) | (() => Promise<unknown>),
	msg?: string
): void | Promise<void> {
	const errorMessage =
		msg ?? 'Expected function to throw, but it completed successfully.';
	try {
		const ret = p();
		if (ret instanceof Promise) {
			return ret.then(
				() => {
					throw new Error(errorMessage);
				},
				() => {
					// Expected throw, so do nothing.
				}
			);
		}
	} catch (e) {
		// Sync function threw, this is the expected behavior.
		return;
	}

	// Sync function did not throw, this is an error.
	throw new Error(errorMessage);
}
