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
