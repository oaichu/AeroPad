import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import {
  getVaultBlob, setVaultBlob, getDeviceList, setDeviceList, getSessionLock, setSessionLock,
} from '../../src/lib/storage.js';

beforeEach(() => {
  (globalThis as any).chrome.storage.local.remove('vaultBlob');
});

describe('storage', () => {
  it('vaultBlob round-trips', async () => {
    expect(await getVaultBlob()).toBeNull();
    const blob = { v: 1 as const, salt: 'aa', iv: 'bb', ciphertext: 'cc' };
    await setVaultBlob(blob);
    expect(await getVaultBlob()).toEqual(blob);
  });

  it('deviceList round-trips through sync', async () => {
    await setDeviceList([{ id: 'd1', name: 'PC', lastSeen: 1 }]);
    expect(await getDeviceList()).toEqual([{ id: 'd1', name: 'PC', lastSeen: 1 }]);
  });

  it('sessionLock defaults to 15 minutes', async () => {
    expect(await getSessionLock()).toEqual({ lastUnlockedAt: 0, autoLockMinutes: 15 });
  });
});