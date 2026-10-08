import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';

beforeEach(() => resetForTests());

describe('vault lifecycle', () => {
  it('isUnlocked reports no-vault on a fresh install', async () => {
    const r = await handleMessage({ kind: 'isUnlocked' });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data).toBe('no-vault');
  });

  it('createVault then isUnlocked returns unlocked', async () => {
    const r = await handleMessage({ kind: 'createVault', password: 'pw12345678' });
    expect(r.ok).toBe(true);
    const r1 = await handleMessage({ kind: 'isUnlocked' });
    if (r1.ok) expect(r1.data).toBe('unlocked');
  });

  it('unlock with wrong password fails', async () => {
    await handleMessage({ kind: 'createVault', password: 'right-pass' });
    await handleMessage({ kind: 'lock' });
    const r = await handleMessage({ kind: 'unlock', password: 'wrong-pass' });
    expect(r.ok).toBe(false);
  });

  it('lock wipes state and reports locked', async () => {
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    await handleMessage({ kind: 'lock' });
    const r = await handleMessage({ kind: 'isUnlocked' });
    if (r.ok) expect(r.data).toBe('locked');
  });
});