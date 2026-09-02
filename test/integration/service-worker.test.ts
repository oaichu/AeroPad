import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';

beforeEach(() => resetForTests());

describe('vault lifecycle', () => {
  it('createVault then isUnlocked', async () => {
    const r0 = await handleMessage({ kind: 'isUnlocked' });
    expect(r0.ok).toBe(true);
    if (r0.ok) expect(r0.data).toBe(false);
    const r = await handleMessage({ kind: 'createVault', password: 'pw12345678' });
    expect(r.ok).toBe(true);
    const r1 = await handleMessage({ kind: 'isUnlocked' });
    if (r1.ok) expect(r1.data).toBe(true);
  });

  it('unlock with wrong password fails', async () => {
    await handleMessage({ kind: 'createVault', password: 'right' });
    await handleMessage({ kind: 'lock' });
    const r = await handleMessage({ kind: 'unlock', password: 'wrong' });
    expect(r.ok).toBe(false);
  });

  it('lock wipes state', async () => {
    await handleMessage({ kind: 'createVault', password: 'pw' });
    await handleMessage({ kind: 'lock' });
    const r = await handleMessage({ kind: 'isUnlocked' });
    if (r.ok) expect(r.data).toBe(false);
  });
});