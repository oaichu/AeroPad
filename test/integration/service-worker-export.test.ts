import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';
import type { Response } from '../../src/lib/messages.js';

beforeEach(() => resetForTests());

function data<T>(r: Response): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error}`);
  return r.data as T;
}

describe('export/import', () => {
  it('exportAeropad → importAeropad round-trips', async () => {
    await handleMessage({ kind: 'createVault', password: 'pw' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'exportAeropad', password: 'pw' });
    expect(r.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    const json = data<string>(r);
    const imp = await handleMessage({ kind: 'importAeropad', json, password: 'pw', strategy: 'replace' });
    expect(imp.ok).toBe(true);
    const r2 = await handleMessage({ kind: 'getCodes' });
    const codes = data<unknown[]>(r2);
    expect(codes.length).toBe(1);
  });

  it('changeMasterPassword re-encrypts', async () => {
    await handleMessage({ kind: 'createVault', password: 'old' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'changeMasterPassword', oldPassword: 'old', newPassword: 'new' });
    expect(r.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    const u = await handleMessage({ kind: 'unlock', password: 'new' });
    expect(u.ok).toBe(true);
    const r2 = await handleMessage({ kind: 'getCodes' });
    const codes = data<unknown[]>(r2);
    expect(codes.length).toBe(1);
  });

  it('changeMasterPassword rejects wrong old password (Ruling 2)', async () => {
    await handleMessage({ kind: 'createVault', password: 'correct' });
    const r = await handleMessage({ kind: 'changeMasterPassword', oldPassword: 'wrong', newPassword: 'new' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('wrong_password');
    await handleMessage({ kind: 'lock' });
    const u = await handleMessage({ kind: 'unlock', password: 'correct' });
    expect(u.ok).toBe(true);
  });

  it('fillOnTab sends fill_command to the content script', async () => {
    await handleMessage({ kind: 'createVault', password: 'pw' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'getCodes' });
    const list = data<Array<{ id: string }>>(r);
    const f = await handleMessage({ kind: 'fillOnTab', tabId: 42, entryId: list[0]!.id });
    expect(f.ok).toBe(true);
  });
});