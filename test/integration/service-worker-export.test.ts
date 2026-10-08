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
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'exportAeropad', password: 'password-1' });
    expect(r.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    const json = data<string>(r);
    const imp = await handleMessage({ kind: 'importAeropad', json, password: 'password-1', strategy: 'replace' });
    expect(imp.ok).toBe(true);
    const r2 = await handleMessage({ kind: 'getCodes' });
    const codes = data<unknown[]>(r2);
    expect(codes.length).toBe(1);
  });

  it('changeMasterPassword re-encrypts', async () => {
    await handleMessage({ kind: 'createVault', password: 'old-pass-1' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'changeMasterPassword', oldPassword: 'old-pass-1', newPassword: 'new-pass-1' });
    expect(r.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    const u = await handleMessage({ kind: 'unlock', password: 'new-pass-1' });
    expect(u.ok).toBe(true);
    const r2 = await handleMessage({ kind: 'getCodes' });
    const codes = data<unknown[]>(r2);
    expect(codes.length).toBe(1);
  });

  it('changeMasterPassword rejects wrong old password (Ruling 2)', async () => {
    await handleMessage({ kind: 'createVault', password: 'correct-pw' });
    const r = await handleMessage({ kind: 'changeMasterPassword', oldPassword: 'wrong', newPassword: 'new' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('wrong_password');
    await handleMessage({ kind: 'lock' });
    const u = await handleMessage({ kind: 'unlock', password: 'correct-pw' });
    expect(u.ok).toBe(true);
  });

  it('exportAeropad requires a real password (no constant fallback)', async () => {
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    const r = await handleMessage({ kind: 'exportAeropad' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('export_password_required');
    const r2 = await handleMessage({ kind: 'exportAeropad', password: 'short' });
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.error).toBe('export_password_required');
  });

  it('unlocked replace-import keeps the existing master password', async () => {
    await handleMessage({ kind: 'createVault', password: 'vault-pw-1' });
    // Export a DIFFERENT vault's backup (password 'backup-pw')
    const backup = await handleMessage({ kind: 'exportAeropad', password: 'backup-pw' });
    expect(backup.ok).toBe(true);
    const imp = await handleMessage({ kind: 'importAeropad', json: data<string>(backup), password: 'backup-pw', strategy: 'replace' });
    expect(imp.ok).toBe(true);
    await handleMessage({ kind: 'lock' });
    // Master password must NOT have silently become 'backup-pw'.
    expect((await handleMessage({ kind: 'unlock', password: 'backup-pw' })).ok).toBe(false);
    expect((await handleMessage({ kind: 'unlock', password: 'vault-pw-1' })).ok).toBe(true);
  });

  it('rejects a backup file with out-of-range KDF iterations', async () => {
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    const r = await handleMessage({ kind: 'exportAeropad', password: 'password-1' });
    const file = JSON.parse(data<string>(r));
    file.kdf.iter = 2_000_000_000;
    const imp = await handleMessage({ kind: 'importAeropad', json: JSON.stringify(file), password: 'password-1', strategy: 'replace' });
    expect(imp.ok).toBe(false);
    if (!imp.ok) expect(imp.error).toBe('Unsupported KDF iterations');
  });

  it('rejects a backup whose decrypted vault has malformed entries', async () => {
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    const { exportVault } = await import('../../src/lib/aeropad-format.js');
    const json = await exportVault({ codes: [{ id: 1 } as never], notes: [] }, 'password-1');
    const imp = await handleMessage({ kind: 'importAeropad', json, password: 'password-1', strategy: 'replace' });
    expect(imp.ok).toBe(false);
    if (!imp.ok) expect(imp.error).toBe('Invalid vault structure');
  });

  it('updateEntry rejects a patch that breaks entry invariants', async () => {
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const codes = data<Array<{ id: string }>>(await handleMessage({ kind: 'getCodes' }));
    const r = await handleMessage({ kind: 'updateEntry', id: codes[0]!.id, patch: { period: 0 } });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('invalid_entry');
  });

  it('fillOnTab sends fill_command to the content script', async () => {
    await handleMessage({ kind: 'createVault', password: 'password-1' });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'getCodes' });
    const list = data<Array<{ id: string }>>(r);
    const f = await handleMessage({ kind: 'fillOnTab', tabId: 42, entryId: list[0]!.id });
    expect(f.ok).toBe(true);
  });
});