import { describe, it, expect } from 'vitest';
import { exportVault, importVault } from '../../src/lib/aeropad-format.js';

describe('aeropad format', () => {
  it('exports and re-imports an empty vault', async () => {
    const json = await exportVault({ codes: [], notes: [] }, 'pw');
    const v = await importVault(json, 'pw');
    expect(v).toEqual({ codes: [], notes: [] });
  });

  it('round-trips with entries', async () => {
    const vault = {
      codes: [{ id: 'a', issuer: 'X', account: 'a@x', secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA1' as const, digits: 6 as const, period: 30, createdAt: 1 }],
      notes: [{ id: 'n1', title: 't', body: 'b', updatedAt: 1 }],
    };
    const json = await exportVault(vault, 'pw');
    expect(await importVault(json, 'pw')).toEqual(vault);
  });

  it('rejects wrong password', async () => {
    const json = await exportVault({ codes: [], notes: [] }, 'right');
    await expect(importVault(json, 'wrong')).rejects.toThrow();
  });

  it('rejects malformed JSON', async () => {
    await expect(importVault('not json', 'pw')).rejects.toThrow();
  });
});