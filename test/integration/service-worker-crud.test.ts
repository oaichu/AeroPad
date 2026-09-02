import '../helpers/chrome-shim.js';
import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage, resetForTests } from '../../src/background/service-worker.js';
import type { Response } from '../../src/lib/messages.js';

beforeEach(() => resetForTests());

async function bootstrap(): Promise<void> {
  await handleMessage({ kind: 'createVault', password: 'pw' });
}

function data<T>(r: Response): T {
  if (!r.ok) throw new Error(`expected ok, got ${r.error}`);
  return r.data as T;
}

describe('CRUD', () => {
  it('addEntry then getCodes returns it', async () => {
    await bootstrap();
    await handleMessage({
      kind: 'addEntry',
      entry: { issuer: 'GitHub', account: 'me', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
    });
    const r = await handleMessage({ kind: 'getCodes' });
    expect(r.ok).toBe(true);
    const codes = data<unknown[]>(r);
    expect(codes.length).toBe(1);
  });

  it('saveNote then getNotes round-trips', async () => {
    await bootstrap();
    await handleMessage({ kind: 'saveNote', note: { id: 'n1', title: 't', body: 'b', updatedAt: 1 } });
    const r = await handleMessage({ kind: 'getNotes' });
    const notes = data<Array<{ id: string; body: string }>>(r);
    expect(notes[0]!.body).toBe('b');
  });

  it('deleteEntry removes the entry', async () => {
    await bootstrap();
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'A', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'getCodes' });
    const list = data<Array<{ id: string }>>(r);
    await handleMessage({ kind: 'deleteEntry', id: list[0]!.id });
    const r2 = await handleMessage({ kind: 'getCodes' });
    const list2 = data<unknown[]>(r2);
    expect(list2.length).toBe(0);
  });

  it('reorderEntries persists new order', async () => {
    await bootstrap();
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'A', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'B', account: 'b', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'getCodes' });
    const list = data<Array<{ id: string; issuer: string }>>(r);
    const reversed = [list[1]!.id, list[0]!.id];
    await handleMessage({ kind: 'reorderEntries', orderedIds: reversed });
    const r2 = await handleMessage({ kind: 'getCodes' });
    const list2 = data<Array<{ issuer: string }>>(r2);
    expect(list2.map((e) => e.issuer)).toEqual(['B', 'A']);
  });

  it('updateEntry mutates fields and persists', async () => {
    await bootstrap();
    await handleMessage({ kind: 'addEntry', entry: { issuer: 'A', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    const r = await handleMessage({ kind: 'getCodes' });
    const list = data<Array<{ id: string; issuer: string }>>(r);
    await handleMessage({ kind: 'updateEntry', id: list[0]!.id, patch: { issuer: 'X' } });
    const r2 = await handleMessage({ kind: 'getCodes' });
    const list2 = data<Array<{ issuer: string }>>(r2);
    expect(list2[0]!.issuer).toBe('X');
  });

  it('CRUD refuses when locked', async () => {
    const r = await handleMessage({ kind: 'addEntry', entry: { issuer: 'A', account: 'a', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 } });
    expect(r.ok).toBe(false);
  });
});