// src/lib/storage.ts
import type { VaultBlob, VaultMeta, Device } from '../types/index.js';

const LOCAL = chrome.storage.local;
const SYNC = chrome.storage.sync;

export async function getVaultBlob(): Promise<VaultBlob | null> {
  const r = await LOCAL.get('vaultBlob');
  return (r.vaultBlob as VaultBlob | undefined) ?? null;
}
export async function setVaultBlob(b: VaultBlob): Promise<void> {
  await LOCAL.set({ vaultBlob: b });
}

export async function getVaultMeta(): Promise<VaultMeta | null> {
  const r = await LOCAL.get('vaultMeta');
  return (r.vaultMeta as VaultMeta | undefined) ?? null;
}
export async function setVaultMeta(m: VaultMeta): Promise<void> {
  await LOCAL.set({ vaultMeta: m });
}

export async function getDeviceList(): Promise<Device[]> {
  const r = await SYNC.get('deviceList');
  return (r.deviceList as Device[] | undefined) ?? [];
}
export async function setDeviceList(devices: Device[]): Promise<void> {
  await SYNC.set({ deviceList: devices });
}

const DEFAULT_LOCK = { lastUnlockedAt: 0, autoLockMinutes: 15 };

export async function getSessionLock(): Promise<typeof DEFAULT_LOCK> {
  const r = await LOCAL.get('sessionLock');
  return (r.sessionLock as typeof DEFAULT_LOCK | undefined) ?? DEFAULT_LOCK;
}
export async function setSessionLock(s: typeof DEFAULT_LOCK): Promise<void> {
  await LOCAL.set({ sessionLock: s });
}