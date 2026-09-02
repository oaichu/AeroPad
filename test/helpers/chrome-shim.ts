let store: Record<string, unknown> = {};
(globalThis as any).chrome = {
  storage: {
    local: {
      get: (k: string | string[]) => Promise.resolve(
        Array.isArray(k)
          ? Object.fromEntries(k.map((key) => [key, store[key]]))
          : { [k]: store[k] }),
      set: (o: Record<string, unknown>) => { Object.assign(store, o); return Promise.resolve(); },
      remove: (k: string) => { delete store[k]; return Promise.resolve(); },
    },
    sync: {
      get: (k: string | string[]) => Promise.resolve(
        Array.isArray(k)
          ? Object.fromEntries(k.map((key) => [key, store['sync:' + key]]))
          : { [k]: store['sync:' + k] }),
      set: (o: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(o)) store['sync:' + k] = v;
        return Promise.resolve();
      },
    },
  },
};