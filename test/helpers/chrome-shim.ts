let store: Record<string, unknown> = {};
type ChromeListener = (...args: unknown[]) => unknown;
const listeners: ChromeListener[] = [];
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
  runtime: {
    getURL: (path: string) => path,
    onMessage: {
      addListener: (fn: ChromeListener) => { listeners.push(fn); },
      removeListener: (fn: ChromeListener) => {
        const i = listeners.indexOf(fn);
        if (i >= 0) listeners.splice(i, 1);
      },
      _listeners: listeners,
    },
    sendMessage: (msg: unknown) => {
      // dispatch to the most recently added listener, like Chrome's fan-out,
      // but tests can also invoke the registered listener directly.
      const last = listeners[listeners.length - 1];
      return last?.(msg, {}, () => {});
    },
  },
  tabs: {
    sendMessage: (_tabId: number, _msg: unknown) => Promise.resolve(),
  },
};