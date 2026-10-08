// src/content/detector.ts
// Detects 2FA inputs on the page and injects an inline fill button next to each one.
// On click, the button asks the SW (via `fill_request`) for a code; if the SW
// returns a `fill_command`, the value is written and input/change events are
// dispatched. If the SW returns no match, the click is a no-op (the user can
// open the toolbar popup manually).
const NAME_PATTERN = /otp|2fa|token|code|verification/i;

export function matches2FA(
  el: HTMLInputElement,
  form?: HTMLFormElement | null,
  passwordEl?: HTMLInputElement | null,
): boolean {
  if (el.autocomplete === 'one-time-code') return true;
  if (el.getAttribute('autocomplete') === 'one-time-code') return true;
  if (form && passwordEl && el.inputMode === 'numeric') {
    const children = Array.from(form.elements) as HTMLElement[];
    const pwIdx = children.indexOf(passwordEl);
    const elIdx = children.indexOf(el);
    if (pwIdx >= 0 && elIdx > pwIdx) return true;
  }
  if (NAME_PATTERN.test(el.name) || NAME_PATTERN.test(el.id)) return true;
  return false;
}

export function detectTwoFactorInputs(root: ParentNode = document): HTMLInputElement[] {
  const inputs = Array.from(root.querySelectorAll<HTMLInputElement>('input'));
  return inputs.filter((el) => {
    if (!el.type || el.type === 'password' || el.type === 'hidden') return false;
    const form = el.form;
    const passwordEl = form?.querySelector<HTMLInputElement>('input[type=password]') ?? null;
    return matches2FA(el, form, passwordEl);
  });
}

function injectIcon(input: HTMLInputElement): void {
  if (input.dataset['aeropadIconInjected']) return;
  input.dataset['aeropadIconInjected'] = '1';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = '\u{1F510}'; // key icon
  btn.style.cssText = 'margin-left:6px;cursor:pointer;background:transparent;border:0;font-size:14px;vertical-align:middle';
  btn.title = 'Fill from AeroPad';
  btn.setAttribute('aria-label', 'Fill from AeroPad');
  btn.addEventListener('click', async (ev) => {
    ev.preventDefault();
    try {
      const resp = await chrome.runtime.sendMessage({
        kind: 'fill_request',
        tabId: 0,
        fieldSelector: input.name || input.id,
        domain: location.hostname,
      });
      if (resp && typeof resp === 'object') {
        const payload = ('data' in resp && resp.data && typeof resp.data === 'object')
          ? resp.data
          : resp;
        if ('kind' in payload && payload.kind === 'fill_command') {
          const code = (payload as { code?: unknown }).code;
          if (typeof code === 'string') {
            input.value = code;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            btn.remove();
          }
        }
        // fill_request_multiple / fill_request_none: no auto-fill;
        // the user opens the toolbar popup manually if they want to choose.
      }
    } catch {
      // SW not reachable (e.g. locked); the toolbar popup is the fallback path.
    }
  });
  input.insertAdjacentElement('afterend', btn);
}

function fillInto(input: HTMLInputElement, code: string): void {
  input.value = code;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  input.focus();
}

// Receives fill_command from the service worker (popup "fill" action and the
// fill-current keyboard command) and writes the code into the best field:
// the focused eligible input if any, otherwise the first detected 2FA input.
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((msg: unknown) => {
    if (typeof msg !== 'object' || msg === null) return;
    const m = msg as { kind?: unknown; code?: unknown };
    if (m.kind !== 'fill_command' || typeof m.code !== 'string') return;
    const active = document.activeElement;
    if (active instanceof HTMLInputElement && matches2FA(active, active.form, active.form?.querySelector('input[type=password]') ?? null)) {
      fillInto(active, m.code);
      return;
    }
    const target = detectTwoFactorInputs()[0];
    if (target) fillInto(target, m.code);
  });
}

const observer = new MutationObserver((mutations) => {
  if (!mutations.some((m) => m.addedNodes.length > 0)) return;
  for (const el of detectTwoFactorInputs()) injectIcon(el);
});

function start(): void {
  observer.observe(document.body, { childList: true, subtree: true });
  for (const el of detectTwoFactorInputs()) injectIcon(el);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}

window.addEventListener('pagehide', () => observer.disconnect());