import { describe, it, expect, beforeEach } from 'vitest';
import { detectTwoFactorInputs, matches2FA } from '../../src/content/detector.js';

describe('matches2FA', () => {
  it('matches autocomplete=one-time-code', () => {
    const el = document.createElement('input');
    el.setAttribute('autocomplete', 'one-time-code');
    expect(matches2FA(el)).toBe(true);
  });

  it('matches numeric inputmode after a password field', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="pw">
        <input inputmode="numeric" name="code">
      </form>`;
    const form = document.querySelector('form')!;
    const pw = form.querySelector<HTMLInputElement>('input[type=password]')!;
    const code = form.querySelector<HTMLInputElement>('input[name=code]')!;
    expect(matches2FA(code, form, pw)).toBe(true);
  });

  it('matches by name pattern', () => {
    const el = document.createElement('input');
    el.name = 'totp_code';
    expect(matches2FA(el)).toBe(true);
  });

  it('does not match an unrelated text input', () => {
    const el = document.createElement('input');
    el.type = 'text';
    el.name = 'q';
    expect(matches2FA(el)).toBe(false);
  });
});

describe('detectTwoFactorInputs', () => {
  beforeEach(() => { document.body.innerHTML = ''; });
  it('finds the input in the document', () => {
    document.body.innerHTML = `<input autocomplete="one-time-code">`;
    const found = detectTwoFactorInputs();
    expect(found.length).toBe(1);
  });
});