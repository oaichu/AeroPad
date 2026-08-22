/**
 * OTPAuth URI Builder & Parser (RFC 6238 / Key URI Format)
 */

export function buildOTPAuthURI(options = {}) {
  const {
    issuer = 'AetherPad',
    account = 'user',
    secret = '',
    digits = 6,
    period = 30,
    algo = 'SHA1'
  } = options;

  const encIssuer = encodeURIComponent(issuer.trim());
  const encAccount = encodeURIComponent(account.trim());
  const cleanSecret = secret.replace(/[\s-]/g, '').toUpperCase();

  return `otpauth://totp/${encIssuer}:${encAccount}?secret=${cleanSecret}&issuer=${encIssuer}&algorithm=${algo}&digits=${digits}&period=${period}`;
}

const MIN_PERIOD = 1;
const MAX_PERIOD = 3600;

function invalid(errorCode, error) {
  return { isValid: false, errorCode, error };
}

function normalizeSecret(value) {
  const cleaned = String(value).replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(cleaned)) {
    return null;
  }

  const unpadded = cleaned.replace(/=+$/, '');
  return /^[A-Z2-7]{8,128}$/.test(unpadded) ? unpadded : null;
}

function normalizeAlgorithm(value) {
  const normalized = String(value).toUpperCase().replace(/-/g, '');
  if (normalized === 'SHA1' || normalized === 'SHA256' || normalized === 'SHA512') {
    return normalized;
  }
  return null;
}

function parseIntegerParam(url, name, defaultValue, min, max, errorCode) {
  const raw = url.searchParams.get(name);
  if (raw === null) {
    return { value: defaultValue };
  }

  if (!/^\d+$/.test(raw)) {
    return { error: invalid(errorCode, `Invalid ${name} parameter`) };
  }

  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    return { error: invalid(errorCode, `Invalid ${name} parameter`) };
  }

  return { value };
}

export function parseOTPAuthURI(input) {
  if (!input || typeof input !== 'string') {
    return invalid('empty_input', 'Empty input');
  }

  const trimmed = input.trim();

  // If input is a standard URI
  if (trimmed.toLowerCase().startsWith('otpauth://')) {
    try {
      const url = new URL(trimmed);
      if (url.protocol.toLowerCase() !== 'otpauth:') {
        return invalid('invalid_protocol', 'Invalid protocol');
      }

      if (url.hostname.toLowerCase() !== 'totp' || url.port) {
        return invalid('unsupported_type', 'Only otpauth://totp/... URIs are supported');
      }

      const label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
      const separator = label.indexOf(':');
      const labelIssuer = separator === -1 ? '' : label.slice(0, separator);
      const labelAccount = separator === -1 ? label : label.slice(separator + 1);

      const issuer = url.searchParams.get('issuer')?.trim() || labelIssuer || 'Custom 2FA';
      const account = labelAccount || 'User';

      const secretParam = url.searchParams.get('secret');
      if (secretParam === null || secretParam.trim() === '') {
        return invalid('missing_secret', 'Missing secret parameter');
      }

      const secret = normalizeSecret(secretParam);
      if (!secret) {
        return invalid('invalid_secret', 'Invalid Base32 secret');
      }

      const algorithmParam = url.searchParams.get('algorithm');
      const algo = normalizeAlgorithm(algorithmParam === null ? 'SHA1' : algorithmParam);
      if (!algo) {
        return invalid('unsupported_algorithm', 'Unsupported algorithm');
      }

      const digitsResult = parseIntegerParam(url, 'digits', 6, 6, 8, 'invalid_digits');
      if (digitsResult.error) {
        return digitsResult.error;
      }

      if (digitsResult.value !== 6 && digitsResult.value !== 8) {
        return invalid('invalid_digits', 'Digits must be 6 or 8');
      }

      const periodResult = parseIntegerParam(url, 'period', 30, MIN_PERIOD, MAX_PERIOD, 'invalid_period');
      if (periodResult.error) {
        return periodResult.error;
      }

      return {
        isValid: true,
        type: 'totp',
        issuer,
        account,
        secret,
        digits: digitsResult.value,
        period: periodResult.value,
        algo
      };
    } catch {
      return invalid('invalid_uri', 'Invalid URI');
    }
  }

  // Check if raw input is a Base32 string
  const cleanBase32 = normalizeSecret(trimmed);
  if (cleanBase32) {
    return {
      isValid: true,
      type: 'totp',
      issuer: 'Direct Key',
      account: 'Account',
      secret: cleanBase32,
      digits: 6,
      period: 30,
      algo: 'SHA1'
    };
  }

  return invalid('unrecognized_format', 'Unrecognized format');
}
