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

export function parseOTPAuthURI(input) {
  if (!input || typeof input !== 'string') {
    return { isValid: false, error: 'Empty input' };
  }

  const trimmed = input.trim();

  // If input is a standard URI
  if (trimmed.startsWith('otpauth://')) {
    try {
      const url = new URL(trimmed);
      if (url.protocol !== 'otpauth:') {
        return { isValid: false, error: 'Invalid protocol' };
      }

      // url.host might be 'totp' and url.pathname might be '/Google:user@gmail.com'
      let label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
      if (!label && url.host && url.host !== 'totp') {
        label = decodeURIComponent(url.host);
      }
      // If label starts with totp/ strip it
      label = label.replace(/^totp\//i, '');

      let issuer = url.searchParams.get('issuer') || '';
      let account = 'User';

      if (label.includes(':')) {
        const parts = label.split(':');
        issuer = issuer || parts[0];
        account = parts.slice(1).join(':');
      } else if (label) {
        account = label;
      }

      if (!issuer) {
        issuer = 'Custom 2FA';
      }

      const secret = (url.searchParams.get('secret') || '').replace(/[\s-]/g, '').toUpperCase();
      if (!secret) {
        return { isValid: false, error: 'Missing secret parameter' };
      }

      const digits = parseInt(url.searchParams.get('digits') || '6', 10);
      const period = parseInt(url.searchParams.get('period') || '30', 10);
      const algo = url.searchParams.get('algorithm') || 'SHA-1';

      return {
        isValid: true,
        type: 'totp',
        issuer,
        account,
        secret,
        digits,
        period,
        algo
      };
    } catch (err) {
      return { isValid: false, error: err.message };
    }
  }

  // Check if raw input is a Base32 string
  const cleanBase32 = trimmed.replace(/[\s-]/g, '').toUpperCase();
  if (/^[A-Z2-7]{16,64}$/.test(cleanBase32)) {
    return {
      isValid: true,
      type: 'totp',
      issuer: 'Direct Key',
      account: 'Account',
      secret: cleanBase32,
      digits: 6,
      period: 30,
      algo: 'SHA-1'
    };
  }

  return { isValid: false, error: 'Unrecognized format' };
}
