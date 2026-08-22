/**
 * Base32 RFC 4648 Encoding & Decoding Utility
 */
export const Base32 = {
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',

  decode(input) {
    if (!input || typeof input !== 'string') {
      return new Uint8Array(0).buffer;
    }
    const cleanInput = input.toUpperCase().replace(/[\s=-]/g, '');
    const length = cleanInput.length;
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array(Math.floor((length * 5) / 8));

    for (let i = 0; i < length; i++) {
      const char = cleanInput[i];
      const val = this.alphabet.indexOf(char);
      if (val === -1) {
        // Invalid character: reject the whole input. Silently skipping would
        // produce a different key than the user intended (wrong codes forever).
        return new Uint8Array(0).buffer;
      }

      value = (value << 5) | val;
      bits += 5;

      if (bits >= 8) {
        output[index++] = (value >>> (bits - 8)) & 255;
        bits -= 8;
      }
    }
    return output.buffer;
  },

  encode(buffer) {
    if (!buffer) return '';
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;

      while (bits >= 5) {
        output += this.alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += this.alphabet[(value << (5 - bits)) & 31];
    }
    return output;
  },

  randomSecret(length = 16) {
    let result = '';
    const bytes = new Uint8Array(length);
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(bytes);
    } else {
      // TOTP secrets must never come from Math.random — fail loudly instead.
      throw new Error('No cryptographically secure RNG available in this environment');
    }
    for (let i = 0; i < length; i++) {
      result += this.alphabet[bytes[i] % this.alphabet.length];
    }
    return result;
  }
};
