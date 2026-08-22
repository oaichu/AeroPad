# TOTP and OTPAuth Contract

## Canonical account policy

```text
secret: uppercase Base32 A–Z and 2–7, 8–128 characters after separator cleanup
generated secret: 32 Base32 characters (160 bits)
digits: 6 or 8 only
period: integer seconds from 1 through 3600; default 30
algorithm: SHA1, SHA256, or SHA512; default SHA1 when the URI omits it
type: totp only
```

Imports retain valid legacy secret lengths for interoperability. The generator, placeholder, and product copy use 32 characters. The generator uses Web Crypto CSPRNG bytes and does not use `Math.random`.

## URI parsing

`parseOTPAuthURI(input)` accepts a trimmed `otpauth://` URI or a direct Base32 secret. URI parsing is strict:

1. The protocol must be `otpauth:`.
2. The host must be `totp`, case-insensitively.
3. `otpauth://hotp/...` returns `{ isValid: false, errorCode: "unsupported_type" }`. It is never interpreted as TOTP.
4. The label is decoded once. A label issuer/account pair is parsed by the first `:`; an explicit `issuer` query parameter overrides the label issuer only when valid.
5. `secret` is canonicalized to uppercase after removing spaces, hyphens, and optional Base32 padding, then validated against the alphabet and length bounds.
6. `algorithm`, `digits`, and `period` are validated when present. Invalid values return an error; they do not fall back to SHA-1, 6 digits, or 30 seconds.

The parser returns canonical fields:

```js
{
  isValid: true,
  type: 'totp',
  issuer: 'Example',
  account: 'user@example.com',
  secret: 'JBSWY3DPEHPK3PXP',
  digits: 6,
  period: 30,
  algo: 'SHA1'
}
```

Invalid results include a stable `errorCode` from `empty_input`, `invalid_protocol`, `unsupported_type`, `missing_secret`, `invalid_secret`, `unsupported_algorithm`, `invalid_digits`, or `invalid_period`.

## Algorithm normalization

`normalizeAlgorithm(input)` accepts case-insensitive `SHA1`, `SHA-1`, `SHA256`, `SHA-256`, `SHA512`, or `SHA-512` and returns the Web Crypto name `SHA-1`, `SHA-256`, or `SHA-512`. Any other value throws/returns `unsupported_algorithm`; it never becomes SHA-1.

## TOTP engine

The engine computes RFC 6238 dynamic truncation with an unsigned 8-byte big-endian counter:

```text
windowIndex = floor(timestampSeconds / account.period)
counter = uint64be(windowIndex)
HMAC = HMAC(account.algorithm, decodedSecret, counter)
offset = HMAC[lastByte] & 0x0f
binary = 31-bit dynamic-truncation value
code = binary mod 10^digits, left padded to digits
```

The engine validates all options before Web Crypto. A malformed secret or unsupported option returns an unavailable-code result; the UI displays `------` and never presents a fabricated OTP.

## Refresh engine

Each account owns its own refresh state:

```js
windowIndex = Math.floor(nowSeconds / account.period)
remaining = account.period - (nowSeconds % account.period)
progress = remaining / account.period * 100
```

The timer updates countdown/progress every second and regenerates only accounts whose `windowIndex` changed. A visibility return forces a refresh for every account. There is no global 30-second regeneration gate. Decoder preview uses the same account policy as the vault card.

Cards display the canonical algorithm, digit count, and period. The global header may show “live” but must not label every account as HMAC-SHA1 or 30 seconds.

## QR input bounds

Image decoding accepts image MIME types only. Images are decoded with `createImageBitmap` when available and downsampled so the longest edge is at most 2048px before RGBA extraction. A rejected image shows a recoverable error and does not allocate a full 4096×4096 pixel buffer. QR decode output is passed through the strict URI parser above.

## Local search

Note search remains local and in-memory. Input is debounced by 125ms; the cached corpus uses Unicode NFD plus diacritic removal and lowercase matching. Title matches score above content matches. Search never sends note text to a server and does not persist a plaintext index after lock.
