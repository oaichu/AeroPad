# Vault v2 Schema and Commit Contract

## Storage backend

The durable vault uses IndexedDB:

- Database: `aeropad-vault`
- Database version: `1`
- Object store: `vault`
- Key path: `id`
- Current record key: `current`
- Transaction mode for commits: `readwrite`
- Transaction scope: `vault` only

The current record is one value. IndexedDB transaction completion is the commit point; there is no separate notes/TOTP manifest that can advance independently.

## Current record envelope

The record has this shape:

```json
{
  "id": "current",
  "format": "aeropad-vault",
  "version": 2,
  "generation": 14,
  "kdf": {
    "name": "PBKDF2-SHA256",
    "iterations": 600000,
    "salt": "base64-16-byte-salt"
  },
  "cipher": {
    "name": "AES-256-GCM",
    "iv": "base64-12-byte-iv",
    "aad": "AeroPad|vault|v2|generation=14"
  },
  "ciphertext": "base64-ciphertext-with-auth-tag"
}
```

The AAD string is encoded as UTF-8 and supplied to Web Crypto for both encryption and decryption. The generation in the AAD must equal the record generation. Every commit uses a fresh 12-byte IV and the same 16-byte salt for the active password generation.

## Decrypted payload

The ciphertext decodes to exactly one JSON object:

```json
{
  "schemaVersion": 2,
  "notes": [
    {
      "id": "note-...",
      "title": "Example",
      "content": "...",
      "tags": ["ops"],
      "updatedAt": 1755800000000
    }
  ],
  "totpAccounts": [
    {
      "id": "totp-...",
      "issuer": "Example",
      "account": "user@example.com",
      "secret": "JBSWY3DPEHPK3PXP",
      "password": "optional-account-password",
      "digits": 6,
      "period": 30,
      "algo": "SHA1"
    }
  ],
  "metadata": {
    "createdAt": 1755800000000,
    "updatedAt": 1755800000000
  }
}
```

`password` is optional and is encrypted with the rest of the payload. It must never be written to a separate plaintext store. `algo` is canonical storage spelling: `SHA1`, `SHA256`, or `SHA512`.

## Bounds and validation

Validation runs before KDF or AES work. Invalid data is rejected with a user-visible recovery error and is never coerced to an empty array.

- `format` must equal `aeropad-vault`.
- `version` and `schemaVersion` must equal `2`.
- `generation` is an integer from `1` through `Number.MAX_SAFE_INTEGER`.
- `kdf.name` must equal `PBKDF2-SHA256`; `iterations` is an integer from `600000` through `2000000`.
- Decoded salt is exactly 16 bytes; decoded IV is exactly 12 bytes.
- Decoded ciphertext is at least 16 bytes and at most 16 MiB.
- `notes` has at most 2,000 entries; each title is at most 512 UTF-16 code units; each content is at most 1 MiB; tags contain at most 32 values of at most 64 code units.
- `totpAccounts` has at most 1,000 entries; issuer/account are at most 256 code units; secret is canonical Base32 of 8–128 characters; password is at most 1,024 code units.
- TOTP `digits`, `period`, and `algo` follow [`totp-otpauth.md`](totp-otpauth.md).

Base64 decoding must reject malformed input rather than accepting partial bytes. The parser must not call `deriveKey` until every bound has passed.

## Atomic commit protocol

1. The UI snapshots the in-memory payload using a structured clone-safe value.
2. The storage queue assigns `nextGeneration = lastCommittedGeneration + 1`.
3. The crypto layer validates the payload, creates the envelope, derives/encrypts with the exact AAD, and returns the candidate record.
4. The store opens one `readwrite` transaction on `vault` and executes `put(candidate, "current")`.
5. The queue resolves `flush()` only from transaction completion, then updates `lastCommittedGeneration` and the UI state to `committed`.
6. If encryption or the transaction fails, the previous record remains current, `flush()` rejects, and the UI reports `save-failed` with a retry/export action.

Autosave calls are serialized and coalesced. `lock()` awaits `flush()`. It must not reload or clear `vaultKey` while a commit is pending.

## Encrypted backup format

An exported `.aeropad` file is UTF-8 JSON with this outer shape:

```json
{
  "format": "aeropad-backup",
  "version": 1,
  "createdAt": 1755800000000,
  "envelope": { "id": "current", "format": "aeropad-vault" },
  "checksum": {
    "algorithm": "SHA-256",
    "value": "hex-digest-of-canonical-envelope-json"
  }
}
```

The complete v2 envelope is stored in `envelope`; the shortened object above only illustrates the shape. The checksum is calculated over `JSON.stringify(envelope)` with the schema property order and is used to detect corruption, not as an authenticity substitute for AES-GCM. Import verifies outer format, version, checksum, envelope bounds, and password before replacing the current record in one IndexedDB transaction.

## Legacy migration

The migration reader may inspect `aeropad_notes`, `aeropad_totp`, and their existing corrupt backups once. It must preserve the raw values until the first v2 transaction completes.

- Two valid plaintext arrays are imported into one in-memory payload and require a master password before the first v2 commit.
- Two valid legacy envelopes are decrypted only after password verification. Their salt, iteration count, and ciphertext are independently validated.
- A mixed generation, one-sided envelope, malformed value, or plaintext corrupt backup is reported as `legacy-recovery-required`; the missing side is never treated as `[]`.
- After a successful v2 commit, old keys are removed on a best-effort basis and the UI explains that browser secure erase cannot be guaranteed.

## Key lifecycle and storage status

The derived AES key is non-extractable and held in memory only. Locking clears the reference, password inputs, revealed secret/password text, decoder state, and active account payload. JavaScript cannot guarantee physical memory erasure, so the product wording must say “cleared from the active session,” not “securely erased.”

On boot the app calls `navigator.storage.persist()` when available and records whether the browser granted persistence. This is a durability hint, not a guarantee against user deletion or browser policy eviction.

The default inactivity lock is 15 minutes. User activity resets the timer; `visibilitychange` refreshes the UI and immediately checks the lock deadline.
