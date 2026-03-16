/**
 * ecchimail.ts — ECCHImail v2 mail composition and opening
 *
 * Mail wire format (minimum 262 bytes):
 *
 *   ┌─────────────────┬────────┐
 *   │ Field           │ Size   │
 *   ├─────────────────┼────────┤
 *   │ Sender addr A   │ 65 B   │  0x04 ‖ Ax ‖ Ay
 *   │ Recipient addr Y│ 65 B   │  0x04 ‖ Yx ‖ Yy
 *   │ Key material f  │ 32 B   │  big-endian scalar
 *   │ Timestamp       │  8 B   │  Unix seconds, big-endian uint64
 *   │ IV              │ 12 B   │  AES-256-GCM nonce
 *   │ Ciphertext      │ var    │  encrypted plaintext
 *   │ Auth tag        │ 16 B   │  GCM authentication tag
 *   │ Schnorr sig     │ 64 B   │  Rx ‖ s over message_id
 *   └─────────────────┴────────┘
 *
 * message_id = SHA-256(timestamp ‖ min(A,Y) ‖ max(A,Y) ‖ IV)
 *   where min/max are determined by lexicographic byte comparison.
 *
 * AES key derivation:
 *   IKM  = S.x  (32-byte X-coord of ECDH shared secret)
 *   salt = SHA-256(A ‖ Y ‖ f_bytes)
 *   info = "ECCHImail-v2"
 *   out  = 32 bytes  →  AES-256-GCM key
 */

import {
  G, N,
  randomScalar,
  scalarMul,
  pointAdd,
  encodePoint,
  decodePoint,
  isValidPoint,
  bigIntToBytes,
  bytesToBigInt,
  type Point,
} from './p-256';
import {
  sha256Hash,
  hkdf,
  aesGcmEncrypt,
  aesGcmDecrypt,
  randomBytes,
} from './cipher';
import { schnorrSign, schnorrVerify } from './ecsh';

// ---------------------------------------------------------------------------
// Offsets and sizes
// ---------------------------------------------------------------------------

export const OFFSET_A = 0;           // sender public key
export const SIZE_A = 65;
export const OFFSET_Y = 65;          // recipient public key
export const SIZE_Y = 65;
export const OFFSET_F = 130;         // key material f
export const SIZE_F = 32;
export const OFFSET_TS = 162;        // timestamp
export const SIZE_TS = 8;
export const OFFSET_IV = 170;        // IV
export const SIZE_IV = 12;
export const OFFSET_CT = 182;        // start of ciphertext
export const SIZE_TAG = 16;          // GCM auth tag (at end before sig)
export const SIZE_SIG = 64;          // Schnorr sig (very end)
export const SIZE_TAIL = SIZE_TAG + SIZE_SIG; // 80 bytes

/** Minimum wire size for a mail with an empty plaintext. */
export const MIN_MAIL_SIZE = OFFSET_CT + SIZE_TAG + SIZE_SIG; // 262

/** Byte offset where the Schnorr signature starts (relative to end: -SIZE_SIG). */
export const OFFSET_SIG = -SIZE_SIG;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a uint64 as 8 big-endian bytes. */
function encodeUint64(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  let tmp = n;
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return b;
}

/** Decode 8 big-endian bytes into a uint64. */
function decodeUint64(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = 0; i < 8; i++) {
    n = (n << 8n) | BigInt(b[i]);
  }
  return n;
}

/** Concatenate multiple Uint8Arrays into one. */
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Lexicographic comparison of two byte arrays.
 * Returns negative if a < b, zero if a == b, positive if a > b.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Return [min, max] of the two encoded public keys, ordered
 * lexicographically so that message_id is the same regardless of which
 * side (sender or receiver) computes it.
 */
function sortedKeys(A: Uint8Array, Y: Uint8Array): [Uint8Array, Uint8Array] {
  return compareBytes(A, Y) <= 0 ? [A, Y] : [Y, A];
}

// ---------------------------------------------------------------------------
// message_id
// ---------------------------------------------------------------------------

/**
 * Compute the message_id:
 *   SHA-256(timestamp_bytes ‖ min(A,Y) ‖ max(A,Y) ‖ IV)
 */
export function computeMessageId(
  timestampBytes: Uint8Array,
  A: Uint8Array,
  Y: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const [minKey, maxKey] = sortedKeys(A, Y);
  return sha256Hash(timestampBytes, minKey, maxKey, iv);
}

// ---------------------------------------------------------------------------
// AES key derivation
// ---------------------------------------------------------------------------

/**
 * Derive a 32-byte AES-256-GCM key from a shared ECDH secret.
 *
 * @param sharedX  32-byte X-coordinate of the shared point S.
 * @param A        65-byte encoded sender public key.
 * @param Y        65-byte encoded recipient public key.
 * @param fBytes   32-byte big-endian key material f.
 */
function deriveAesKey(
  sharedX: Uint8Array,
  A: Uint8Array,
  Y: Uint8Array,
  fBytes: Uint8Array,
): Uint8Array {
  const salt = sha256Hash(A, Y, fBytes);
  return hkdf(sharedX, salt, 'ECCHImail-v2', 32);
}

// ---------------------------------------------------------------------------
// Mail header (public; used by server for validation)
// ---------------------------------------------------------------------------

/** Parsed header fields needed for server-side validation. */
export interface MailHeader {
  /** Encoded sender public key (65 bytes). */
  A: Uint8Array;
  /** Encoded recipient public key (65 bytes). */
  Y: Uint8Array;
  /** Timestamp in Unix seconds. */
  timestamp: bigint;
  /** Schnorr signature over message_id (64 bytes). */
  sig: Uint8Array;
  /** Computed message_id (32 bytes). */
  messageId: Uint8Array;
}

/**
 * Parse the fields that the *server* needs to validate a received mail.
 * Does **not** decrypt the ciphertext.
 *
 * @returns `null` if the mail is too short to be well-formed.
 */
export function parseMailHeader(mail: Uint8Array): MailHeader | null {
  if (mail.length < MIN_MAIL_SIZE) return null;

  const A = mail.slice(OFFSET_A, OFFSET_A + SIZE_A);
  const Y = mail.slice(OFFSET_Y, OFFSET_Y + SIZE_Y);
  const timestampBytes = mail.slice(OFFSET_TS, OFFSET_TS + SIZE_TS);
  const iv = mail.slice(OFFSET_IV, OFFSET_IV + SIZE_IV);
  const sig = mail.slice(mail.length - SIZE_SIG);

  const timestamp = decodeUint64(timestampBytes);
  const messageId = computeMessageId(timestampBytes, A, Y, iv);

  return { A, Y, timestamp, sig, messageId };
}

// ---------------------------------------------------------------------------
// composeMail
// ---------------------------------------------------------------------------

/**
 * Compose an ECCHImail v2 mail.
 *
 * @param senderPriv    Sender's long-term private scalar `a`.
 * @param senderPub     Sender's public key point `A = aG`.
 * @param recipientPub  Recipient's public key point `Y = xG`.
 * @param plaintext     Message body to encrypt.
 * @returns             Mail bytes ready to be submitted via SEND.
 */
export function composeMail(
  senderPriv: bigint,
  senderPub: Point,
  recipientPub: Point,
  plaintext: Uint8Array,
): Uint8Array {
  if (senderPriv <= 0n || senderPriv >= N) {
    throw new RangeError('senderPriv must be in (0, N)');
  }

  // 1. Generate one-time scalar f
  const f = randomScalar();
  const fBytes = bigIntToBytes(f, SIZE_F);

  // 2. Shared secret: S = (a + f) × Y
  const aPrime = (senderPriv + f) % N;
  const S = scalarMul(recipientPub, aPrime);
  const Saff = S.toAffine();
  const sharedX = bigIntToBytes(Saff.x, 32);

  const A = encodePoint(senderPub);
  const Y = encodePoint(recipientPub);

  // 3. AES key
  const aesKey = deriveAesKey(sharedX, A, Y, fBytes);

  // 4. Encrypt
  const iv = randomBytes(SIZE_IV);
  const { ciphertext, tag } = aesGcmEncrypt(aesKey, iv, plaintext);

  // 5. Timestamp
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const timestampBytes = encodeUint64(nowSec);

  // 6. message_id
  const messageId = computeMessageId(timestampBytes, A, Y, iv);

  // 7. Schnorr signature over message_id
  const sig = schnorrSign(senderPriv, messageId);

  // 8. Assemble
  return concat(A, Y, fBytes, timestampBytes, iv, ciphertext, tag, sig);
}

// ---------------------------------------------------------------------------
// openMail
// ---------------------------------------------------------------------------

/**
 * Decrypt and authenticate an ECCHImail v2 mail.
 *
 * @param recipientPriv  Recipient's long-term private scalar `x`.
 * @param recipientPub   Recipient's public key point `Y = xG`.
 * @param mail           Raw mail bytes (as returned by {@link composeMail}).
 * @returns              Decrypted plaintext, or `null` on any error
 *                       (invalid format, bad signature, GCM auth failure, …).
 */
export function openMail(
  recipientPriv: bigint,
  recipientPub: Point,
  mail: Uint8Array,
): Uint8Array | null {
  if (mail.length < MIN_MAIL_SIZE) return null;

  // 1. Parse fields
  const ABytes = mail.slice(OFFSET_A, OFFSET_A + SIZE_A);
  const YBytes = mail.slice(OFFSET_Y, OFFSET_Y + SIZE_Y);
  const fBytes = mail.slice(OFFSET_F, OFFSET_F + SIZE_F);
  const timestampBytes = mail.slice(OFFSET_TS, OFFSET_TS + SIZE_TS);
  const iv = mail.slice(OFFSET_IV, OFFSET_IV + SIZE_IV);
  const ciphertext = mail.slice(OFFSET_CT, mail.length - SIZE_TAIL);
  const tag = mail.slice(mail.length - SIZE_TAIL, mail.length - SIZE_SIG);
  const sig = mail.slice(mail.length - SIZE_SIG);

  // 2. Validate that A and Y are valid P-256 points
  if (!isValidPoint(ABytes) || !isValidPoint(YBytes)) return null;

  // 3. Re-compute message_id and verify Schnorr signature
  const messageId = computeMessageId(timestampBytes, ABytes, YBytes, iv);
  if (!schnorrVerify(ABytes, messageId, sig)) return null;

  // 4. Decode sender public key A
  let A: Point;
  try {
    A = decodePoint(ABytes);
  } catch {
    return null;
  }

  // 5. Shared secret: S = x × (A + fG)
  const f = bytesToBigInt(fBytes);
  if (f === 0n || f >= N) return null;

  const fG = scalarMul(G, f);
  const APrime = pointAdd(A, fG);
  const S = scalarMul(APrime, recipientPriv);
  const Saff = S.toAffine();
  const sharedX = bigIntToBytes(Saff.x, 32);

  const Y = encodePoint(recipientPub);

  // 6. AES key
  const aesKey = deriveAesKey(sharedX, ABytes, Y, fBytes);

  // 7. Decrypt (GCM tag authentication is implicit)
  return aesGcmDecrypt(aesKey, iv, ciphertext, tag);
}
