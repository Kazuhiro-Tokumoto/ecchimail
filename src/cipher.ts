/**
 * cipher.ts — AES-256-GCM encryption / decryption and HKDF-SHA-256
 *
 * All operations use the Node.js built-in `crypto` module so that no
 * additional runtime dependencies are required beyond @noble/*.
 */

import { createCipheriv, createDecipheriv, hkdfSync } from 'crypto';
import { sha256 } from '@noble/hashes/sha2.js';

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/** Compute SHA-256 over the concatenation of all supplied byte arrays. */
export function sha256Hash(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  return sha256(buf);
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256
// ---------------------------------------------------------------------------

/**
 * Derive `outputLength` bytes from `ikm` using HKDF-SHA-256.
 *
 * @param ikm          Input key material (e.g. the shared-secret X coordinate).
 * @param salt         Salt bytes.
 * @param info         Context string (encoded as UTF-8).
 * @param outputLength Number of bytes to produce (must be ≤ 255 × 32 = 8160).
 */
export function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  outputLength: number,
): Uint8Array {
  const result = hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), outputLength);
  return new Uint8Array(result);
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/** Output of {@link aesGcmEncrypt}. */
export interface AesGcmResult {
  ciphertext: Uint8Array;
  tag: Uint8Array; // 16 bytes
}

/**
 * Encrypt `plaintext` with AES-256-GCM.
 *
 * @param key       32-byte AES key.
 * @param iv        12-byte initialisation vector (must be unique per (key, plaintext) pair).
 * @param plaintext Bytes to encrypt.
 * @returns Ciphertext and 16-byte authentication tag (separately).
 */
export function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): AesGcmResult {
  if (key.length !== 32) throw new Error('AES-256-GCM key must be 32 bytes');
  if (iv.length !== 12) throw new Error('AES-256-GCM IV must be 12 bytes');

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: new Uint8Array(encrypted),
    tag: new Uint8Array(tag),
  };
}

/**
 * Decrypt and authenticate an AES-256-GCM ciphertext.
 *
 * @param key        32-byte AES key.
 * @param iv         12-byte initialisation vector.
 * @param ciphertext Encrypted bytes.
 * @param tag        16-byte authentication tag.
 * @returns Decrypted plaintext, or `null` if authentication fails.
 */
export function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  if (key.length !== 32) throw new Error('AES-256-GCM key must be 32 bytes');
  if (iv.length !== 12) throw new Error('AES-256-GCM IV must be 12 bytes');
  if (tag.length !== 16) throw new Error('AES-256-GCM auth tag must be 16 bytes');

  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(Buffer.from(tag));
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return new Uint8Array(decrypted);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Random bytes
// ---------------------------------------------------------------------------

import { randomBytes as nodeRandomBytes } from 'crypto';

/** Return `len` cryptographically-secure random bytes. */
export function randomBytes(len: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(len));
}
