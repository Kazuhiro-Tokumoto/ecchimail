/**
 * p-256.ts — P-256 (secp256r1) elliptic curve primitives
 *
 * Wraps @noble/curves/nist to expose the operations required by ECCHImail:
 *   - Scalar multiplication and point addition
 *   - Uncompressed-point encode / decode (65-byte 0x04 || X || Y format)
 *   - On-curve validation
 *   - Cryptographically-secure random scalar generation
 */

import { p256 as _p256 } from '@noble/curves/nist.js';

/** The concrete Point class from @noble/curves. */
type _Point = InstanceType<typeof _p256.Point>;

/** A P-256 projective point. */
export type Point = _Point;

/** Internal helper: convert Uint8Array to hex string (needed by @noble/curves v2 API). */
function _bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

/** P-256 curve order N (order of the base point G). */
export const N: bigint = _p256.Point.CURVE().n;

/** P-256 field prime p. */
export const FIELD_P: bigint = _p256.Point.CURVE().p;

/** P-256 base / generator point G. */
export const G: Point = _p256.Point.BASE;

// ---------------------------------------------------------------------------
// Byte ↔ bigint helpers
// ---------------------------------------------------------------------------

/** Convert big-endian byte array to unsigned bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert an unsigned bigint to a big-endian byte array of exactly `len`
 * bytes (zero-padded on the left, high bits truncated if too large).
 */
export function bigIntToBytes(n: bigint, len = 32): Uint8Array {
  const bytes = new Uint8Array(len);
  let tmp = n;
  for (let i = len - 1; i >= 0; i--) {
    bytes[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------

/** Generate a cryptographically-secure random scalar in [1, N). */
export function randomScalar(): bigint {
  let scalar: bigint;
  do {
    const bytes = _p256.utils.randomSecretKey();
    scalar = bytesToBigInt(bytes);
  } while (scalar === 0n || scalar >= N);
  return scalar;
}

// ---------------------------------------------------------------------------
// Point operations
// ---------------------------------------------------------------------------

/** Scalar multiplication: returns `scalar × point`. */
export function scalarMul(point: Point, scalar: bigint): Point {
  return point.multiply(scalar);
}

/** Elliptic-curve point addition: returns `p1 + p2`. */
export function pointAdd(p1: Point, p2: Point): Point {
  return p1.add(p2);
}

// ---------------------------------------------------------------------------
// Serialisation (uncompressed 65-byte format: 0x04 || X || Y)
// ---------------------------------------------------------------------------

/**
 * Encode a point as a 65-byte uncompressed SEC representation.
 * Returns `0x04 || X (32 B) || Y (32 B)`.
 */
export function encodePoint(point: Point): Uint8Array {
  return point.toBytes(false);
}

/**
 * Decode a 65-byte uncompressed SEC representation and return the
 * corresponding projective point.  Throws if the input is not a valid
 * P-256 point.
 */
export function decodePoint(bytes: Uint8Array): Point {
  const pt = _p256.Point.fromHex(_bytesToHex(bytes));
  pt.assertValidity();
  return pt;
}

/**
 * Return true if `bytes` is a valid 65-byte uncompressed P-256 point.
 * Does NOT accept compressed (33-byte) encoding.
 */
export function isValidPoint(bytes: Uint8Array): boolean {
  if (bytes.length !== 65 || bytes[0] !== 0x04) return false;
  try {
    const pt = _p256.Point.fromHex(_bytesToHex(bytes));
    pt.assertValidity();
    return true;
  } catch {
    return false;
  }
}

