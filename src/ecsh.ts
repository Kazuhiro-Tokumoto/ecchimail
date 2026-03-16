/**
 * ecsh.ts — P-256 Schnorr signature (ECCHI Schnorr, BIP340-style)
 *
 * Algorithm:
 *   Sign(a, m):
 *     1. r  ← random scalar in [1, N)
 *     2. R  = rG;  if R.y is odd, negate r so that R always has even Y
 *     3. Rx = R.x as 32-byte big-endian
 *     4. A  = encodePoint(aG)  (65-byte uncompressed)
 *     5. e  = SHA-256(Rx ‖ A ‖ m) mod N
 *     6. s  = (r + e·a) mod N
 *     7. sig = Rx ‖ s  (64 bytes total)
 *
 *   Verify(A_bytes, m, sig):
 *     1. Parse Rx = sig[0..32], s = sig[32..64]
 *     2. Reject if s ≥ N
 *     3. Recover R with even Y from Rx  (compressed prefix 0x02)
 *     4. e  = SHA-256(Rx ‖ A_bytes ‖ m) mod N
 *     5. Accept iff  sG == R + eA
 */

import { p256 as _p256 } from '@noble/curves/nist.js';
import { G, N, randomScalar, encodePoint, scalarMul, bigIntToBytes, bytesToBigInt } from './p-256';
import { sha256Hash } from './cipher';

/** Internal: convert Uint8Array to hex string for @noble/curves v2 API. */
function _toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

type P256Point = InstanceType<typeof _p256.Point>;

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/**
 * Sign `message` with P-256 Schnorr using private key `privKey`.
 *
 * @param privKey  Scalar in (0, N).
 * @param message  Arbitrary-length byte array to sign.
 * @returns        64-byte signature: Rx (32 B) ‖ s (32 B).
 */
export function schnorrSign(privKey: bigint, message: Uint8Array): Uint8Array {
  if (privKey <= 0n || privKey >= N) {
    throw new RangeError('privKey must be in (0, N)');
  }

  const A = encodePoint(scalarMul(G, privKey));

  // Generate nonce r with even-Y convention (BIP340-style)
  let r = randomScalar();
  let R = scalarMul(G, r);
  const Raff = R.toAffine();
  if (Raff.y % 2n !== 0n) {
    r = N - r;
    R = scalarMul(G, r);
  }

  const Rx = bigIntToBytes(R.toAffine().x, 32);
  const e = bytesToBigInt(sha256Hash(Rx, A, message)) % N;
  const s = (r + e * privKey) % N;

  const sig = new Uint8Array(64);
  sig.set(Rx, 0);
  sig.set(bigIntToBytes(s, 32), 32);
  return sig;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/**
 * Verify a P-256 Schnorr signature.
 *
 * @param pubKeyBytes  65-byte uncompressed public key of the signer.
 * @param message      The signed byte array.
 * @param sig          64-byte signature: Rx ‖ s.
 * @returns            `true` if the signature is valid, `false` otherwise.
 */
export function schnorrVerify(
  pubKeyBytes: Uint8Array,
  message: Uint8Array,
  sig: Uint8Array,
): boolean {
  if (sig.length !== 64) return false;

  const Rx = sig.slice(0, 32);
  const s = bytesToBigInt(sig.slice(32, 64));

  // s must be in [0, N)
  if (s >= N) return false;

  // Recover R with even Y (prefix 0x02 = compressed, even Y)
  const compressedR = new Uint8Array(33);
  compressedR[0] = 0x02;
  compressedR.set(Rx, 1);

  let R: P256Point;
  try {
    R = _p256.Point.fromHex(_toHex(compressedR));
    R.assertValidity();
  } catch {
    return false;
  }

  let A: P256Point;
  try {
    A = _p256.Point.fromHex(_toHex(pubKeyBytes));
    A.assertValidity();
  } catch {
    return false;
  }

  const e = bytesToBigInt(sha256Hash(Rx, pubKeyBytes, message)) % N;

  // Check: sG == R + eA
  const sG = scalarMul(G, s);
  const ReA = R.add(A.multiply(e));

  return sG.equals(ReA);
}
