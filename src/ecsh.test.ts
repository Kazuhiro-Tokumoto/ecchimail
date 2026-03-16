/**
 * Tests for ecsh.ts — P-256 Schnorr signature
 */

import { schnorrSign, schnorrVerify } from './ecsh';
import { N, G, scalarMul, encodePoint, randomScalar } from './p-256';

describe('schnorrSign / schnorrVerify', () => {
  const privKey = 0xdeadbeefcafebabe1234567890abcdef0102030405060708090a0b0c0d0e0fn;
  const pubKeyBytes = encodePoint(scalarMul(G, privKey));
  const message = new TextEncoder().encode('Hello ECCHImail');

  it('sign produces a 64-byte signature', () => {
    const sig = schnorrSign(privKey, message);
    expect(sig.length).toBe(64);
  });

  it('verify accepts a valid signature', () => {
    const sig = schnorrSign(privKey, message);
    expect(schnorrVerify(pubKeyBytes, message, sig)).toBe(true);
  });

  it('verify rejects a tampered message', () => {
    const sig = schnorrSign(privKey, message);
    const badMsg = new TextEncoder().encode('tampered message');
    expect(schnorrVerify(pubKeyBytes, badMsg, sig)).toBe(false);
  });

  it('verify rejects a tampered signature (s component)', () => {
    const sig = schnorrSign(privKey, message);
    const badSig = new Uint8Array(sig);
    badSig[63] ^= 0x01;
    expect(schnorrVerify(pubKeyBytes, message, badSig)).toBe(false);
  });

  it('verify rejects a tampered signature (Rx component)', () => {
    const sig = schnorrSign(privKey, message);
    const badSig = new Uint8Array(sig);
    badSig[0] ^= 0x01;
    expect(schnorrVerify(pubKeyBytes, message, badSig)).toBe(false);
  });

  it('verify rejects wrong public key', () => {
    const sig = schnorrSign(privKey, message);
    const otherPriv = randomScalar();
    const otherPub = encodePoint(scalarMul(G, otherPriv));
    expect(schnorrVerify(otherPub, message, sig)).toBe(false);
  });

  it('verify rejects a short signature', () => {
    const sig = new Uint8Array(63);
    expect(schnorrVerify(pubKeyBytes, message, sig)).toBe(false);
  });

  it('sign throws for privKey = 0', () => {
    expect(() => schnorrSign(0n, message)).toThrow();
  });

  it('sign throws for privKey >= N', () => {
    expect(() => schnorrSign(N, message)).toThrow();
  });

  it('works with empty message', () => {
    const sig = schnorrSign(privKey, new Uint8Array(0));
    expect(schnorrVerify(pubKeyBytes, new Uint8Array(0), sig)).toBe(true);
  });

  it('multiple calls produce different signatures (nonce is random)', () => {
    const sig1 = schnorrSign(privKey, message);
    const sig2 = schnorrSign(privKey, message);
    // With random nonces the Rx bytes should differ with overwhelming probability
    expect(sig1).not.toEqual(sig2);
  });
});
