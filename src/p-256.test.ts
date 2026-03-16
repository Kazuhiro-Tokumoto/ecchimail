/**
 * Tests for p-256.ts — P-256 curve primitives
 */

import {
  N,
  FIELD_P,
  G,
  bytesToBigInt,
  bigIntToBytes,
  randomScalar,
  scalarMul,
  pointAdd,
  encodePoint,
  decodePoint,
  isValidPoint,
} from './p-256';

describe('bytesToBigInt / bigIntToBytes round-trip', () => {
  it('converts zero correctly', () => {
    const b = new Uint8Array(4);
    expect(bytesToBigInt(b)).toBe(0n);
  });

  it('converts a known value', () => {
    const b = new Uint8Array([0x01, 0x00, 0x00, 0x00]);
    expect(bytesToBigInt(b)).toBe(0x01000000n);
  });

  it('round-trips a random bigint', () => {
    const original = 0xdeadbeefcafebaben;
    const bytes = bigIntToBytes(original, 8);
    expect(bytesToBigInt(bytes)).toBe(original);
  });

  it('bigIntToBytes pads with zeros on the left', () => {
    const b = bigIntToBytes(1n, 4);
    expect(b).toEqual(new Uint8Array([0, 0, 0, 1]));
  });
});

describe('P-256 curve constants', () => {
  it('N and FIELD_P are the expected bigints', () => {
    expect(N).toBe(0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n);
    expect(FIELD_P).toBe(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn);
  });
});

describe('randomScalar', () => {
  it('returns a scalar in (0, N)', () => {
    for (let i = 0; i < 10; i++) {
      const s = randomScalar();
      expect(s > 0n).toBe(true);
      expect(s < N).toBe(true);
    }
  });
});

describe('scalarMul and pointAdd', () => {
  it('G + G = 2G', () => {
    const twoG = scalarMul(G, 2n);
    const added = pointAdd(G, G);
    expect(twoG.equals(added)).toBe(true);
  });

  it('k*G for k=1 equals G', () => {
    const pt = scalarMul(G, 1n);
    expect(pt.equals(G)).toBe(true);
  });

  it('(a + b)*G = a*G + b*G', () => {
    const a = 12345n;
    const b = 67890n;
    const lhs = scalarMul(G, (a + b) % N);
    const rhs = pointAdd(scalarMul(G, a), scalarMul(G, b));
    expect(lhs.equals(rhs)).toBe(true);
  });
});

describe('encodePoint / decodePoint', () => {
  it('round-trips the base point G', () => {
    const encoded = encodePoint(G);
    expect(encoded.length).toBe(65);
    expect(encoded[0]).toBe(0x04);
    const decoded = decodePoint(encoded);
    expect(decoded.equals(G)).toBe(true);
  });

  it('round-trips an arbitrary point', () => {
    const pt = scalarMul(G, 99999999n);
    const encoded = encodePoint(pt);
    const decoded = decodePoint(encoded);
    expect(decoded.equals(pt)).toBe(true);
  });

  it('throws for invalid bytes', () => {
    expect(() => decodePoint(new Uint8Array(65))).toThrow();
  });
});

describe('isValidPoint', () => {
  it('returns true for the base point', () => {
    const encoded = encodePoint(G);
    expect(isValidPoint(encoded)).toBe(true);
  });

  it('returns false for wrong length', () => {
    expect(isValidPoint(new Uint8Array(64))).toBe(false);
    expect(isValidPoint(new Uint8Array(66))).toBe(false);
  });

  it('returns false for wrong prefix', () => {
    const encoded = encodePoint(G);
    const bad = new Uint8Array(encoded);
    bad[0] = 0x03;
    expect(isValidPoint(bad)).toBe(false);
  });

  it('returns false for an invalid curve point', () => {
    const bad = new Uint8Array(65);
    bad[0] = 0x04;
    // All-zero X, Y is not on P-256
    expect(isValidPoint(bad)).toBe(false);
  });
});
