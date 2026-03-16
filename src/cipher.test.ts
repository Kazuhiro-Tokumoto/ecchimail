/**
 * Tests for cipher.ts — AES-256-GCM and HKDF-SHA-256
 */

import { sha256Hash, hkdf, aesGcmEncrypt, aesGcmDecrypt, randomBytes } from './cipher';

describe('sha256Hash', () => {
  it('produces a 32-byte digest', () => {
    const digest = sha256Hash(new Uint8Array([1, 2, 3]));
    expect(digest.length).toBe(32);
  });

  it('is deterministic', () => {
    const a = sha256Hash(new Uint8Array([1, 2, 3]));
    const b = sha256Hash(new Uint8Array([1, 2, 3]));
    expect(a).toEqual(b);
  });

  it('concatenates multiple parts before hashing', () => {
    const combined = sha256Hash(new Uint8Array([1, 2, 3, 4, 5]));
    const split = sha256Hash(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]));
    expect(combined).toEqual(split);
  });

  it('different input → different digest', () => {
    const a = sha256Hash(new Uint8Array([1]));
    const b = sha256Hash(new Uint8Array([2]));
    expect(a).not.toEqual(b);
  });
});

describe('hkdf', () => {
  it('produces exactly outputLength bytes', () => {
    const ikm = new Uint8Array(32).fill(1);
    const salt = new Uint8Array(32).fill(2);
    const out32 = hkdf(ikm, salt, 'test', 32);
    const out16 = hkdf(ikm, salt, 'test', 16);
    expect(out32.length).toBe(32);
    expect(out16.length).toBe(16);
  });

  it('is deterministic', () => {
    const ikm = new Uint8Array(32).fill(0xAB);
    const salt = new Uint8Array(16).fill(0xCD);
    const a = hkdf(ikm, salt, 'ECCHImail-v2', 32);
    const b = hkdf(ikm, salt, 'ECCHImail-v2', 32);
    expect(a).toEqual(b);
  });

  it('different ikm → different output', () => {
    const salt = new Uint8Array(32);
    const a = hkdf(new Uint8Array(32).fill(0x01), salt, 'info', 32);
    const b = hkdf(new Uint8Array(32).fill(0x02), salt, 'info', 32);
    expect(a).not.toEqual(b);
  });
});

describe('aesGcmEncrypt / aesGcmDecrypt', () => {
  const key = new Uint8Array(32).fill(0x42);
  const iv = new Uint8Array(12).fill(0x99);

  it('encrypts and decrypts a plaintext', () => {
    const plaintext = new TextEncoder().encode('Hello, ECCHImail!');
    const { ciphertext, tag } = aesGcmEncrypt(key, iv, plaintext);
    const recovered = aesGcmDecrypt(key, iv, ciphertext, tag);
    expect(recovered).not.toBeNull();
    expect(recovered).toEqual(plaintext);
  });

  it('returns null if tag is tampered', () => {
    const plaintext = new TextEncoder().encode('secret message');
    const { ciphertext, tag } = aesGcmEncrypt(key, iv, plaintext);
    const badTag = new Uint8Array(tag);
    badTag[0] ^= 0xff;
    const result = aesGcmDecrypt(key, iv, ciphertext, badTag);
    expect(result).toBeNull();
  });

  it('returns null if ciphertext is tampered', () => {
    const plaintext = new TextEncoder().encode('secret message');
    const { ciphertext, tag } = aesGcmEncrypt(key, iv, plaintext);
    const badCt = new Uint8Array(ciphertext);
    badCt[0] ^= 0xff;
    const result = aesGcmDecrypt(key, iv, badCt, tag);
    expect(result).toBeNull();
  });

  it('encrypts an empty plaintext', () => {
    const { ciphertext, tag } = aesGcmEncrypt(key, iv, new Uint8Array(0));
    expect(ciphertext.length).toBe(0);
    expect(tag.length).toBe(16);
    const recovered = aesGcmDecrypt(key, iv, ciphertext, tag);
    expect(recovered).toEqual(new Uint8Array(0));
  });

  it('throws for wrong key size', () => {
    expect(() => aesGcmEncrypt(new Uint8Array(16), iv, new Uint8Array(1))).toThrow();
  });

  it('throws for wrong IV size', () => {
    expect(() => aesGcmEncrypt(key, new Uint8Array(16), new Uint8Array(1))).toThrow();
  });
});

describe('randomBytes', () => {
  it('returns the requested length', () => {
    expect(randomBytes(12).length).toBe(12);
    expect(randomBytes(32).length).toBe(32);
  });

  it('produces different bytes on each call', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(a).not.toEqual(b);
  });
});
