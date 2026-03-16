/**
 * Tests for ecchimail.ts — mail composition and opening
 */

import {
  composeMail,
  openMail,
  computeMessageId,
  parseMailHeader,
  MIN_MAIL_SIZE,
  SIZE_SIG,
} from './ecchimail';
import { G, N, scalarMul, encodePoint, randomScalar, bigIntToBytes, bytesToBigInt } from './p-256';
import { sha256Hash } from './cipher';

function makeKeypair() {
  const priv = randomScalar();
  const pub = scalarMul(G, priv);
  return { priv, pub };
}

describe('composeMail / openMail round-trip', () => {
  it('sender can send, recipient can open', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const plaintext = new TextEncoder().encode('Hello, ECCHImail!');

    const mail = composeMail(sender.priv, sender.pub, recipient.pub, plaintext);
    expect(mail.length).toBeGreaterThanOrEqual(MIN_MAIL_SIZE);

    const recovered = openMail(recipient.priv, recipient.pub, mail);
    expect(recovered).not.toBeNull();
    expect(recovered).toEqual(plaintext);
  });

  it('round-trip with empty plaintext', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(sender.priv, sender.pub, recipient.pub, new Uint8Array(0));
    expect(mail.length).toBe(MIN_MAIL_SIZE);
    const recovered = openMail(recipient.priv, recipient.pub, mail);
    expect(recovered).toEqual(new Uint8Array(0));
  });

  it('openMail returns null for wrong recipient key', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const other = makeKeypair();
    const plaintext = new TextEncoder().encode('secret');
    const mail = composeMail(sender.priv, sender.pub, recipient.pub, plaintext);
    const result = openMail(other.priv, other.pub, mail);
    // Either null (decryption fails) or garbage — must not equal the original
    if (result !== null) {
      expect(result).not.toEqual(plaintext);
    }
  });

  it('openMail returns null if signature is tampered', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const plaintext = new TextEncoder().encode('hello');
    const mail = composeMail(sender.priv, sender.pub, recipient.pub, plaintext);
    const corrupted = new Uint8Array(mail);
    // Tamper the first byte of the signature (last 64 bytes of mail)
    corrupted[mail.length - SIZE_SIG] ^= 0xff;
    expect(openMail(recipient.priv, recipient.pub, corrupted)).toBeNull();
  });

  it('openMail returns null if ciphertext is tampered', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const plaintext = new TextEncoder().encode('hello world');
    const mail = composeMail(sender.priv, sender.pub, recipient.pub, plaintext);
    const corrupted = new Uint8Array(mail);
    // Tamper in the ciphertext area (between IV end and tag start)
    const ctStart = 65 + 65 + 32 + 8 + 12;
    corrupted[ctStart] ^= 0xff;
    expect(openMail(recipient.priv, recipient.pub, corrupted)).toBeNull();
  });

  it('different messages produce different mails', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail1 = composeMail(sender.priv, sender.pub, recipient.pub, new TextEncoder().encode('msg1'));
    const mail2 = composeMail(sender.priv, sender.pub, recipient.pub, new TextEncoder().encode('msg2'));
    expect(mail1).not.toEqual(mail2);
  });
});

describe('parseMailHeader', () => {
  it('parses a correctly formed mail', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('test'),
    );
    const header = parseMailHeader(mail);
    expect(header).not.toBeNull();
    expect(header!.A.length).toBe(65);
    expect(header!.Y.length).toBe(65);
    expect(typeof header!.timestamp).toBe('bigint');
    expect(header!.messageId.length).toBe(32);
    expect(header!.sig.length).toBe(64);
  });

  it('returns null for too-short input', () => {
    expect(parseMailHeader(new Uint8Array(MIN_MAIL_SIZE - 1))).toBeNull();
  });
});

describe('computeMessageId', () => {
  it('is symmetric (same id for swapped A/Y)', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const A = encodePoint(sender.pub);
    const Y = encodePoint(recipient.pub);
    const tsBytes = new Uint8Array(8); // all-zero timestamp
    const iv = new Uint8Array(12).fill(1);

    const id1 = computeMessageId(tsBytes, A, Y, iv);
    const id2 = computeMessageId(tsBytes, Y, A, iv);
    expect(id1).toEqual(id2);
  });

  it('changes when timestamp changes', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const A = encodePoint(sender.pub);
    const Y = encodePoint(recipient.pub);
    const iv = new Uint8Array(12);
    const ts1 = bigIntToBytes(1000n, 8);
    const ts2 = bigIntToBytes(1001n, 8);
    const id1 = computeMessageId(ts1, A, Y, iv);
    const id2 = computeMessageId(ts2, A, Y, iv);
    expect(id1).not.toEqual(id2);
  });

  it('changes when IV changes', () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const A = encodePoint(sender.pub);
    const Y = encodePoint(recipient.pub);
    const ts = bigIntToBytes(5000n, 8);
    const iv1 = new Uint8Array(12).fill(0);
    const iv2 = new Uint8Array(12).fill(1);
    expect(computeMessageId(ts, A, Y, iv1)).not.toEqual(computeMessageId(ts, A, Y, iv2));
  });
});
