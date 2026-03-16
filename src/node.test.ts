/**
 * Tests for node.ts + client.ts — server and client integration
 *
 * These tests spin up a real WebSocket server on an ephemeral port and exercise
 * the full SEND / LOOK / FETCH / ACK / DELETE / COUNT command cycle.
 */

import { EcchiMailNode } from './node';
import { EcchiMailClient } from './client';
import { composeMail, openMail } from './ecchimail';
import { G, randomScalar, scalarMul } from './p-256';

function makeKeypair() {
  const priv = randomScalar();
  const pub = scalarMul(G, priv);
  return { priv, pub };
}

/** Pick a random port in 40000-49999 to avoid collisions between test suites. */
function randomPort(): number {
  return 40000 + Math.floor(Math.random() * 10000);
}

describe('EcchiMailNode + EcchiMailClient integration', () => {
  let node: EcchiMailNode;
  let client: EcchiMailClient;
  let port: number;

  beforeEach(async () => {
    port = randomPort();
    node = new EcchiMailNode({ port, timestampTolerance: 300 });
    client = new EcchiMailClient(`ws://127.0.0.1:${port}`);
    await client.connect();
  });

  afterEach(async () => {
    await client.disconnect();
    await node.close();
  });

  // -------------------------------------------------------------------------
  // SEND
  // -------------------------------------------------------------------------

  it('SEND accepts a valid mail', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('hello'),
    );
    const result = await client.send(mail);
    expect(result.ok).toBe(true);
    expect(typeof result.messageId).toBe('string');
    expect(result.messageId.length).toBe(64); // 32 bytes hex
  });

  // -------------------------------------------------------------------------
  // COUNT
  // -------------------------------------------------------------------------

  it('COUNT returns 0 when mailbox is empty', async () => {
    const recipient = makeKeypair();
    const cnt = await client.count(recipient.priv, recipient.pub);
    expect(cnt).toBe(0);
  });

  it('COUNT increases after SEND', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('hi'),
    );
    await client.send(mail);
    const cnt = await client.count(recipient.priv, recipient.pub);
    expect(cnt).toBe(1);
  });

  // -------------------------------------------------------------------------
  // LOOK
  // -------------------------------------------------------------------------

  it('LOOK returns empty array when no mails', async () => {
    const recipient = makeKeypair();
    const ids = await client.look(recipient.priv, recipient.pub);
    expect(ids).toEqual([]);
  });

  it('LOOK returns the message_id after SEND', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('look test'),
    );
    const sendResult = await client.send(mail);
    const ids = await client.look(recipient.priv, recipient.pub);
    expect(ids).toContain(sendResult.messageId);
  });

  // -------------------------------------------------------------------------
  // FETCH
  // -------------------------------------------------------------------------

  it('FETCH retrieves the mail bytes', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const plaintext = new TextEncoder().encode('fetch me');
    const mail = composeMail(sender.priv, sender.pub, recipient.pub, plaintext);

    const sendResult = await client.send(mail);
    const fetched = await client.fetch(recipient.priv, recipient.pub, sendResult.messageId);

    // Decrypt and verify
    const recovered = openMail(recipient.priv, recipient.pub, fetched);
    expect(recovered).not.toBeNull();
    expect(recovered).toEqual(plaintext);
  });

  it('FETCH fails for unknown message_id', async () => {
    const recipient = makeKeypair();
    await expect(
      client.fetch(recipient.priv, recipient.pub, 'a'.repeat(64)),
    ).rejects.toBeDefined();
  });

  // -------------------------------------------------------------------------
  // ACK (deletes the mail)
  // -------------------------------------------------------------------------

  it('ACK removes the mail from the mailbox', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('ack me'),
    );
    const sendResult = await client.send(mail);

    await client.ack(recipient.priv, recipient.pub, sendResult.messageId);

    const ids = await client.look(recipient.priv, recipient.pub);
    expect(ids).not.toContain(sendResult.messageId);
  });

  // -------------------------------------------------------------------------
  // DELETE
  // -------------------------------------------------------------------------

  it('DELETE removes the mail without ACK', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('delete me'),
    );
    const sendResult = await client.send(mail);

    await client.delete(recipient.priv, recipient.pub, sendResult.messageId);

    const cnt = await client.count(recipient.priv, recipient.pub);
    expect(cnt).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Security: wrong recipient cannot fetch
  // -------------------------------------------------------------------------

  it('FETCH rejects if public key does not match recipient', async () => {
    const sender = makeKeypair();
    const recipient = makeKeypair();
    const attacker = makeKeypair();
    const mail = composeMail(
      sender.priv,
      sender.pub,
      recipient.pub,
      new TextEncoder().encode('secret'),
    );
    const sendResult = await client.send(mail);

    await expect(
      client.fetch(attacker.priv, attacker.pub, sendResult.messageId),
    ).rejects.toBeDefined();
  });
});
