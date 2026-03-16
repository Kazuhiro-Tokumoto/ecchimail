/**
 * client.ts — ECCHImail client
 *
 * Wraps the WebSocket client-side protocol so callers can perform all
 * ECCHImail operations (SEND / LOOK / FETCH / ACK / DELETE / COUNT)
 * using simple async methods.
 *
 * Example usage:
 *   const client = new EcchiMailClient('ws://localhost:9000');
 *   await client.connect();
 *   const mail = composeMail(privA, pubA, pubX, plaintext);
 *   await client.send(mail);
 *   const ids = await client.look(privX, pubX);
 *   const raw = await client.fetch(privX, pubX, ids[0]);
 *   await client.ack(privX, pubX, ids[0]);
 *   await client.disconnect();
 */

import WebSocket from 'ws';
import {
  N,
  encodePoint,
  bigIntToBytes,
  bytesToBigInt,
  type Point,
} from './p-256';
import { schnorrSign } from './ecsh';

// ---------------------------------------------------------------------------
// Hex helpers (duplicated from node.ts to keep modules self-contained)
// ---------------------------------------------------------------------------

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Odd hex length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sign a LOOK / FETCH / COUNT command payload
// ---------------------------------------------------------------------------

/**
 * Sign the payload `cmd || ts_8bytes` with `privKey`.
 * Returns the 64-byte Schnorr signature as a hex string.
 */
function signCommand(privKey: bigint, cmdName: string, tsSeconds: number): string {
  const cmdBytes = new TextEncoder().encode(cmdName);
  const tsBytes = bigIntToBytes(BigInt(tsSeconds), 8);
  const payload = new Uint8Array(cmdBytes.length + tsBytes.length);
  payload.set(cmdBytes, 0);
  payload.set(tsBytes, cmdBytes.length);
  return bytesToHex(schnorrSign(privKey, payload));
}

// ---------------------------------------------------------------------------
// EcchiMailClient
// ---------------------------------------------------------------------------

/** Server response for SEND. */
export interface SendResult {
  ok: true;
  messageId: string;
}

/** Server response for LOOK. */
export interface LookResult {
  ok: true;
  messageIds: string[];
}

/** Server response for FETCH. */
export interface FetchResult {
  ok: true;
  mail: Uint8Array;
}

/** Server response for ACK / DELETE. */
export interface AckResult {
  ok: true;
}

/** Server response for COUNT. */
export interface CountResult {
  ok: true;
  count: number;
}

export class EcchiMailClientError extends Error {
  constructor(
    message: string,
    public readonly serverError?: string,
  ) {
    super(message);
    this.name = 'EcchiMailClientError';
  }
}

export class EcchiMailClient {
  private ws: WebSocket | null = null;
  /** Pending response callbacks keyed by a sequence number. */
  private readonly pending = new Map<
    number,
    { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }
  >();
  private seq = 0;

  constructor(private readonly url: string) {}

  /** Open the WebSocket connection to the server. */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      ws.once('open', () => resolve());
      ws.once('error', (err) => reject(err));
      ws.on('message', (data) => this.onMessage(data.toString()));
      ws.on('close', () => {
        for (const { reject: rej } of this.pending.values()) {
          rej(new EcchiMailClientError('Connection closed'));
        }
        this.pending.clear();
      });
    });
  }

  /** Close the WebSocket connection. */
  disconnect(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.ws || this.ws.readyState === WebSocket.CLOSED) {
        resolve();
        return;
      }
      this.ws.once('close', () => resolve());
      this.ws.close();
    });
  }

  private onMessage(raw: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return;
    }
    // Responses are correlated by sequence number echoed in `_seq`
    const seq = msg['_seq'];
    if (typeof seq === 'number') {
      const pending = this.pending.get(seq);
      if (pending) {
        this.pending.delete(seq);
        pending.resolve(msg);
      }
    }
  }

  private sendRequest(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new EcchiMailClientError('Not connected'));
    }
    const seq = this.seq++;
    return new Promise((resolve, reject) => {
      this.pending.set(seq, { resolve, reject });
      this.ws!.send(JSON.stringify({ ...payload, _seq: seq }));
    });
  }

  private assertOk<T extends { ok: boolean }>(resp: Record<string, unknown>): T {
    if (!resp['ok']) {
      throw new EcchiMailClientError(
        `Server error: ${resp['error'] ?? 'unknown'}`,
        typeof resp['error'] === 'string' ? resp['error'] : undefined,
      );
    }
    return resp as unknown as T;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Submit a pre-composed mail to the server.
   * @param mail  Bytes produced by {@link composeMail}.
   */
  async send(mail: Uint8Array): Promise<SendResult> {
    const resp = await this.sendRequest({ cmd: 'SEND', mail: bytesToHex(mail) });
    return this.assertOk<SendResult>(resp);
  }

  /**
   * Check which mails are waiting for `recipientPub`.
   * @returns Array of hex-encoded message_ids.
   */
  async look(recipientPriv: bigint, recipientPub: Point): Promise<string[]> {
    if (recipientPriv <= 0n || recipientPriv >= N) {
      throw new RangeError('recipientPriv must be in (0, N)');
    }
    const pubkeyHex = bytesToHex(encodePoint(recipientPub));
    const ts = Math.floor(Date.now() / 1000);
    const sig = signCommand(recipientPriv, 'LOOK', ts);
    const resp = await this.sendRequest({ cmd: 'LOOK', pubkey: pubkeyHex, ts, sig });
    const result = this.assertOk<LookResult>(resp);
    return result.messageIds;
  }

  /**
   * Fetch a specific mail by its message_id.
   * @returns Raw mail bytes suitable for {@link openMail}.
   */
  async fetch(
    recipientPriv: bigint,
    recipientPub: Point,
    messageId: string,
  ): Promise<Uint8Array> {
    if (recipientPriv <= 0n || recipientPriv >= N) {
      throw new RangeError('recipientPriv must be in (0, N)');
    }
    const pubkeyHex = bytesToHex(encodePoint(recipientPub));
    const ts = Math.floor(Date.now() / 1000);
    const sig = signCommand(recipientPriv, 'FETCH', ts);
    const resp = await this.sendRequest({
      cmd: 'FETCH',
      pubkey: pubkeyHex,
      messageId,
      ts,
      sig,
    });
    const result = this.assertOk<FetchResult>(resp);
    return hexToBytes(result.mail as unknown as string);
  }

  /**
   * Acknowledge receipt of a mail.  The server deletes the mail after ACK.
   * @param messageIdHex  Hex message_id (from {@link look}).
   */
  async ack(
    recipientPriv: bigint,
    recipientPub: Point,
    messageIdHex: string,
  ): Promise<void> {
    if (recipientPriv <= 0n || recipientPriv >= N) {
      throw new RangeError('recipientPriv must be in (0, N)');
    }
    const pubkeyHex = bytesToHex(encodePoint(recipientPub));
    const messageIdBytes = hexToBytes(messageIdHex);
    const sig = bytesToHex(schnorrSign(recipientPriv, messageIdBytes));
    const resp = await this.sendRequest({
      cmd: 'ACK',
      pubkey: pubkeyHex,
      messageId: messageIdHex,
      sig,
    });
    this.assertOk(resp);
  }

  /**
   * Delete an unread mail without acknowledging it.
   * @param messageIdHex  Hex message_id (from {@link look}).
   */
  async delete(
    recipientPriv: bigint,
    recipientPub: Point,
    messageIdHex: string,
  ): Promise<void> {
    if (recipientPriv <= 0n || recipientPriv >= N) {
      throw new RangeError('recipientPriv must be in (0, N)');
    }
    const pubkeyHex = bytesToHex(encodePoint(recipientPub));
    const messageIdBytes = hexToBytes(messageIdHex);
    const sig = bytesToHex(schnorrSign(recipientPriv, messageIdBytes));
    const resp = await this.sendRequest({
      cmd: 'DELETE',
      pubkey: pubkeyHex,
      messageId: messageIdHex,
      sig,
    });
    this.assertOk(resp);
  }

  /**
   * Query the number of pending mails for `recipientPub`.
   */
  async count(recipientPriv: bigint, recipientPub: Point): Promise<number> {
    if (recipientPriv <= 0n || recipientPriv >= N) {
      throw new RangeError('recipientPriv must be in (0, N)');
    }
    const pubkeyHex = bytesToHex(encodePoint(recipientPub));
    const ts = Math.floor(Date.now() / 1000);
    const sig = signCommand(recipientPriv, 'COUNT', ts);
    const resp = await this.sendRequest({ cmd: 'COUNT', pubkey: pubkeyHex, ts, sig });
    const result = this.assertOk<CountResult>(resp);
    return result.count;
  }
}
