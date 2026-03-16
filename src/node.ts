/**
 * node.ts — ECCHImail server node
 *
 * Responsibilities:
 *   • Maintain an in-memory mailbox keyed by recipient public key.
 *   • Validate and store incoming SEND mails.
 *   • Serve LOOK / FETCH / ACK / DELETE / COUNT commands (all require a
 *     valid Schnorr signature from the owner of the queried mailbox).
 *   • Federate LOOK / FETCH requests to peer nodes over WebSocket S2S links.
 *
 * Client ↔ Server message protocol (JSON over WebSocket):
 *
 *   SEND    { cmd:"SEND",   mail:"<hex>" }
 *   LOOK    { cmd:"LOOK",   pubkey:"<hex>", ts:<unix-sec>, sig:"<hex>" }
 *   FETCH   { cmd:"FETCH",  pubkey:"<hex>", messageId:"<hex>", ts:<unix-sec>, sig:"<hex>" }
 *   ACK     { cmd:"ACK",    pubkey:"<hex>", messageId:"<hex>", sig:"<hex>" }
 *   DELETE  { cmd:"DELETE", pubkey:"<hex>", messageId:"<hex>", sig:"<hex>" }
 *   COUNT   { cmd:"COUNT",  pubkey:"<hex>", ts:<unix-sec>, sig:"<hex>" }
 *
 * Server-to-server protocol (untrusted-but-cooperative nodes, JSON):
 *   { cmd:"S2S_LOOK",       pubkey:"<hex>" }
 *   { cmd:"S2S_LOOK_RESP",  messageIds:["<hex>", ...] }
 *   { cmd:"S2S_FETCH",      messageId:"<hex>" }
 *   { cmd:"S2S_FETCH_RESP", mail:"<hex>" | null }
 */

import WebSocket, { WebSocketServer } from 'ws';
import {
  isValidPoint,
  bigIntToBytes,
} from './p-256';
import { schnorrVerify } from './ecsh';
import { parseMailHeader, MIN_MAIL_SIZE } from './ecchimail';

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Odd hex length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

/** Encode command string + 8-byte timestamp for LOOK/FETCH/COUNT signatures. */
function encodeCommandPayload(cmdName: string, tsSeconds: number): Uint8Array {
  const cmdBytes = new TextEncoder().encode(cmdName);
  const tsBytes = bigIntToBytes(BigInt(tsSeconds), 8);
  const out = new Uint8Array(cmdBytes.length + tsBytes.length);
  out.set(cmdBytes, 0);
  out.set(tsBytes, cmdBytes.length);
  return out;
}

// ---------------------------------------------------------------------------
// MailStore
// ---------------------------------------------------------------------------

interface MailEntry {
  messageId: string; // hex
  recipientPubkey: string; // hex (65-byte uncompressed point)
  mail: Uint8Array;
}

class MailStore {
  private readonly mails = new Map<string, MailEntry>();
  private readonly mailbox = new Map<string, Set<string>>();

  store(messageId: string, recipientPubkey: string, mail: Uint8Array): void {
    if (this.mails.has(messageId)) return; // idempotent
    this.mails.set(messageId, { messageId, recipientPubkey, mail });
    let s = this.mailbox.get(recipientPubkey);
    if (!s) {
      s = new Set();
      this.mailbox.set(recipientPubkey, s);
    }
    s.add(messageId);
  }

  getIds(recipientPubkey: string): string[] {
    return [...(this.mailbox.get(recipientPubkey) ?? [])];
  }

  getMail(messageId: string): MailEntry | undefined {
    return this.mails.get(messageId);
  }

  hasMessage(messageId: string): boolean {
    return this.mails.has(messageId);
  }

  delete(messageId: string): boolean {
    const entry = this.mails.get(messageId);
    if (!entry) return false;
    this.mails.delete(messageId);
    this.mailbox.get(entry.recipientPubkey)?.delete(messageId);
    return true;
  }

  count(recipientPubkey: string): number {
    return this.mailbox.get(recipientPubkey)?.size ?? 0;
  }
}

// ---------------------------------------------------------------------------
// EcchiMailNode
// ---------------------------------------------------------------------------

const TIMESTAMP_TOLERANCE_SEC = 300;

export interface NodeOptions {
  /** TCP port to listen on for incoming client and peer connections. */
  port: number;
  /**
   * List of peer WebSocket URLs to connect to on startup.
   * Example: ["ws://localhost:9001"]
   */
  peers?: string[];
  /** Tolerance window (seconds) for timestamp freshness checks. Default 300. */
  timestampTolerance?: number;
}

/** Pending S2S request state for LOOK aggregation. */
interface PendingLook {
  resolve: (ids: string[]) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** Pending S2S request state for FETCH relay. */
interface PendingFetch {
  resolve: (mail: Uint8Array | null) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class EcchiMailNode {
  private readonly store = new MailStore();
  private readonly wss: WebSocketServer;
  private readonly tolerance: number;
  /** Active peer WebSocket connections (server-to-server). */
  private readonly peers = new Set<WebSocket>();

  // Correlation IDs for S2S round-trips
  private nextCorrelId = 0;
  private readonly pendingLooks = new Map<number, PendingLook>();
  private readonly pendingFetches = new Map<number, PendingFetch>();

  constructor(private readonly opts: NodeOptions) {
    this.tolerance = opts.timestampTolerance ?? TIMESTAMP_TOLERANCE_SEC;
    this.wss = new WebSocketServer({ port: opts.port });
    this.wss.on('connection', (ws) => this.onConnection(ws));
  }

  /** Connect to known peer nodes (called after construction). */
  connectToPeers(): void {
    for (const url of this.opts.peers ?? []) {
      this.connectToPeer(url);
    }
  }

  private connectToPeer(url: string): void {
    const ws = new WebSocket(url);
    ws.on('open', () => {
      this.peers.add(ws);
    });
    ws.on('message', (data) => this.handleS2SMessage(ws, data.toString()));
    ws.on('close', () => this.peers.delete(ws));
    ws.on('error', () => ws.terminate());
  }

  /** Close the server (used in tests). */
  close(): Promise<void> {
    for (const peer of this.peers) {
      peer.terminate();
    }
    return new Promise((resolve, reject) => {
      this.wss.close((err) => (err ? reject(err) : resolve()));
    });
  }

  // -------------------------------------------------------------------------
  // Incoming client connection
  // -------------------------------------------------------------------------

  private onConnection(ws: WebSocket): void {
    ws.on('message', (data) => {
      void this.handleClientMessage(ws, data.toString());
    });
  }

  private send(ws: WebSocket, payload: Record<string, unknown>, seq?: number): void {
    if (ws.readyState === WebSocket.OPEN) {
      const out = seq !== undefined ? { ...payload, _seq: seq } : payload;
      ws.send(JSON.stringify(out));
    }
  }

  private error(ws: WebSocket, message: string, seq?: number): void {
    this.send(ws, { ok: false, error: message }, seq);
  }

  // -------------------------------------------------------------------------
  // Client command dispatch
  // -------------------------------------------------------------------------

  private async handleClientMessage(ws: WebSocket, raw: string): Promise<void> {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return this.error(ws, 'Invalid JSON');
    }

    const cmd = msg['cmd'];
    const seq = typeof msg['_seq'] === 'number' ? (msg['_seq'] as number) : undefined;
    switch (cmd) {
      case 'SEND':   return this.handleSend(ws, msg, seq);
      case 'LOOK':   return this.handleLook(ws, msg, seq);
      case 'FETCH':  return this.handleFetch(ws, msg, seq);
      case 'ACK':    return this.handleAckOrDelete(ws, msg, 'ACK', seq);
      case 'DELETE': return this.handleAckOrDelete(ws, msg, 'DELETE', seq);
      case 'COUNT':  return this.handleCount(ws, msg, seq);
      default:       return this.error(ws, 'Unknown command', seq);
    }
  }

  // -------------------------------------------------------------------------
  // SEND
  // -------------------------------------------------------------------------

  private handleSend(ws: WebSocket, msg: Record<string, unknown>, seq?: number): void {
    const mailHex = msg['mail'];
    if (typeof mailHex !== 'string') return this.error(ws, 'SEND: mail must be a hex string', seq);

    let mail: Uint8Array;
    try {
      mail = hexToBytes(mailHex);
    } catch {
      return this.error(ws, 'SEND: mail is not valid hex', seq);
    }

    if (mail.length < MIN_MAIL_SIZE) {
      return this.error(ws, 'SEND: mail too short', seq);
    }

    const header = parseMailHeader(mail);
    if (!header) return this.error(ws, 'SEND: malformed mail', seq);

    // Validate sender and recipient public keys
    if (!isValidPoint(header.A)) return this.error(ws, 'SEND: invalid sender public key', seq);
    if (!isValidPoint(header.Y)) return this.error(ws, 'SEND: invalid recipient public key', seq);

    // Timestamp freshness check
    const nowSec = Math.floor(Date.now() / 1000);
    const mailTs = Number(header.timestamp);
    if (Math.abs(nowSec - mailTs) > this.tolerance) {
      return this.error(ws, 'SEND: timestamp out of range', seq);
    }

    // Verify Schnorr signature (sender signs message_id)
    if (!schnorrVerify(header.A, header.messageId, header.sig)) {
      return this.error(ws, 'SEND: signature verification failed', seq);
    }

    // Store
    const messageId = bytesToHex(header.messageId);
    const recipientPubkey = bytesToHex(header.Y);
    this.store.store(messageId, recipientPubkey, mail);

    this.send(ws, { ok: true, messageId }, seq);
  }

  // -------------------------------------------------------------------------
  // LOOK
  // -------------------------------------------------------------------------

  private async handleLook(
    ws: WebSocket,
    msg: Record<string, unknown>,
    seq?: number,
  ): Promise<void> {
    const { pubkey, ts, sig } = msg;
    if (typeof pubkey !== 'string') return this.error(ws, 'LOOK: pubkey required', seq);
    if (typeof ts !== 'number') return this.error(ws, 'LOOK: ts required', seq);
    if (typeof sig !== 'string') return this.error(ws, 'LOOK: sig required', seq);

    if (!this.validateCommandSignature('LOOK', pubkey, ts, sig)) {
      return this.error(ws, 'LOOK: signature/timestamp verification failed', seq);
    }

    const localIds = this.store.getIds(pubkey);

    // Federate to peers
    let peerIds: string[] = [];
    if (this.peers.size > 0) {
      try {
        peerIds = await this.federateLook(pubkey);
      } catch {
        // Best-effort: if federation fails, return only local results
      }
    }

    // Deduplicate
    const allIds = [...new Set([...localIds, ...peerIds])];
    this.send(ws, { ok: true, messageIds: allIds }, seq);
  }

  // -------------------------------------------------------------------------
  // FETCH
  // -------------------------------------------------------------------------

  private async handleFetch(
    ws: WebSocket,
    msg: Record<string, unknown>,
    seq?: number,
  ): Promise<void> {
    const { pubkey, messageId, ts, sig } = msg;
    if (typeof pubkey !== 'string') return this.error(ws, 'FETCH: pubkey required', seq);
    if (typeof messageId !== 'string') return this.error(ws, 'FETCH: messageId required', seq);
    if (typeof ts !== 'number') return this.error(ws, 'FETCH: ts required', seq);
    if (typeof sig !== 'string') return this.error(ws, 'FETCH: sig required', seq);

    if (!this.validateCommandSignature('FETCH', pubkey, ts, sig)) {
      return this.error(ws, 'FETCH: signature/timestamp verification failed', seq);
    }

    // Verify the requester owns the mailbox
    const entry = this.store.getMail(messageId as string);
    if (entry) {
      if (entry.recipientPubkey !== pubkey) {
        return this.error(ws, 'FETCH: message does not belong to this key', seq);
      }
      return this.send(ws, { ok: true, mail: bytesToHex(entry.mail) }, seq);
    }

    // Try peers
    if (this.peers.size > 0) {
      try {
        const mail = await this.federateFetch(messageId as string);
        if (mail) {
          // Validate that the fetched mail actually belongs to this recipient
          const header = parseMailHeader(mail);
          if (!header || bytesToHex(header.Y) !== pubkey) {
            return this.error(ws, 'FETCH: message does not belong to this key', seq);
          }
          return this.send(ws, { ok: true, mail: bytesToHex(mail) }, seq);
        }
      } catch {
        // Fall through to not-found
      }
    }

    this.error(ws, 'FETCH: message not found', seq);
  }

  // -------------------------------------------------------------------------
  // ACK / DELETE
  // -------------------------------------------------------------------------

  private handleAckOrDelete(
    ws: WebSocket,
    msg: Record<string, unknown>,
    cmd: 'ACK' | 'DELETE',
    seq?: number,
  ): void {
    const { pubkey, messageId, sig } = msg;
    if (typeof pubkey !== 'string') return this.error(ws, `${cmd}: pubkey required`, seq);
    if (typeof messageId !== 'string') return this.error(ws, `${cmd}: messageId required`, seq);
    if (typeof sig !== 'string') return this.error(ws, `${cmd}: sig required`, seq);

    let pubkeyBytes: Uint8Array;
    let messageIdBytes: Uint8Array;
    let sigBytes: Uint8Array;
    try {
      pubkeyBytes = hexToBytes(pubkey);
      messageIdBytes = hexToBytes(messageId);
      sigBytes = hexToBytes(sig);
    } catch {
      return this.error(ws, `${cmd}: invalid hex`, seq);
    }

    if (!isValidPoint(pubkeyBytes)) return this.error(ws, `${cmd}: invalid public key`, seq);

    // Verify signature over message_id
    if (!schnorrVerify(pubkeyBytes, messageIdBytes, sigBytes)) {
      return this.error(ws, `${cmd}: signature verification failed`, seq);
    }

    // Verify ownership
    const entry = this.store.getMail(messageId);
    if (!entry) return this.error(ws, `${cmd}: message not found`, seq);
    if (entry.recipientPubkey !== pubkey) {
      return this.error(ws, `${cmd}: message does not belong to this key`, seq);
    }

    this.store.delete(messageId);
    this.send(ws, { ok: true }, seq);
  }

  // -------------------------------------------------------------------------
  // COUNT
  // -------------------------------------------------------------------------

  private handleCount(ws: WebSocket, msg: Record<string, unknown>, seq?: number): void {
    const { pubkey, ts, sig } = msg;
    if (typeof pubkey !== 'string') return this.error(ws, 'COUNT: pubkey required', seq);
    if (typeof ts !== 'number') return this.error(ws, 'COUNT: ts required', seq);
    if (typeof sig !== 'string') return this.error(ws, 'COUNT: sig required', seq);

    if (!this.validateCommandSignature('COUNT', pubkey, ts, sig)) {
      return this.error(ws, 'COUNT: signature/timestamp verification failed', seq);
    }

    const count = this.store.count(pubkey);
    this.send(ws, { ok: true, count }, seq);
  }

  // -------------------------------------------------------------------------
  // Shared signature validation for LOOK / FETCH / COUNT
  // -------------------------------------------------------------------------

  private validateCommandSignature(
    cmdName: string,
    pubkeyHex: string,
    ts: number,
    sigHex: string,
  ): boolean {
    // Timestamp freshness
    const nowSec = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSec - ts) > this.tolerance) return false;

    let pubkeyBytes: Uint8Array;
    let sigBytes: Uint8Array;
    try {
      pubkeyBytes = hexToBytes(pubkeyHex);
      sigBytes = hexToBytes(sigHex);
    } catch {
      return false;
    }

    if (!isValidPoint(pubkeyBytes)) return false;

    const payload = encodeCommandPayload(cmdName, ts);
    return schnorrVerify(pubkeyBytes, payload, sigBytes);
  }

  // -------------------------------------------------------------------------
  // S2S (server-to-server) message handling
  // -------------------------------------------------------------------------

  private handleS2SMessage(ws: WebSocket, raw: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return;
    }

    const cmd = msg['cmd'];

    if (cmd === 'S2S_LOOK') {
      const pubkey = msg['pubkey'];
      const correlId = msg['correlId'];
      if (typeof pubkey !== 'string' || typeof correlId !== 'number') return;
      const messageIds = this.store.getIds(pubkey);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ cmd: 'S2S_LOOK_RESP', correlId, messageIds }));
      }
      return;
    }

    if (cmd === 'S2S_FETCH') {
      const messageId = msg['messageId'];
      const correlId = msg['correlId'];
      if (typeof messageId !== 'string' || typeof correlId !== 'number') return;
      const entry = this.store.getMail(messageId);
      const mailHex = entry ? bytesToHex(entry.mail) : null;
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ cmd: 'S2S_FETCH_RESP', correlId, mail: mailHex }));
      }
      return;
    }

    // Responses to our outgoing S2S requests
    if (cmd === 'S2S_LOOK_RESP') {
      const correlId = msg['correlId'];
      const messageIds = msg['messageIds'];
      if (typeof correlId !== 'number' || !Array.isArray(messageIds)) return;
      const pending = this.pendingLooks.get(correlId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingLooks.delete(correlId);
        pending.resolve(messageIds as string[]);
      }
      return;
    }

    if (cmd === 'S2S_FETCH_RESP') {
      const correlId = msg['correlId'];
      const mailHex = msg['mail'];
      if (typeof correlId !== 'number') return;
      const pending = this.pendingFetches.get(correlId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingFetches.delete(correlId);
        if (typeof mailHex === 'string') {
          try {
            pending.resolve(hexToBytes(mailHex));
          } catch {
            pending.resolve(null);
          }
        } else {
          pending.resolve(null);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // S2S federation helpers
  // -------------------------------------------------------------------------

  /** Broadcast S2S_LOOK to all peers and collect combined results. */
  private federateLook(pubkey: string): Promise<string[]> {
    const peerArray = [...this.peers].filter((ws) => ws.readyState === WebSocket.OPEN);
    if (peerArray.length === 0) return Promise.resolve([]);

    return Promise.all(
      peerArray.map(
        (ws) =>
          new Promise<string[]>((resolve) => {
            const correlId = this.nextCorrelId++;
            const timer = setTimeout(() => {
              this.pendingLooks.delete(correlId);
              resolve([]);
            }, 5000);
            this.pendingLooks.set(correlId, { resolve, timer });
            ws.send(JSON.stringify({ cmd: 'S2S_LOOK', pubkey, correlId }));
          }),
      ),
    ).then((arrays) => arrays.flat());
  }

  /** Ask all peers for a specific mail (stops at first positive response). */
  private async federateFetch(messageId: string): Promise<Uint8Array | null> {
    for (const ws of this.peers) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const result = await new Promise<Uint8Array | null>((resolve) => {
        const correlId = this.nextCorrelId++;
        const timer = setTimeout(() => {
          this.pendingFetches.delete(correlId);
          resolve(null);
        }, 5000);
        this.pendingFetches.set(correlId, { resolve, timer });
        ws.send(JSON.stringify({ cmd: 'S2S_FETCH', messageId, correlId }));
      });
      if (result) return result;
    }
    return null;
  }

  /** Register an already-connected peer WebSocket (e.g. when a peer connects in). */
  addPeerConnection(ws: WebSocket): void {
    this.peers.add(ws);
    ws.on('message', (data) => this.handleS2SMessage(ws, data.toString()));
    ws.on('close', () => this.peers.delete(ws));
    ws.on('error', () => ws.terminate());
  }
}
