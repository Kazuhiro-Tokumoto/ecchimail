import { WebSocketServer, WebSocket } from "ws";
import { createServer } from "https";
import { readFileSync } from "fs";
import { cipher } from "./cryptos/xor.js";
import { PointPairSchnorrP256 } from "./cryptos/ecdsa.js";

// ─── 型定義 ─────────────────────────────────────────────

/** 署名: [Rx, Ry, s] 各Uint8Array */
type Signature = [Uint8Array, Uint8Array, Uint8Array];

/** 公開鍵: [X, Y] 各Uint8Array (32bytes) */
type PubKey = [Uint8Array, Uint8Array];

/** クライアント → サーバ: SEND */
interface CmdSend {
    cmd: "SEND";
    mail: number[];  // メール全体 (Uint8Array → number[] でJSON化)
}

/** クライアント → サーバ: LOOK */
interface CmdLook {
    cmd: "LOOK";
    pubkey: number[];       // 受信者の公開鍵 (65 bytes: 04||X||Y)
    timestamp: number;       // Unix秒
    sig: [number[], number[], number[]];  // Schnorr署名(Rx, Ry, s)
}

/** クライアント → サーバ: FETCH */
interface CmdFetch {
    cmd: "FETCH";
    pubkey: number[];
    messageId: string;       // hex
    timestamp: number;
    sig: [number[], number[], number[]];
}

/** クライアント → サーバ: ACK */
interface CmdAck {
    cmd: "ACK";
    pubkey: number[];
    messageId: string;
    sig: [number[], number[], number[]];
}

/** クライアント → サーバ: DELETE */
interface CmdDelete {
    cmd: "DELETE";
    pubkey: number[];
    messageId: string;
    sig: [number[], number[], number[]];
}

/** クライアント → サーバ: COUNT */
interface CmdCount {
    cmd: "COUNT";
    pubkey: number[];
    timestamp: number;
    sig: [number[], number[], number[]];
}

type ClientCommand = CmdSend | CmdLook | CmdFetch | CmdAck | CmdDelete | CmdCount;

/** ピア間コマンド */
interface PeerLook {
    cmd: "PEER_LOOK";
    pubkey: string;  // hex
}

interface PeerFetch {
    cmd: "PEER_FETCH";
    pubkey: string;
    messageId: string;
}

interface PeerDelete {
    cmd: "PEER_DELETE";
    pubkey: string;
    messageId: string;
}

interface PeerLookOk {
    cmd: "PEER_LOOK_OK";
    ids: string[];
}

interface PeerFetchOk {
    cmd: "PEER_FETCH_OK";
    mail: number[];
}

interface PeerFetchFail {
    cmd: "PEER_FETCH_FAIL";
}

type PeerCommand = PeerLook | PeerFetch | PeerDelete | PeerLookOk | PeerFetchOk | PeerFetchFail;

// ─── サーバ本体 ─────────────────────────────────────────

export class ecchimailserverAPI {
    private mailbox: Map<string, Uint8Array[]>; // 公開鍵hex → メール[]
    private peers: WebSocket[];
    private wss: WebSocketServer;
    private schnorr: PointPairSchnorrP256;
    private hash: cipher;

    constructor(port: number, dnsSeed: string, domain: string, certPath?: string, keyPath?: string) {
        this.mailbox = new Map();
        this.peers = [];
        this.schnorr = new PointPairSchnorrP256();
        this.hash = new cipher();

        const useSSL = certPath !== undefined && keyPath !== undefined;
        const protocol = useSSL ? "wss" : "ws";

        if (useSSL) {
            // WSS (TLS)
            const httpsServer = createServer({
                cert: readFileSync(certPath),
                key: readFileSync(keyPath),
            });
            this.wss = new WebSocketServer({ server: httpsServer });
            this.wss.on("connection", (ws) => {
                ws.on("message", (raw) => {
                    this.handleMessage(ws, raw as Buffer);
                });
            });
            httpsServer.listen(port, () => {
                console.log(`ECCHImail node listening on wss://${domain}:${port}`);
            });
        } else {
            // WS (開発用)
            this.wss = new WebSocketServer({ port });
            this.wss.on("connection", (ws) => {
                ws.on("message", (raw) => {
                    this.handleMessage(ws, raw as Buffer);
                });
            });
            console.log(`ECCHImail node listening on ws://${domain}:${port}`);
        }

        // DNS TXTにはプロトコル付きで登録されている前提
        // e.g. "wss://mail.shudo-physics.com:8080" or "ws://localhost:8080"
        this.resolveNodes(dnsSeed).then(nodes => {
            nodes
                .filter(node => !node.includes(domain))
                .forEach(node => this.connectToPeer(node));
        });

        // 期限切れメールの定期クリーンアップ (1時間ごと)
        setInterval(() => this.cleanupExpiredMails(), 60 * 60 * 1000);
    }

    // ─── 期限切れメール削除 ─────────────────────────────
    private cleanupExpiredMails() {
        const now = this.now();
        let deleted = 0;
        for (const [pubkey, mails] of this.mailbox) {
            const before = mails.length;
            const kept = mails.filter(mail => {
                const ts = this.extractTimestamp(mail);
                return (now - ts) < ecchimailserverAPI.RETENTION_SECONDS;
            });
            deleted += before - kept.length;
            if (kept.length === 0) {
                this.mailbox.delete(pubkey);
            } else {
                this.mailbox.set(pubkey, kept);
            }
        }
        if (deleted > 0) {
            console.log(`Cleanup: ${deleted} expired mails removed`);
        }
    }

    // ─── DNS Seed ───────────────────────────────────────
    private async resolveNodes(dnsSeed: string): Promise<string[]> {
        try {
            const res = await fetch(
                `https://dns.google/resolve?name=${dnsSeed}&type=TXT`
            );
            const data = await res.json();
            return data.Answer?.map((r: any) => r.data.replace(/"/g, "")) ?? [];
        } catch {
            console.error("DNS seed resolution failed");
            return [];
        }
    }

    // ─── ピア接続 ───────────────────────────────────────
    private connectToPeer(node: string) {
        const ws = new WebSocket(node);
        ws.onopen = () => {
            console.log(`Connected to peer: ${node}`);
            this.peers.push(ws);
        };
        ws.onmessage = (event) => {
            this.handlePeerMessage(ws, event.data as Buffer);
        };
        ws.onclose = () => {
            console.log(`Disconnected from peer: ${node}`);
            this.peers = this.peers.filter(p => p !== ws);
        };
    }

    // ─── ユーティリティ ─────────────────────────────────

    /** number[] → Uint8Array */
    private toU8(arr: number[]): Uint8Array {
        return new Uint8Array(arr);
    }

    /** number[][] の署名 → Signature型 */
    private toSig(sig: [number[], number[], number[]]): Signature {
        return [this.toU8(sig[0]), this.toU8(sig[1]), this.toU8(sig[2])];
    }

    /** 65バイト非圧縮公開鍵 → PubKey [X, Y] */
    private uncompressPubkey(raw: Uint8Array): PubKey {
        // raw = 0x04 || X(32) || Y(32)
        return [raw.slice(1, 33), raw.slice(33, 65)];
    }

    private concat(...arrays: Uint8Array[]): Uint8Array {
        const total = arrays.reduce((n, a) => n + a.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) { out.set(a, offset); offset += a.length; }
        return out;
    }

    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    }

    private encodeUint64(n: number): Uint8Array {
        const buf = new Uint8Array(8);
        const view = new DataView(buf.buffer);
        view.setUint32(0, Math.floor(n / 0x100000000), false);
        view.setUint32(4, n >>> 0, false);
        return buf;
    }

    private sortKeys(a: Uint8Array, b: Uint8Array): [Uint8Array, Uint8Array] {
        for (let i = 0; i < a.length; i++) {
            if (a[i] < b[i]) return [a, b];
            if (a[i] > b[i]) return [b, a];
        }
        return [a, b];
    }

    private now(): number {
        return Math.floor(Date.now() / 1000);
    }

    // ─── メール解析 ─────────────────────────────────────
    // フォーマット: A(65) | Y(65) | f(32) | timestamp(8) | IV(16) | ciphertext(var) | hmac(32) | sig(64)

    private extractSender(mail: Uint8Array): Uint8Array {
        return mail.slice(0, 65);  // A
    }

    private extractRecipient(mail: Uint8Array): Uint8Array {
        return mail.slice(65, 130);  // Y
    }

    private extractTimestamp(mail: Uint8Array): number {
        const view = new DataView(mail.buffer, mail.byteOffset + 162, 8);
        return view.getUint32(0) * 0x100000000 + view.getUint32(4);
    }

    private extractIV(mail: Uint8Array): Uint8Array {
        return mail.slice(170, 186);
    }

    private extractSignature(mail: Uint8Array): Signature {
        const sig = mail.slice(-64);
        // Schnorr署名は [Rx(32), Ry(32), s(32)] だが
        // メール内は [r||s] = 64バイト... 
        // ecdsa.tsの署名は [Rx, Ry, s] で96バイト
        // ここは実装に合わせる必要がある
        // ecdsa.ts の sign は [Rx(var), Ry(var), s(var)] を返す
        // メールフォーマットを合わせる: 署名は96バイト [Rx(32)||Ry(32)||s(32)]
        return [
            mail.slice(-96, -64),   // Rx
            mail.slice(-64, -32),   // Ry
            mail.slice(-32),        // s
        ];
    }

    /** メールからmessage_idを計算 */
    private computeMessageId(mail: Uint8Array): string {
        const A = this.extractSender(mail);
        const Y = this.extractRecipient(mail);
        const timestamp = mail.slice(162, 170);
        const iv = this.extractIV(mail);

        const [minKey, maxKey] = this.sortKeys(A, Y);
        const data = this.concat(timestamp, minKey, maxKey, iv);
        return this.bytesToHex(this.hash.sha256(data));
    }

    /** message_idのUint8Arrayを計算（署名検証用） */
    private computeMessageIdBytes(mail: Uint8Array): Uint8Array {
        const A = this.extractSender(mail);
        const Y = this.extractRecipient(mail);
        const timestamp = mail.slice(162, 170);
        const iv = this.extractIV(mail);

        const [minKey, maxKey] = this.sortKeys(A, Y);
        return this.hash.sha256(this.concat(timestamp, minKey, maxKey, iv));
    }

    /** コマンド署名対象を構築: "COMMAND" || timestamp */
    private buildCommandSigTarget(command: string, timestamp: number): Uint8Array {
        return this.concat(
            new TextEncoder().encode(command),
            this.encodeUint64(timestamp),
        );
    }

    // ─── 署名検証 ───────────────────────────────────────

    /** メール送信時の署名検証: 送信者Aでmessage_idを検証 */
    private verifySendSignature(mail: Uint8Array): boolean {
        const A = this.uncompressPubkey(this.extractSender(mail));
        const messageId = this.computeMessageIdBytes(mail);
        const sig = this.extractSignature(mail);
        return this.schnorr.verify(messageId, A, sig);
    }

    /** コマンド署名検証: pubkeyでcommand||timestampを検証 */
    private verifyCommandSignature(
        pubkeyRaw: Uint8Array,
        command: string,
        timestamp: number,
        sig: Signature,
    ): boolean {
        // タイムスタンプ鮮度: ±5分
        if (Math.abs(this.now() - timestamp) > 300) return false;
        const target = this.buildCommandSigTarget(command, timestamp);
        const pubkey = this.uncompressPubkey(pubkeyRaw);
        return this.schnorr.verify(target, pubkey, sig);
    }

    /** ACK/DELETE署名検証: pubkeyでmessage_idを検証 */
    private verifyMessageIdSignature(
        pubkeyRaw: Uint8Array,
        messageId: string,
        sig: Signature,
    ): boolean {
        const pubkey = this.uncompressPubkey(pubkeyRaw);
        const idBytes = this.hexToBytes(messageId);
        return this.schnorr.verify(idBytes, pubkey, sig);
    }

    private hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    // ─── クライアントコマンド処理 ───────────────────────

    private handleMessage(ws: WebSocket, raw: Buffer) {
        let msg: ClientCommand;
        try {
            msg = JSON.parse(raw.toString());
        } catch {
            ws.send(JSON.stringify({ error: "invalid JSON" }));
            return;
        }

        switch (msg.cmd) {
            case "SEND":    this.handleSend(ws, msg);    break;
            case "LOOK":    this.handleLook(ws, msg);    break;
            case "FETCH":   this.handleFetch(ws, msg);   break;
            case "ACK":     this.handleAck(ws, msg);     break;
            case "DELETE":  this.handleDelete(ws, msg);  break;
            case "COUNT":   this.handleCount(ws, msg);   break;
            default:
                ws.send(JSON.stringify({ error: "unknown command" }));
        }
    }

    // ─── SEND ───────────────────────────────────────────
    private static readonly MAX_MAIL_SIZE = 50 * 1024; // 50KB
    private static readonly RETENTION_SECONDS = 5 * 24 * 60 * 60; // 5日

    private handleSend(ws: WebSocket, msg: CmdSend) {
        const mail = this.toU8(msg.mail);

        // メールサイズ上限チェック (50KB)
        if (mail.length > ecchimailserverAPI.MAX_MAIL_SIZE) {
            ws.send(JSON.stringify({ cmd: "SEND_FAIL", error: "mail too large (max 50KB)" }));
            return;
        }

        // メールサイズ最小チェック (282 bytes: 空本文+署名96バイト版)
        if (mail.length < 65 + 65 + 32 + 8 + 16 + 32 + 96) {
            ws.send(JSON.stringify({ cmd: "SEND_FAIL", error: "mail too short" }));
            return;
        }

        // タイムスタンプ鮮度チェック
        const ts = this.extractTimestamp(mail);
        if (Math.abs(this.now() - ts) > 300) {
            ws.send(JSON.stringify({ cmd: "SEND_FAIL", error: "timestamp expired" }));
            return;
        }

        // 署名検証
        if (!this.verifySendSignature(mail)) {
            ws.send(JSON.stringify({ cmd: "SEND_FAIL", error: "invalid signature" }));
            return;
        }

        // メールボックスに保管
        const Y = this.bytesToHex(this.extractRecipient(mail));
        if (!this.mailbox.has(Y)) this.mailbox.set(Y, []);
        this.mailbox.get(Y)!.push(mail);

        ws.send(JSON.stringify({ cmd: "SEND_OK" }));
    }

    // ─── LOOK ───────────────────────────────────────────
    private handleLook(ws: WebSocket, msg: CmdLook) {
        const pubkeyRaw = this.toU8(msg.pubkey);
        const sig = this.toSig(msg.sig);

        if (!this.verifyCommandSignature(pubkeyRaw, "LOOK", msg.timestamp, sig)) {
            ws.send(JSON.stringify({ cmd: "LOOK_FAIL", error: "invalid signature" }));
            return;
        }

        const pubkeyHex = this.bytesToHex(pubkeyRaw);
        const localIds = this.getMessageIds(pubkeyHex);

        this.askPeersForLook(pubkeyHex).then(peerIds => {
            const allIds = [...new Set([...localIds, ...peerIds])]; // 重複排除
            ws.send(JSON.stringify({ cmd: "LOOK_OK", ids: allIds }));
        });
    }

    // ─── FETCH ──────────────────────────────────────────
    private handleFetch(ws: WebSocket, msg: CmdFetch) {
        const pubkeyRaw = this.toU8(msg.pubkey);
        const sig = this.toSig(msg.sig);

        if (!this.verifyCommandSignature(pubkeyRaw, "FETCH", msg.timestamp, sig)) {
            ws.send(JSON.stringify({ cmd: "FETCH_FAIL", error: "invalid signature" }));
            return;
        }

        const pubkeyHex = this.bytesToHex(pubkeyRaw);
        const mail = this.findMail(pubkeyHex, msg.messageId);
        if (mail) {
            ws.send(JSON.stringify({ cmd: "FETCH_OK", mail: Array.from(mail) }));
            return;
        }

        this.askPeersForFetch(pubkeyHex, msg.messageId).then(peerMail => {
            if (peerMail) {
                ws.send(JSON.stringify({ cmd: "FETCH_OK", mail: Array.from(peerMail) }));
            } else {
                ws.send(JSON.stringify({ cmd: "FETCH_FAIL", error: "not found" }));
            }
        });
    }

    // ─── ACK ────────────────────────────────────────────
    private handleAck(ws: WebSocket, msg: CmdAck) {
        const pubkeyRaw = this.toU8(msg.pubkey);
        const sig = this.toSig(msg.sig);

        if (!this.verifyMessageIdSignature(pubkeyRaw, msg.messageId, sig)) {
            ws.send(JSON.stringify({ cmd: "ACK_FAIL", error: "invalid signature" }));
            return;
        }

        const pubkeyHex = this.bytesToHex(pubkeyRaw);
        const deleted = this.deleteMail(pubkeyHex, msg.messageId);
        this.broadcastDelete(pubkeyHex, msg.messageId);
        ws.send(JSON.stringify({ cmd: "ACK_OK", deleted }));
    }

    // ─── DELETE ──────────────────────────────────────────
    private handleDelete(ws: WebSocket, msg: CmdDelete) {
        const pubkeyRaw = this.toU8(msg.pubkey);
        const sig = this.toSig(msg.sig);

        if (!this.verifyMessageIdSignature(pubkeyRaw, msg.messageId, sig)) {
            ws.send(JSON.stringify({ cmd: "DELETE_FAIL", error: "invalid signature" }));
            return;
        }

        const pubkeyHex = this.bytesToHex(pubkeyRaw);
        const deleted = this.deleteMail(pubkeyHex, msg.messageId);
        this.broadcastDelete(pubkeyHex, msg.messageId);
        ws.send(JSON.stringify({ cmd: "DELETE_OK", deleted }));
    }

    // ─── COUNT ──────────────────────────────────────────
    private handleCount(ws: WebSocket, msg: CmdCount) {
        const pubkeyRaw = this.toU8(msg.pubkey);
        const sig = this.toSig(msg.sig);

        if (!this.verifyCommandSignature(pubkeyRaw, "COUNT", msg.timestamp, sig)) {
            ws.send(JSON.stringify({ cmd: "COUNT_FAIL", error: "invalid signature" }));
            return;
        }

        const pubkeyHex = this.bytesToHex(pubkeyRaw);
        const localCount = this.mailbox.get(pubkeyHex)?.length ?? 0;
        // TODO: ピアにも問い合わせて合算
        ws.send(JSON.stringify({ cmd: "COUNT_OK", count: localCount }));
    }

    // ─── ピア間通信 ─────────────────────────────────────

    private handlePeerMessage(ws: WebSocket, raw: Buffer) {
        let msg: PeerCommand;
        try {
            msg = JSON.parse(raw.toString());
        } catch { return; }

        switch (msg.cmd) {
            case "PEER_LOOK":   this.handlePeerLook(ws, msg);   break;
            case "PEER_FETCH":  this.handlePeerFetch(ws, msg);  break;
            case "PEER_DELETE": this.handlePeerDelete(msg);      break;
            default: break;
        }
    }

    private handlePeerLook(ws: WebSocket, msg: PeerLook) {
        const ids = this.getMessageIds(msg.pubkey);
        ws.send(JSON.stringify({ cmd: "PEER_LOOK_OK", ids } satisfies PeerLookOk));
    }

    private handlePeerFetch(ws: WebSocket, msg: PeerFetch) {
        const mail = this.findMail(msg.pubkey, msg.messageId);
        if (mail) {
            ws.send(JSON.stringify({ cmd: "PEER_FETCH_OK", mail: Array.from(mail) } satisfies PeerFetchOk));
        } else {
            ws.send(JSON.stringify({ cmd: "PEER_FETCH_FAIL" } satisfies PeerFetchFail));
        }
    }

    private handlePeerDelete(msg: PeerDelete) {
        this.deleteMail(msg.pubkey, msg.messageId);
    }

    private async askPeersForLook(pubkeyHex: string): Promise<string[]> {
        const results: string[] = [];
        const promises = this.peers.map(peer => {
            return new Promise<void>((resolve) => {
                const timeout = setTimeout(() => resolve(), 3000);
                const handler = (data: Buffer) => {
                    try {
                        const resp = JSON.parse(data.toString()) as PeerLookOk;
                        if (resp.cmd === "PEER_LOOK_OK") {
                            results.push(...resp.ids);
                            clearTimeout(timeout);
                            peer.off("message", handler);
                            resolve();
                        }
                    } catch { /* ignore */ }
                };
                peer.on("message", handler);
                peer.send(JSON.stringify({ cmd: "PEER_LOOK", pubkey: pubkeyHex } satisfies PeerLook));
            });
        });
        await Promise.all(promises);
        return results;
    }

    private async askPeersForFetch(pubkeyHex: string, messageId: string): Promise<Uint8Array | null> {
        for (const peer of this.peers) {
            const result = await new Promise<Uint8Array | null>((resolve) => {
                const timeout = setTimeout(() => resolve(null), 3000);
                const handler = (data: Buffer) => {
                    try {
                        const resp = JSON.parse(data.toString());
                        if (resp.cmd === "PEER_FETCH_OK") {
                            clearTimeout(timeout);
                            peer.off("message", handler);
                            resolve(this.toU8(resp.mail));
                        } else if (resp.cmd === "PEER_FETCH_FAIL") {
                            clearTimeout(timeout);
                            peer.off("message", handler);
                            resolve(null);
                        }
                    } catch { /* ignore */ }
                };
                peer.on("message", handler);
                peer.send(JSON.stringify({ cmd: "PEER_FETCH", pubkey: pubkeyHex, messageId } satisfies PeerFetch));
            });
            if (result) return result;
        }
        return null;
    }

    private broadcastDelete(pubkeyHex: string, messageId: string) {
        const msg: PeerDelete = { cmd: "PEER_DELETE", pubkey: pubkeyHex, messageId };
        this.peers.forEach(peer => {
            peer.send(JSON.stringify(msg));
        });
    }

    // ─── メールボックス操作 ─────────────────────────────

    private getMessageIds(pubkeyHex: string): string[] {
        const mails = this.mailbox.get(pubkeyHex) ?? [];
        return mails.map(m => this.computeMessageId(m));
    }

    private findMail(pubkeyHex: string, messageId: string): Uint8Array | null {
        const mails = this.mailbox.get(pubkeyHex) ?? [];
        return mails.find(m => this.computeMessageId(m) === messageId) ?? null;
    }

    private deleteMail(pubkeyHex: string, messageId: string): boolean {
        const mails = this.mailbox.get(pubkeyHex);
        if (!mails) return false;
        const idx = mails.findIndex(m => this.computeMessageId(m) === messageId);
        if (idx === -1) return false;
        mails.splice(idx, 1);
        return true;
    }
}