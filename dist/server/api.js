import { WebSocketServer, WebSocket } from "ws";
import { createServer } from "https";
import { readFileSync } from "fs";
import { cipher } from "./cryptos/xor.js";
import { PointPairSchnorrP256 } from "./cryptos/ecdsa.js";
// ─── サーバ本体 ─────────────────────────────────────────
export class ecchimailserverAPI {
    mailbox; // 公開鍵hex → メール[]
    peers;
    wss;
    schnorr;
    hash;
    constructor(port, dnsSeed, certPath, keyPath, domain) {
        this.mailbox = new Map();
        this.peers = [];
        this.schnorr = new PointPairSchnorrP256();
        this.hash = new cipher();
        // HTTPS + WSS
        const httpsServer = createServer({
            cert: readFileSync(certPath),
            key: readFileSync(keyPath),
        });
        this.wss = new WebSocketServer({ server: httpsServer });
        this.wss.on("connection", (ws) => {
            ws.on("message", (raw) => {
                this.handleMessage(ws, raw);
            });
        });
        httpsServer.listen(port, () => {
            console.log(`ECCHImail node listening on wss://${domain}:${port}`);
        });
        // DNS TXT引いてノード一覧取得 → 自分を除外して接続
        this.resolveNodes(dnsSeed).then(nodes => {
            nodes
                .filter(node => !node.includes(domain))
                .forEach(node => this.connectToPeer(node));
        });
    }
    // ─── DNS Seed ───────────────────────────────────────
    async resolveNodes(dnsSeed) {
        try {
            const res = await fetch(`https://dns.google/resolve?name=${dnsSeed}&type=TXT`);
            const data = await res.json();
            return data.Answer?.map((r) => r.data.replace(/"/g, "")) ?? [];
        }
        catch {
            console.error("DNS seed resolution failed");
            return [];
        }
    }
    // ─── ピア接続 ───────────────────────────────────────
    connectToPeer(node) {
        const ws = new WebSocket(node);
        ws.onopen = () => {
            console.log(`Connected to peer: ${node}`);
            this.peers.push(ws);
        };
        ws.onmessage = (event) => {
            this.handlePeerMessage(ws, event.data);
        };
        ws.onclose = () => {
            console.log(`Disconnected from peer: ${node}`);
            this.peers = this.peers.filter(p => p !== ws);
        };
    }
    // ─── ユーティリティ ─────────────────────────────────
    /** number[] → Uint8Array */
    toU8(arr) {
        return new Uint8Array(arr);
    }
    /** number[][] の署名 → Signature型 */
    toSig(sig) {
        return [this.toU8(sig[0]), this.toU8(sig[1]), this.toU8(sig[2])];
    }
    /** 65バイト非圧縮公開鍵 → PubKey [X, Y] */
    uncompressPubkey(raw) {
        // raw = 0x04 || X(32) || Y(32)
        return [raw.slice(1, 33), raw.slice(33, 65)];
    }
    concat(...arrays) {
        const total = arrays.reduce((n, a) => n + a.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) {
            out.set(a, offset);
            offset += a.length;
        }
        return out;
    }
    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    }
    encodeUint64(n) {
        const buf = new Uint8Array(8);
        const view = new DataView(buf.buffer);
        view.setUint32(0, Math.floor(n / 0x100000000), false);
        view.setUint32(4, n >>> 0, false);
        return buf;
    }
    sortKeys(a, b) {
        for (let i = 0; i < a.length; i++) {
            if (a[i] < b[i])
                return [a, b];
            if (a[i] > b[i])
                return [b, a];
        }
        return [a, b];
    }
    now() {
        return Math.floor(Date.now() / 1000);
    }
    // ─── メール解析 ─────────────────────────────────────
    // フォーマット: A(65) | Y(65) | f(32) | timestamp(8) | IV(16) | ciphertext(var) | hmac(32) | sig(64)
    extractSender(mail) {
        return mail.slice(0, 65); // A
    }
    extractRecipient(mail) {
        return mail.slice(65, 130); // Y
    }
    extractTimestamp(mail) {
        const view = new DataView(mail.buffer, mail.byteOffset + 162, 8);
        return view.getUint32(0) * 0x100000000 + view.getUint32(4);
    }
    extractIV(mail) {
        return mail.slice(170, 186);
    }
    extractSignature(mail) {
        const sig = mail.slice(-64);
        // Schnorr署名は [Rx(32), Ry(32), s(32)] だが
        // メール内は [r||s] = 64バイト... 
        // ecdsa.tsの署名は [Rx, Ry, s] で96バイト
        // ここは実装に合わせる必要がある
        // ecdsa.ts の sign は [Rx(var), Ry(var), s(var)] を返す
        // メールフォーマットを合わせる: 署名は96バイト [Rx(32)||Ry(32)||s(32)]
        return [
            mail.slice(-96, -64), // Rx
            mail.slice(-64, -32), // Ry
            mail.slice(-32), // s
        ];
    }
    /** メールからmessage_idを計算 */
    computeMessageId(mail) {
        const A = this.extractSender(mail);
        const Y = this.extractRecipient(mail);
        const timestamp = mail.slice(162, 170);
        const iv = this.extractIV(mail);
        const [minKey, maxKey] = this.sortKeys(A, Y);
        const data = this.concat(timestamp, minKey, maxKey, iv);
        return this.bytesToHex(this.hash.sha256(data));
    }
    /** message_idのUint8Arrayを計算（署名検証用） */
    computeMessageIdBytes(mail) {
        const A = this.extractSender(mail);
        const Y = this.extractRecipient(mail);
        const timestamp = mail.slice(162, 170);
        const iv = this.extractIV(mail);
        const [minKey, maxKey] = this.sortKeys(A, Y);
        return this.hash.sha256(this.concat(timestamp, minKey, maxKey, iv));
    }
    /** コマンド署名対象を構築: "COMMAND" || timestamp */
    buildCommandSigTarget(command, timestamp) {
        return this.concat(new TextEncoder().encode(command), this.encodeUint64(timestamp));
    }
    // ─── 署名検証 ───────────────────────────────────────
    /** メール送信時の署名検証: 送信者Aでmessage_idを検証 */
    verifySendSignature(mail) {
        const A = this.uncompressPubkey(this.extractSender(mail));
        const messageId = this.computeMessageIdBytes(mail);
        const sig = this.extractSignature(mail);
        return this.schnorr.verify(messageId, A, sig);
    }
    /** コマンド署名検証: pubkeyでcommand||timestampを検証 */
    verifyCommandSignature(pubkeyRaw, command, timestamp, sig) {
        // タイムスタンプ鮮度: ±5分
        if (Math.abs(this.now() - timestamp) > 300)
            return false;
        const target = this.buildCommandSigTarget(command, timestamp);
        const pubkey = this.uncompressPubkey(pubkeyRaw);
        return this.schnorr.verify(target, pubkey, sig);
    }
    /** ACK/DELETE署名検証: pubkeyでmessage_idを検証 */
    verifyMessageIdSignature(pubkeyRaw, messageId, sig) {
        const pubkey = this.uncompressPubkey(pubkeyRaw);
        const idBytes = this.hexToBytes(messageId);
        return this.schnorr.verify(idBytes, pubkey, sig);
    }
    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
    // ─── クライアントコマンド処理 ───────────────────────
    handleMessage(ws, raw) {
        let msg;
        try {
            msg = JSON.parse(raw.toString());
        }
        catch {
            ws.send(JSON.stringify({ error: "invalid JSON" }));
            return;
        }
        switch (msg.cmd) {
            case "SEND":
                this.handleSend(ws, msg);
                break;
            case "LOOK":
                this.handleLook(ws, msg);
                break;
            case "FETCH":
                this.handleFetch(ws, msg);
                break;
            case "ACK":
                this.handleAck(ws, msg);
                break;
            case "DELETE":
                this.handleDelete(ws, msg);
                break;
            case "COUNT":
                this.handleCount(ws, msg);
                break;
            default:
                ws.send(JSON.stringify({ error: "unknown command" }));
        }
    }
    // ─── SEND ───────────────────────────────────────────
    handleSend(ws, msg) {
        const mail = this.toU8(msg.mail);
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
        if (!this.mailbox.has(Y))
            this.mailbox.set(Y, []);
        this.mailbox.get(Y).push(mail);
        ws.send(JSON.stringify({ cmd: "SEND_OK" }));
    }
    // ─── LOOK ───────────────────────────────────────────
    handleLook(ws, msg) {
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
    handleFetch(ws, msg) {
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
            }
            else {
                ws.send(JSON.stringify({ cmd: "FETCH_FAIL", error: "not found" }));
            }
        });
    }
    // ─── ACK ────────────────────────────────────────────
    handleAck(ws, msg) {
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
    handleDelete(ws, msg) {
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
    handleCount(ws, msg) {
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
    handlePeerMessage(ws, raw) {
        let msg;
        try {
            msg = JSON.parse(raw.toString());
        }
        catch {
            return;
        }
        switch (msg.cmd) {
            case "PEER_LOOK":
                this.handlePeerLook(ws, msg);
                break;
            case "PEER_FETCH":
                this.handlePeerFetch(ws, msg);
                break;
            case "PEER_DELETE":
                this.handlePeerDelete(msg);
                break;
            default: break;
        }
    }
    handlePeerLook(ws, msg) {
        const ids = this.getMessageIds(msg.pubkey);
        ws.send(JSON.stringify({ cmd: "PEER_LOOK_OK", ids }));
    }
    handlePeerFetch(ws, msg) {
        const mail = this.findMail(msg.pubkey, msg.messageId);
        if (mail) {
            ws.send(JSON.stringify({ cmd: "PEER_FETCH_OK", mail: Array.from(mail) }));
        }
        else {
            ws.send(JSON.stringify({ cmd: "PEER_FETCH_FAIL" }));
        }
    }
    handlePeerDelete(msg) {
        this.deleteMail(msg.pubkey, msg.messageId);
    }
    async askPeersForLook(pubkeyHex) {
        const results = [];
        const promises = this.peers.map(peer => {
            return new Promise((resolve) => {
                const timeout = setTimeout(() => resolve(), 3000);
                const handler = (data) => {
                    try {
                        const resp = JSON.parse(data.toString());
                        if (resp.cmd === "PEER_LOOK_OK") {
                            results.push(...resp.ids);
                            clearTimeout(timeout);
                            peer.off("message", handler);
                            resolve();
                        }
                    }
                    catch { /* ignore */ }
                };
                peer.on("message", handler);
                peer.send(JSON.stringify({ cmd: "PEER_LOOK", pubkey: pubkeyHex }));
            });
        });
        await Promise.all(promises);
        return results;
    }
    async askPeersForFetch(pubkeyHex, messageId) {
        for (const peer of this.peers) {
            const result = await new Promise((resolve) => {
                const timeout = setTimeout(() => resolve(null), 3000);
                const handler = (data) => {
                    try {
                        const resp = JSON.parse(data.toString());
                        if (resp.cmd === "PEER_FETCH_OK") {
                            clearTimeout(timeout);
                            peer.off("message", handler);
                            resolve(this.toU8(resp.mail));
                        }
                        else if (resp.cmd === "PEER_FETCH_FAIL") {
                            clearTimeout(timeout);
                            peer.off("message", handler);
                            resolve(null);
                        }
                    }
                    catch { /* ignore */ }
                };
                peer.on("message", handler);
                peer.send(JSON.stringify({ cmd: "PEER_FETCH", pubkey: pubkeyHex, messageId }));
            });
            if (result)
                return result;
        }
        return null;
    }
    broadcastDelete(pubkeyHex, messageId) {
        const msg = { cmd: "PEER_DELETE", pubkey: pubkeyHex, messageId };
        this.peers.forEach(peer => {
            peer.send(JSON.stringify(msg));
        });
    }
    // ─── メールボックス操作 ─────────────────────────────
    getMessageIds(pubkeyHex) {
        const mails = this.mailbox.get(pubkeyHex) ?? [];
        return mails.map(m => this.computeMessageId(m));
    }
    findMail(pubkeyHex, messageId) {
        const mails = this.mailbox.get(pubkeyHex) ?? [];
        return mails.find(m => this.computeMessageId(m) === messageId) ?? null;
    }
    deleteMail(pubkeyHex, messageId) {
        const mails = this.mailbox.get(pubkeyHex);
        if (!mails)
            return false;
        const idx = mails.findIndex(m => this.computeMessageId(m) === messageId);
        if (idx === -1)
            return false;
        mails.splice(idx, 1);
        return true;
    }
}
