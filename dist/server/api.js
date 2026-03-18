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
    seenRequests = new Map(); // requestId → timestamp
    appClients = new Map(); // app名 → WebSocket
    static DEFAULT_TTL = 255;
    static ENVELOPE_TIMEOUT = 30; // 秒
    constructor(port, dnsSeed, domain, certPath, keyPath) {
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
                this.handleNewConnection(ws);
            });
            httpsServer.listen(port, () => {
                console.log(`ECCHImail node listening on wss://${domain}:${port}`);
            });
        }
        else {
            // WS (開発用)
            this.wss = new WebSocketServer({ port });
            this.wss.on("connection", (ws) => {
                this.handleNewConnection(ws);
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
        // DNSノード再発見 (1時間ごと)
        setInterval(() => this.refreshPeers(dnsSeed, domain), 60 * 60 * 1000);
        // seenキャッシュクリーンアップ (30秒ごと)
        setInterval(() => this.cleanupSeen(), 30 * 1000);
        // ─── ローカルApp APIサーバ (localhost:5000) ──────────
        const appServer = new WebSocketServer({ port: 5000 });
        appServer.on("connection", (ws) => {
            let appName = "";
            ws.on("message", (raw) => {
                try {
                    const msg = JSON.parse(raw.toString());
                    // 最初のメッセージで app 登録
                    if (!appName && msg.app) {
                        appName = msg.app;
                        this.appClients.set(appName, ws);
                        console.log(`App registered: ${appName}`);
                        ws.send(JSON.stringify({ status: "registered", app: appName }));
                        return;
                    }
                    // 登録済みなら、ピアに転送 (1KB制限)
                    if (appName) {
                        const size = raw.toString().length;
                        if (size > 1024) {
                            ws.send(JSON.stringify({ error: "payload too large (max 1KB)" }));
                            return;
                        }
                        this.broadcastToPeers(msg, undefined, appName);
                    }
                }
                catch { /* ignore */ }
            });
            ws.on("close", () => {
                if (appName) {
                    this.appClients.delete(appName);
                    console.log(`App disconnected: ${appName}`);
                }
            });
        });
        console.log("App API listening on ws://localhost:5000");
    }
    // ─── ピア再発見 ─────────────────────────────────────
    connectedUrls = new Set();
    async refreshPeers(dnsSeed, domain) {
        const nodes = await this.resolveNodes(dnsSeed);
        const newNodes = nodes
            .filter(node => !node.includes(domain))
            .filter(node => !this.connectedUrls.has(node));
        for (const node of newNodes) {
            console.log(`New peer discovered: ${node}`);
            this.connectToPeer(node);
        }
    }
    // ─── 期限切れメール削除 ─────────────────────────────
    cleanupExpiredMails() {
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
            }
            else {
                this.mailbox.set(pubkey, kept);
            }
        }
        if (deleted > 0) {
            console.log(`Cleanup: ${deleted} expired mails removed`);
        }
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
        this.connectedUrls.add(node);
        const ws = new WebSocket(node);
        ws.onopen = () => {
            console.log(`Connected to peer: ${node}`);
            // ピアとして名乗る
            ws.send(JSON.stringify({ cmd: "HELLO", role: "peer" }));
            this.peers.push(ws);
        };
        ws.onmessage = (event) => {
            this.handlePeerMessage(ws, event.data);
        };
        ws.onclose = () => {
            console.log(`Disconnected from peer: ${node}`);
            this.peers = this.peers.filter(p => p !== ws);
            this.connectedUrls.delete(node);
        };
    }
    // ─── 新規接続の振り分け ─────────────────────────────
    handleNewConnection(ws) {
        let identified = false;
        const firstMessageHandler = (raw) => {
            try {
                const msg = JSON.parse(raw.toString());
                if (msg.cmd === "HELLO" && msg.role === "peer") {
                    // ピアとして登録
                    identified = true;
                    console.log("Incoming peer connected");
                    this.peers.push(ws);
                    ws.off("message", firstMessageHandler);
                    ws.on("message", (data) => {
                        this.handlePeerMessage(ws, data);
                    });
                    ws.on("close", () => {
                        console.log("Incoming peer disconnected");
                        this.peers = this.peers.filter(p => p !== ws);
                    });
                    return;
                }
            }
            catch { /* not JSON or not HELLO */ }
            // HELLOじゃなかったらクライアントとして扱う
            identified = true;
            ws.off("message", firstMessageHandler);
            // 最初のメッセージもクライアントコマンドとして処理
            this.handleMessage(ws, raw);
            ws.on("message", (data) => {
                this.handleMessage(ws, data);
            });
        };
        ws.on("message", firstMessageHandler);
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
    static MAX_MAIL_SIZE = 50 * 1024; // 50KB
    static RETENTION_SECONDS = 5 * 24 * 60 * 60; // 5日
    handleSend(ws, msg) {
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
    /** seenキャッシュの古いエントリを削除 */
    cleanupSeen() {
        const now = this.now();
        for (const [id, ts] of this.seenRequests) {
            if (now - ts > ecchimailserverAPI.ENVELOPE_TIMEOUT) {
                this.seenRequests.delete(id);
            }
        }
    }
    /** ランダムなrequestIdを生成 */
    generateRequestId() {
        const bytes = new Uint8Array(16);
        globalThis.crypto.getRandomValues(bytes);
        return this.bytesToHex(bytes);
    }
    /** PeerCommandをエンベロープに包んで送信 */
    sendToPeer(peer, payload, requestId, ttl, timestamp, app) {
        const envelope = {
            requestId: requestId ?? this.generateRequestId(),
            timestamp: timestamp ?? this.now(),
            ttl: ttl ?? ecchimailserverAPI.DEFAULT_TTL,
            payload,
        };
        if (app)
            envelope.app = app;
        peer.send(JSON.stringify(envelope));
    }
    /** 全ピアにブロードキャスト（エンベロープ付き） */
    broadcastToPeers(payload, excludeWs, app) {
        const requestId = this.generateRequestId();
        const timestamp = this.now();
        this.seenRequests.set(requestId, timestamp);
        this.peers.forEach(peer => {
            if (peer !== excludeWs) {
                this.sendToPeer(peer, payload, requestId, ecchimailserverAPI.DEFAULT_TTL, timestamp, app);
            }
        });
    }
    /** エンベロープを検証して中身を処理、必要なら転送 */
    handlePeerMessage(ws, raw) {
        let envelope;
        try {
            const parsed = JSON.parse(raw.toString());
            // HELLOはエンベロープなし
            if (parsed.cmd === "HELLO")
                return;
            // レスポンス系（_OKや_FAIL）はエンベロープなしで直接来る
            if (parsed.cmd?.endsWith("_OK") || parsed.cmd?.endsWith("_FAIL")) {
                this.handlePeerResponse(ws, parsed);
                return;
            }
            envelope = parsed;
        }
        catch {
            return;
        }
        // 1. requestId重複チェック
        if (this.seenRequests.has(envelope.requestId))
            return;
        // 2. タイムスタンプ鮮度チェック (30秒)
        if (Math.abs(this.now() - envelope.timestamp) > ecchimailserverAPI.ENVELOPE_TIMEOUT)
            return;
        // 3. TTLチェック
        if (envelope.ttl <= 0)
            return;
        // 4. seenに追加
        this.seenRequests.set(envelope.requestId, envelope.timestamp);
        // 5. ペイロードを処理
        if (envelope.app) {
            // appメッセージの1KB制限
            const payloadSize = JSON.stringify(envelope.payload).length;
            if (payloadSize > 1024)
                return;
            // 外部アプリ宛: 登録済みのアプリに転送
            const appWs = this.appClients.get(envelope.app);
            if (appWs && appWs.readyState === 1) {
                appWs.send(JSON.stringify(envelope.payload));
            }
            // 未登録でも転送はする（他のノードでは登録されてるかもしれない）
        }
        else {
            // メール層: 既存のハンドラで処理
            const msg = envelope.payload;
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
        // 6. TTL-1して他のピアに転送（送信元を除く）
        this.peers.forEach(peer => {
            if (peer !== ws) {
                this.sendToPeer(peer, envelope.payload, envelope.requestId, envelope.ttl - 1, envelope.timestamp, envelope.app);
            }
        });
    }
    /** レスポンス系メッセージの処理（エンベロープなし） */
    handlePeerResponse(ws, msg) {
        // レスポンスはaskPeers系のonMessageハンドラが処理するのでここでは何もしない
        // wsのmessageイベントに登録されたハンドラが拾う
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
                this.sendToPeer(peer, { cmd: "PEER_LOOK", pubkey: pubkeyHex });
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
                this.sendToPeer(peer, { cmd: "PEER_FETCH", pubkey: pubkeyHex, messageId });
            });
            if (result)
                return result;
        }
        return null;
    }
    broadcastDelete(pubkeyHex, messageId) {
        this.broadcastToPeers({ cmd: "PEER_DELETE", pubkey: pubkeyHex, messageId });
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
