import { cipher } from "./cryptos/xor.js";
import { PointPairSchnorrP256 } from "./cryptos/ecdsa.js";

// ecdsa.ts に以下のpublicメソッドを追加する必要がある:
//   public scalarMultPublic(Pt: [Uint8Array, Uint8Array], k: Uint8Array): [Uint8Array, Uint8Array]
//   public pointAddPublic(P: [Uint8Array, Uint8Array], Q: [Uint8Array, Uint8Array]): [Uint8Array, Uint8Array]
//   public getN(): bigint  (位数Nを返す)

/** 署名: [Rx, Ry, s] 各Uint8Array */
type Signature = [Uint8Array, Uint8Array, Uint8Array];

/** 公開鍵: [X, Y] 各Uint8Array (32bytes) */
type PubKey = [Uint8Array, Uint8Array];

/** サーバレスポンス */
interface ServerResponse {
  cmd: string;
  ids?: string[];
  mail?: number[];
  count?: number;
  deleted?: boolean;
  error?: string;
}

export class ecchimailclientAPI {
  private ws: WebSocket | null = null;
  private schnorr: PointPairSchnorrP256;
  private crypt: cipher;
  private privKey: Uint8Array;
  private pubKey: PubKey;
  private pubKeyRaw: Uint8Array; // 65 bytes: 04||X||Y

  constructor(privKey: Uint8Array) {
    this.schnorr = new PointPairSchnorrP256();
    this.crypt = new cipher();
    this.privKey = privKey;
    this.pubKey = this.schnorr.privatekeytoPublicKey(privKey);
    this.pubKeyRaw = this.encodePubKey(this.pubKey);
  }

  // ─── 接続 ───────────────────────────────────────────

  public async connect(dnsSeed: string): Promise<void> {
    const WS =
      typeof window !== "undefined" ? WebSocket : (await import("ws")).default;

    const nodes = await this.resolveNodes(dnsSeed);
    const isBrowser = typeof window !== "undefined";
    const isSecure = isBrowser && window.location.protocol === "https:";
    const usable = nodes.filter((n) =>
      isSecure ? n.startsWith("wss://") : true,
    );

    if (usable.length === 0) throw new Error("no available nodes");

    // ランダムなノードに接続
    const node = usable[Math.floor(Math.random() * usable.length)];

    return new Promise((resolve, reject) => {
      this.ws = new WS(node) as WebSocket;
      this.ws.onopen = () => {
        console.log(`Connected to ${node}`);
        resolve();
      };
      this.ws.onerror = (e) => reject(e);
    });
  }

  public disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private async resolveNodes(dnsSeed: string): Promise<string[]> {
    try {
      const res = await fetch(
        `https://dns.google/resolve?name=${dnsSeed}&type=TXT`,
      );
      const data = await res.json();
      return data.Answer?.map((r: any) => r.data.replace(/"/g, "")) ?? [];
    } catch {
      return [];
    }
  }

  // ─── 送信 ───────────────────────────────────────────

  /**
   * メールを送信する
   * @param to 受信者の非圧縮公開鍵 (65 bytes: 04||X||Y)
   * @param plaintext 平文メッセージ
   */
  public async send(to: Uint8Array, plaintext: Uint8Array): Promise<void> {
    this.ensureConnected();
    const mail = this.composeMail(to, plaintext);
    const resp = await this.request({
      cmd: "SEND",
      mail: Array.from(mail),
    });
    if (resp.cmd !== "SEND_OK") {
      throw new Error(`SEND failed: ${resp.error}`);
    }
  }

  // ─── 確認 ───────────────────────────────────────────

  /**
   * 自分宛のメールのmessage_id一覧を取得
   */
  public async look(): Promise<string[]> {
    this.ensureConnected();
    const timestamp = this.now();
    const sigTarget = this.concat(
      new TextEncoder().encode("LOOK"),
      this.encodeUint64(timestamp),
    );
    const sig = this.schnorr.sign(sigTarget, this.privKey, this.pubKey);

    const resp = await this.request({
      cmd: "LOOK",
      pubkey: Array.from(this.pubKeyRaw),
      timestamp,
      sig: [Array.from(sig[0]), Array.from(sig[1]), Array.from(sig[2])],
    });
    if (resp.cmd !== "LOOK_OK") {
      throw new Error(`LOOK failed: ${resp.error}`);
    }
    return resp.ids ?? [];
  }

  // ─── 取得 ───────────────────────────────────────────

  /**
   * message_idを指定してメールを取得・復号する
   * @returns 平文メッセージ。失敗時はnull
   */
  public async fetch(messageId: string): Promise<Uint8Array | null> {
    this.ensureConnected();
    const timestamp = this.now();
    const sigTarget = this.concat(
      new TextEncoder().encode("FETCH"),
      this.encodeUint64(timestamp),
    );
    const sig = this.schnorr.sign(sigTarget, this.privKey, this.pubKey);

    const resp = await this.request({
      cmd: "FETCH",
      pubkey: Array.from(this.pubKeyRaw),
      messageId,
      timestamp,
      sig: [Array.from(sig[0]), Array.from(sig[1]), Array.from(sig[2])],
    });
    if (resp.cmd !== "FETCH_OK" || !resp.mail) {
      return null;
    }

    const mail = new Uint8Array(resp.mail);
    const plaintext = this.openMail(mail);

    // 復号成功したらACK
    if (plaintext) {
      await this.ack(messageId);
    }
    return plaintext;
  }

  // ─── ACK ────────────────────────────────────────────

  /**
   * 受信確認（メール削除）
   */
  public async ack(messageId: string): Promise<void> {
    this.ensureConnected();
    const idBytes = this.hexToBytes(messageId);
    const sig = this.schnorr.sign(idBytes, this.privKey, this.pubKey);

    await this.request({
      cmd: "ACK",
      pubkey: Array.from(this.pubKeyRaw),
      messageId,
      sig: [Array.from(sig[0]), Array.from(sig[1]), Array.from(sig[2])],
    });
  }

  // ─── DELETE ──────────────────────────────────────────

  /**
   * 未読メールを削除
   */
  public async delete(messageId: string): Promise<void> {
    this.ensureConnected();
    const idBytes = this.hexToBytes(messageId);
    const sig = this.schnorr.sign(idBytes, this.privKey, this.pubKey);

    await this.request({
      cmd: "DELETE",
      pubkey: Array.from(this.pubKeyRaw),
      messageId,
      sig: [Array.from(sig[0]), Array.from(sig[1]), Array.from(sig[2])],
    });
  }

  // ─── COUNT ──────────────────────────────────────────

  /**
   * 自分宛のメール件数を取得
   */
  public async count(): Promise<number> {
    this.ensureConnected();
    const timestamp = this.now();
    const sigTarget = this.concat(
      new TextEncoder().encode("COUNT"),
      this.encodeUint64(timestamp),
    );
    const sig = this.schnorr.sign(sigTarget, this.privKey, this.pubKey);

    const resp = await this.request({
      cmd: "COUNT",
      pubkey: Array.from(this.pubKeyRaw),
      timestamp,
      sig: [Array.from(sig[0]), Array.from(sig[1]), Array.from(sig[2])],
    });
    if (resp.cmd !== "COUNT_OK") {
      throw new Error(`COUNT failed: ${resp.error}`);
    }
    return resp.count ?? 0;
  }

  // ─── composeMail ────────────────────────────────────
  // フォーマット: A(65) | Y(65) | f(32) | timestamp(8) | IV(16) | ciphertext(var) | hmac(32) | sig(96)

  private composeMail(to: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const A = this.pubKeyRaw; // 送信者 65 bytes
    const Y = to; // 受信者 65 bytes
    const recipientPubKey = this.decodePubKey(Y);

    // 1. f を生成 (1 ≤ f < N)
    const f = new Uint8Array(32);
    globalThis.crypto.getRandomValues(f);
    // fを秘密鍵として有効な範囲にする（簡易: 上位ビットをクリア）

    // 2. 共有秘密 S = (a + f) × Y
    //    実効秘密鍵 a' = (a + f) mod N
    const aPrime = this.addScalars(this.privKey, f);
    // S = a' × Y (受信者の公開鍵のスカラー倍)
    const S = this.schnorr.scalarMultPublic(recipientPubKey, aPrime);

    // 3. AES鍵導出
    const salt = this.crypt.sha256(this.concat(A, Y, f));
    const sharedKey = this.hkdf(S[0], salt, "ECCHImail-v2", 32);

    // 4. 暗号化 (SHA256-CTR + HMAC-SHA256)
    const encrypted = this.crypt.encrypt(plaintext, sharedKey);
    // encrypted = IV(16) | ciphertext(var) | HMAC(32)

    // 5. timestamp
    const timestamp = this.now();
    const tsBytes = this.encodeUint64(timestamp);

    // 6. IVを取り出してmessage_id計算
    const iv = encrypted.slice(0, 16);
    const [minKey, maxKey] = this.sortKeys(A, Y);
    const messageId = this.crypt.sha256(
      this.concat(tsBytes, minKey, maxKey, iv),
    );

    // 7. 署名 (message_idに対して)
    const sig = this.schnorr.sign(messageId, this.privKey, this.pubKey);

    // 8. 組み立て
    // A(65) | Y(65) | f(32) | timestamp(8) | encrypted(IV+ciphertext+HMAC) | sig(Rx+Ry+s=96)
    return this.concat(
      A, // 65 bytes
      Y, // 65 bytes
      f, // 32 bytes
      tsBytes, // 8 bytes
      encrypted, // 16 + var + 32 bytes
      sig[0],
      sig[1],
      sig[2], // 96 bytes
    );
  }

  // ─── openMail ───────────────────────────────────────

  private openMail(mail: Uint8Array): Uint8Array | null {
    // 1. パース
    const A = mail.slice(0, 65); // 送信者
    const Y = mail.slice(65, 130); // 受信者 (= 自分)
    const f = mail.slice(130, 162); // 鍵材料
    const tsBytes = mail.slice(162, 170); // timestamp
    const encrypted = mail.slice(170, -96); // IV + ciphertext + HMAC
    const sigRx = mail.slice(-96, -64);
    const sigRy = mail.slice(-64, -32);
    const sigS = mail.slice(-32);
    const sig: Signature = [sigRx, sigRy, sigS];

    // 2. 送信者の公開鍵が有効か
    const senderPubKey = this.decodePubKey(A);
    if (
      !this.schnorr.isPointOnCurve([
        this.bytesToBigInt(senderPubKey[0]),
        this.bytesToBigInt(senderPubKey[1]),
      ])
    )
      return null;

    // 3. message_id 再計算 + 署名検証
    const iv = encrypted.slice(0, 16);
    const [minKey, maxKey] = this.sortKeys(A, Y);
    const messageId = this.crypt.sha256(
      this.concat(tsBytes, minKey, maxKey, iv),
    );
    if (!this.schnorr.verify(messageId, senderPubKey, sig)) return null;

    // 4. 共有秘密 S = x × (A + fG)
    const fG = this.schnorr.privatekeytoPublicKey(f); // fG = f × G
    const APrime = this.schnorr.pointAddPublic(senderPubKey, fG); // A + fG
    const S = this.schnorr.scalarMultPublic(APrime, this.privKey); // x × (A + fG)

    // 5. 鍵導出
    const salt = this.crypt.sha256(this.concat(A, Y, f));
    const sharedKey = this.hkdf(S[0], salt, "ECCHImail-v2", 32);

    // 6. 復号
    return this.crypt.decrypt(encrypted, sharedKey);
  }

  // ─── WebSocket通信 ──────────────────────────────────

  private ensureConnected(): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("not connected. call connect() first");
    }
  }

  private request(msg: any): Promise<ServerResponse> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 10000);
      const handler = (event: MessageEvent | { data: any }) => {
        try {
          const data =
            typeof event.data === "string" ? event.data : event.data.toString();
          const resp: ServerResponse = JSON.parse(data);
          clearTimeout(timeout);
          this.ws!.removeEventListener("message", handler as any);
          resolve(resp);
        } catch {
          /* ignore parse errors */
        }
      };
      this.ws!.addEventListener("message", handler as any);
      this.ws!.send(JSON.stringify(msg));
    });
  }

  // ─── HKDF-SHA256 ────────────────────────────────────

  private hkdf(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: string,
    length: number,
  ): Uint8Array {
    const infoBytes = new TextEncoder().encode(info);
    const prk = this.hmacSha256(salt, ikm);
    const out = new Uint8Array(length);
    let prev = new Uint8Array(0);
    let pos = 0;
    let counter = 1;
    while (pos < length) {
      prev = this.hmacSha256(
        prk,
        this.concat(prev, infoBytes, new Uint8Array([counter++])),
      ) as Uint8Array<ArrayBuffer>;
      const take = Math.min(prev.length, length - pos);
      out.set(prev.subarray(0, take), pos);
      pos += take;
    }
    return out;
  }

  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.crypt.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return this.crypt.sha256(
      this.concat(opad, this.crypt.sha256(this.concat(ipad, data))),
    );
  }

  // ─── スカラー演算 ───────────────────────────────────

  /** (a + f) mod N を Uint8Array で返す */
  private addScalars(a: Uint8Array, f: Uint8Array): Uint8Array {
    const N =
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const aBig = this.bytesToBigInt(a);
    const fBig = this.bytesToBigInt(f);
    const result = (aBig + fBig) % N;
    return this.bigintToBytes(result, 32);
  }

  // ─── エンコード/デコード ────────────────────────────

  /** PubKey [X, Y] → 65 bytes 非圧縮 (04||X||Y) */
  private encodePubKey(pub: PubKey): Uint8Array {
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(this.padTo32(pub[0]), 1);
    out.set(this.padTo32(pub[1]), 33);
    return out;
  }

  /** 65 bytes 非圧縮 → PubKey [X, Y] */
  private decodePubKey(raw: Uint8Array): PubKey {
    return [raw.slice(1, 33), raw.slice(33, 65)];
  }

  private padTo32(bytes: Uint8Array): Uint8Array {
    if (bytes.length === 32) return bytes;
    const out = new Uint8Array(32);
    out.set(bytes, 32 - bytes.length);
    return out;
  }

  private sortKeys(a: Uint8Array, b: Uint8Array): [Uint8Array, Uint8Array] {
    for (let i = 0; i < a.length; i++) {
      if (a[i] < b[i]) return [a, b];
      if (a[i] > b[i]) return [b, a];
    }
    return [a, b];
  }

  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  private now(): number {
    return Math.floor(Date.now() / 1000);
  }

  private encodeUint64(n: number): Uint8Array {
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    view.setUint32(0, Math.floor(n / 0x100000000), false);
    view.setUint32(4, n >>> 0, false);
    return buf;
  }

  private bytesToBigInt(bytes: Uint8Array): bigint {
    let res = 0n;
    for (const b of bytes) res = (res << 8n) + BigInt(b);
    return res;
  }

  private bigintToBytes(n: bigint, length: number): Uint8Array {
    const hex = n.toString(16).padStart(length * 2, "0");
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}
