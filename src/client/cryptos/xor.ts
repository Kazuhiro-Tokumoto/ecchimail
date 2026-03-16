export class cipher {
  // =====================================================================
  // sha256 ばぐがおおそう
  // =====================================================================
  public sha256(data: Uint8Array): Uint8Array {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);

    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

    let h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a;
    let h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;

    const len = data.length;
    const bitLen = len * 8;
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    view.setUint32(blocks.length - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(blocks.length - 4, bitLen >>> 0, false);

    for (let i = 0; i < blocks.length; i += 64) {
      const W = new Uint32Array(64);
      for (let t = 0; t < 16; t++) {
        W[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }

      let a = h0,
        b = h1,
        c = h2,
        d = h3;
      let e = h4,
        f = h5,
        g = h6,
        h = h7;

      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e >>> 0) & g); // ✅ ~e を明示的にuint32化
        const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
  }

  // ---------------------------------------------------------------------
  // ユーティリティ
  // ---------------------------------------------------------------------
  private bigintToHex(n: bigint, byteLength?: number): string {
    const hex = n.toString(16).toUpperCase();
    const padLen = byteLength ? byteLength * 2 : hex.length + (hex.length % 2);
    return hex.padStart(padLen, "0");
  }
  private BigintToBytes(n: bigint, byteLength?: number): Uint8Array {
    const hex = this.bigintToHex(n, byteLength);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  private hexToBigInt(hex: string): bigint {
    return BigInt("0x" + hex);
  }
  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length;
    let res = 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);

    let i = 0;
    for (; i <= len - 8; i += 8) {
      res = (res << 64n) + view.getBigUint64(i);
    }
    for (; i < len; i++) {
      res = (res << 8n) + BigInt(bytes[i]);
    }
    return res;
  }
  public bytesToHex(bytes: Uint8Array): string {
    return this.bigintToHex(this.bytesToBigInt(bytes));
  }
  public hexToBytes(hex: string): Uint8Array {
    return this.BigintToBytes(this.hexToBigInt(hex));
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

  private counterToBytes(n: number): Uint8Array {
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    view.setUint32(0, Math.floor(n / 0x100000000), false);
    view.setUint32(4, n >>> 0, false);
    return buf;
  }

  // ---------------------------------------------------------------------
  // 意味なしストレッチ（1回のハッシュで遅延させる）
  // ---------------------------------------------------------------------
  private stretch(data: Uint8Array, salt: Uint8Array): Uint8Array {
    let h = this.concat(data, salt);
    for (let i = 0; i < 1; i++) {
      h = this.hmacSha256(data, this.concat(h, salt));
    }
    return h;
  }

  // ---------------------------------------------------------------------
  // HMAC-SHA256
  // ---------------------------------------------------------------------
  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }

  // ---------------------------------------------------------------------
  // HKDF（暗号化用とMAC用で独立した鍵を導出）
  // ---------------------------------------------------------------------
  private hkdf(
    inputKey: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
  ): Uint8Array {
    const prk = this.hmacSha256(salt, inputKey);
    const out = new Uint8Array(length);
    let prev = new Uint8Array(0);
    let pos = 0;
    let counter = 1;
    while (pos < length) {
      prev = this.hmacSha256(
        prk,
        this.concat(prev, info, new Uint8Array([counter++])),
      ) as Uint8Array<ArrayBuffer>;
      const take = Math.min(prev.length, length - pos);
      out.set(prev.subarray(0, take), pos);
      pos += take;
    }
    return out;
  }

  // ---------------------------------------------------------------------
  // CTR モード（SHA-256 ベース）
  // ---------------------------------------------------------------------
  private ctrProcess(
    data: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
  ): Uint8Array {
    const BLOCK = 32;
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += BLOCK) {
      const counter = Math.floor(i / BLOCK);
      // sha256 の代わりに hmacSha256 を使う
      const blockKey = this.hmacSha256(
        key,
        this.concat(iv, this.counterToBytes(counter)),
      );
      const end = Math.min(BLOCK, data.length - i);
      for (let j = 0; j < end; j++) {
        result[i + j] = data[i + j] ^ blockKey[j];
      }
    }
    return result;
  }

  // ---------------------------------------------------------------------
  // 暗号化
  // 出力フォーマット: [ IV (16B) | 暗号文 | HMAC (32B) ]
  // ---------------------------------------------------------------------
  public encrypt = (rawData: Uint8Array, key: Uint8Array): Uint8Array => {
    // 鍵は32Bのみ受け付ける
    if (key.length !== 32) {
      throw new Error("鍵は32バイトにしてください");
    }

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
    //変えるのめんどい
    const stretchedKey = this.stretch(key, iv);

    // HKDF で暗号化用とMAC用を独立して導出
    const encKey = this.hkdf(
      stretchedKey,
      iv,
      new TextEncoder().encode("enc"),
      32,
    );
    const macKey = this.hkdf(
      stretchedKey,
      iv,
      new TextEncoder().encode("mac"),
      32,
    );

    const ciphertext = this.ctrProcess(rawData, encKey, iv);
    const mac = this.hmacSha256(macKey, this.concat(iv, ciphertext));

    return this.concat(iv, ciphertext, mac);
  };

  // ---------------------------------------------------------------------
  // 復号
  // 改ざんを検知した場合は null を返します
  // ---------------------------------------------------------------------
  public decrypt = (
    encryptedWithIv: Uint8Array,
    key: Uint8Array,
  ): Uint8Array | null => {
    // 鍵は32Bのみ受け付ける
    if (key.length !== 32) {
      throw new Error("鍵は32バイトにしてください");
    }

    // フォーマット: [ IV (16B) | 暗号文 | HMAC (32B) ]
    if (encryptedWithIv.length < 16 + 32) {
      console.error("decrypt error: データが短すぎます");
      return null;
    }

    const iv = encryptedWithIv.slice(0, 16);
    const mac = encryptedWithIv.slice(-32);
    const ciphertext = encryptedWithIv.slice(16, -32);
    //変えるのめんどい
    const stretchedKey = this.stretch(key, iv);

    // HKDF で同じ鍵を再導出
    const encKey = this.hkdf(
      stretchedKey,
      iv,
      new TextEncoder().encode("enc"),
      32,
    );
    const macKey = this.hkdf(
      stretchedKey,
      iv,
      new TextEncoder().encode("mac"),
      32,
    );

    // MAC 検証（タイミング攻撃対策で全バイト比較）
    const expectedMac = this.hmacSha256(macKey, this.concat(iv, ciphertext));
    let diff = 0;
    for (let i = 0; i < 32; i++) {
      diff |= mac[i] ^ expectedMac[i];
    }
    if (diff !== 0) {
      console.error("decrypt error: MAC 検証失敗（改ざんの可能性）");
      return null;
    }

    return this.ctrProcess(ciphertext, encKey, iv);
  };
}