# ECCHImail Protocol Design Specification

**Version:** 2.1  
**Date:** 2026-03-16  
**Status:** Draft  

---

## 1. Overview

ECCHImail は P-256 楕円曲線上に構築された、エンドツーエンド暗号化・匿名メッセージングプロトコルである。公開鍵ベースのアドレッシング、f-offset ECDH 鍵交換、P-256 Schnorr 署名、SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) 暗号化を組み合わせ、機密性・完全性・匿名性を実現する。

### 1.1 設計目標

- **E2E暗号化:** メッセージ本文は中継サーバを含む第三者に一切読めない
- **匿名性:** アドレスは生の公開鍵であり、実世界の身元と紐付かない
- **完全性:** 全メッセージに P-256 Schnorr 署名を付与。改ざん検知は HMAC タグが担当
- **鍵多様性:** f-offset により毎回異なる共有秘密を導出
- **簡潔性:** 既存の ECCHI プリミティブ（p-256.ts, cipher.ts）上に構築
- **サーバ検証可能:** 全コマンドに署名が必要。署名なしでは何もできない
- **分散配送:** サーバ連合によりメールを保管・中継。単一障害点なし

### 1.2 暗号プリミティブ

| プリミティブ | 仕様 |
|---|---|
| 楕円曲線 | NIST P-256 (secp256r1) |
| 鍵交換 | f-offset ECDH: (a+f) × Y |
| 署名 | P-256 Schnorr (BIP340 スタイル) |
| 共通鍵暗号 | SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) |
| 鍵導出 | HKDF-SHA256 |
| ハッシュ | SHA-256 |

---

## 2. アドレッシング

ECCHImail のアドレスは、ユーザの **非圧縮 P-256 公開鍵そのもの** である。ハッシュやエンコーディング層を介さないため、アドレスを知っていれば即座に暗号化・署名検証が可能。

### 2.1 アドレスフォーマット

| フィールド | サイズ | 内容 |
|---|---|---|
| プレフィックス | 1 byte | `0x04`（非圧縮点識別子） |
| X 座標 | 32 bytes | x 座標のビッグエンディアン |
| Y 座標 | 32 bytes | y 座標のビッグエンディアン |

**合計: 65 bytes（16進表示で 0x + 130文字 = 132文字）**

### 2.2 表示形式

```
0x04[X: 64 hex][Y: 64 hex]
```

### 2.3 鍵生成手順

1. 暗号学的に安全な乱数で 256 ビット整数を生成 → 秘密鍵 `a`
2. `1 ≤ a < N`（P-256 の位数）を確認
3. 公開鍵を計算: `A = aG`（G は P-256 の基点）
4. 非圧縮点としてエンコード: `0x04 || X || Y`

---

## 3. 鍵交換: f-offset ECDH

### 3.1 概要

ECCHImail は **f-offset ECDH** 方式を採用する。送信のたびにランダムスカラー f（一度限りの鍵材料）で両者の鍵にオフセットを加え、長期鍵ペアの再利用でありながら毎回異なる共有秘密を得る。

### 3.2 記法

| 記号 | 意味 |
|---|---|
| `a` | 送信者の長期秘密鍵 |
| `A = aG` | 送信者の公開鍵（= アドレス） |
| `x` | 受信者の長期秘密鍵 |
| `Y = xG` | 受信者の公開鍵（= アドレス） |
| `f` | 一度限りの鍵材料（1 ≤ f < N、CSPRNG で生成） |
| `fG` | f に対応する公開点（受信者が f から計算） |
| `G` | P-256 基点 |
| `N` | P-256 位数 |

### 3.3 プロトコル

**送信者（秘密鍵 a、相手の公開鍵 Y）:**

1. ランダムスカラー f を生成（1 ≤ f < N）
2. 実効秘密鍵を計算: `a' = (a + f) mod N`
3. 共有秘密を計算: `S = a' × Y = (a + f) × Y`
4. f をメールに含める（32 bytes）

**受信者（秘密鍵 x、送信者の公開鍵 A、メールから f を取得）:**

1. fG を計算: `fG = f × G`
2. 実効公開鍵を計算: `A' = A + fG`
3. 共有秘密を計算: `S = x × A' = x × (A + fG) = x(a + f)G`

**一致の証明:**

```
送信者: S = (a + f) × Y = (a + f) × xG = x(a + f)G
受信者: S = x × (A + fG) = x × (aG + fG) = x(a + f)G
```

### 3.4 鍵導出

共有秘密 S（楕円曲線上の点）から AES 鍵を導出する:

1. 共有点の X 座標を取得: `S.x`（32 bytes, big-endian）
2. HKDF-SHA256 で鍵導出:
   - IKM: `S.x`
   - salt: `SHA-256(A || Y || f)`
   - info: `"ECCHImail-v2"`
   - 出力: 32 bytes → SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) 鍵

### 3.5 セキュリティ特性

- **ECDLP 依存:** 攻撃者は Y, f, A を知っていても、x を知らなければ共有秘密 S を計算できない
- **鍵多様性:** f が毎回異なるため、同一の送受信者ペアでも毎回異なる共有秘密が生成される
- **MITM 耐性:** 攻撃者は a を知らないため (a+f) × Y を計算できない。偽の A を差し込んでも署名検証で即発覚。fG を改ざんしても HMAC タグで復号失敗
- **Forward Secrecy について:** 長期秘密鍵 a が漏洩した場合、公開値 f から過去の共有秘密を復元可能。Bitcoin / Ethereum 等と同等のセキュリティモデル

---

## 4. メッセージ ID

### 4.1 定義

```
message_id = SHA-256(timestamp || min(A, Y) || max(A, Y) || IV)
```

- `timestamp`: 8 bytes, Unix 秒 (big-endian)
- `min(A, Y)`, `max(A, Y)`: 公開鍵のバイト列を辞書順で比較し、小さい方を先に配置
- `IV`: 16 bytes, SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) の初期化ベクトル（CSPRNG）

### 4.2 設計根拠

- **順序正規化:** A, Y の順序を辞書順で固定することで、送信者・受信者どちらから計算しても同一の message_id を得る
- **ユニーク性:** IV は毎回 CSPRNG で生成されるため、同一秒・同一ペアでも衝突しない
- **軽量:** 暗号文全体をハッシュに含めず、固定長フィールドのみで構成

### 4.3 用途

- 送信署名の対象
- ACK 署名の対象
- DELETE の指定対象
- FETCH の指定対象

---

## 5. メッセージフォーマット

### 5.1 構造

```
+--------------------+----------+
| フィールド          | サイズ    |
+--------------------+----------+
| 送信者アドレス A    | 65 bytes |
| 受信者アドレス Y    | 65 bytes |
| 鍵材料 f           | 32 bytes |
| タイムスタンプ      | 8 bytes  |
| IV                 | 16 bytes |
| ciphertext         | 可変長    |
| HMAC tag           | 32 bytes |
| Schnorr 署名       | 64 bytes |
+--------------------+----------+
```

### 5.2 各フィールドの詳細

**送信者アドレス A (65 bytes):**  
送信者の非圧縮 P-256 公開鍵。受信者はこれを使って鍵交換（A + fG の計算）と署名検証を行う。サーバもこれを使って署名検証を行う。

**受信者アドレス Y (65 bytes):**  
受信者の非圧縮 P-256 公開鍵。サーバはこれを使ってメールボックスの振り分けを行う。

**鍵材料 f (32 bytes):**  
一度限りのランダムスカラー。受信者が fG を計算し、共有秘密を導出するために必要。

**タイムスタンプ (8 bytes):**  
送信時刻の Unix 秒（uint64, big-endian）。サーバが受付時に鮮度チェックに使用。

**IV (16 bytes):**  
SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) の初期化ベクトル。CSPRNG で生成。

**ciphertext (可変長):**  
平文メッセージの暗号化結果。

**HMAC tag (32 bytes):**  
HMAC-SHA256 タグ。改ざん検知を担当。

**Schnorr 署名 (64 bytes):**  
- r: 32 bytes（署名の R 点の X 座標）
- s: 32 bytes（署名スカラー）
- 署名対象: `message_id`

### 5.3 バイト列レイアウト

```
[0x04||Ax||Ay] [0x04||Yx||Yy] [f] [timestamp] [IV] [ciphertext] [tag] [r||s]
|<-- 65B ----->|<-- 65B ----->|32B|<-- 8B --->|16B|<- var ---->|32B |<64B>|
```

**最小メッセージサイズ（空本文）: 65 + 65 + 32 + 8 + 16 + 0 + 32 + 64 = 282 bytes**

---

## 6. 署名: P-256 Schnorr

### 6.1 署名アルゴリズム

ECCHI プロトコルと同一の P-256 Schnorr 署名を使用する。

**署名生成（秘密鍵 a、メッセージ m）:**

1. ランダムノンス `r` を生成（1 ≤ r < N）
2. `R = rG` を計算
3. チャレンジ `e = SHA-256(R.x || A || m) mod N`
4. `s = (r + e × a) mod N`
5. 署名: `(R.x, s)` — 各 32 bytes、合計 64 bytes

**署名検証（公開鍵 A、メッセージ m、署名 (R.x, s)）:**

1. `R.x` から点 R を復元
2. チャレンジ `e = SHA-256(R.x || A || m) mod N`
3. `sG == R + eA` を検証

### 6.2 署名対象

ECCHImail ではメッセージの署名対象は **message_id** に一本化する。

```
署名対象 = message_id = SHA-256(timestamp || min(A,Y) || max(A,Y) || IV)
```

### 6.3 役割分担

| 機能 | 担当 |
|---|---|
| メッセージ改ざん検知 | SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) 認証タグ |
| 送信証明 | 送信者による message_id への Schnorr 署名 |
| 受信証明 | 受信者による message_id への ACK 署名 |

---

## 7. 処理フロー

### 7.1 送信フロー

```
送信者 (秘密鍵 a, 公開鍵 A)
  │
  │  入力: 受信者公開鍵 Y, 平文メッセージ P
  │
  ├─ 1. ランダムスカラー f を生成 (1 ≤ f < N)
  ├─ 2. 共有秘密 S = (a + f) × Y を計算
  ├─ 3. 共有鍵 = HKDF-SHA256(S.x, salt=SHA256(A||Y||f), info="ECCHImail-v2")
  ├─ 4. IV を生成 (16 bytes, CSPRNG)
  ├─ 5. 暗号文, hmac = Encrypt-then-MAC(共有鍵, IV, P)
  ├─ 6. timestamp = 現在の Unix 秒
  ├─ 7. message_id = SHA-256(timestamp || min(A,Y) || max(A,Y) || IV)
  ├─ 8. sig = Schnorr-Sign(a, message_id)
  ├─ 9. メール = A || Y || f || timestamp || IV || ciphertext || hmac || sig
  └─ 10. SEND コマンドでサーバに送信
```

### 7.2 サーバ受付フロー

```
サーバ
  │
  │  入力: SEND コマンド + メール
  │
  ├─ 1. A を取り出す (先頭 65 bytes)
  ├─ 2. Y を取り出す (65-130 bytes)
  ├─ 3. A, Y が有効な P-256 点か検証
  ├─ 4. timestamp を検証: |現在時刻 - timestamp| ≤ 300秒 (5分)
  ├─ 5. message_id = SHA-256(timestamp || min(A,Y) || max(A,Y) || IV)
  ├─ 6. Schnorr-Verify(A, message_id, sig)
  ├─ 7. 検証失敗 → 破棄
  └─ 8. 検証成功 → Y 宛のメールとして保管
```

### 7.3 受信フロー

```
受信者 (秘密鍵 x, 公開鍵 Y)
  │
  ├─ 1. 任意のサーバに接続
  ├─ 2. LOOK (署名: Schnorr-Sign(x, "LOOK" || timestamp))
  ├─ 3. サーバが他の全サーバに問い合わせ
  ├─ 4. Y 宛の全 message_id リストを受信
  ├─ 5. FETCH message_id (署名: Schnorr-Sign(x, "FETCH" || timestamp))
  ├─ 6. メール本体を取得（保管サーバから中継 or 直接取得）
  ├─ 7. A, Y, f を取り出す
  ├─ 8. A が有効な P-256 点か検証
  ├─ 9. message_id を再計算し署名検証: Schnorr-Verify(A, message_id, sig)
  ├─ 10. fG = f × G を計算
  ├─ 11. 実効公開鍵 A' = A + fG を計算
  ├─ 12. 共有秘密 S = x × A' を計算
  ├─ 13. 共有鍵 = HKDF-SHA256(S.x, salt=SHA256(A||Y||f), info="ECCHImail-v2")
  ├─ 14. 平文 P = Decrypt-then-Verify(共有鍵, IV, ciphertext, hmac)
  ├─ 15. 復号成功 → ACK: Schnorr-Sign(x, message_id)
  └─ 16. サーバが ACK 署名を Y で検証 → OK ならメール削除
```

---

## 8. サーバ連合

### 8.1 アーキテクチャ

```
[サーバA] ←─WebSocket─→ [サーバB] ←─WebSocket─→ [サーバC]
   |                         |                         |
 ユーザ群                  ユーザ群                  ユーザ群
```

サーバ同士は WebSocket で P2P 接続し、連合を形成する。

### 8.2 ノードの信頼モデル

ノードは基本的に正当であるとする。

### 8.3 メール保管ポリシー

- **送信伝播なし:** 送信者が接続したサーバのみがメール本体を保管する。他のサーバへの伝播は行わない
- **受信伝播あり:** LOOK コマンド時に全サーバへ問い合わせが伝播する

### 8.4 LOOK の動作

1. 受信者が接続先サーバに LOOK を送信（署名付き）
2. 接続先サーバは自身のメールボックスを検索
3. 接続先サーバは隣接サーバに LOOK を中継
4. 各サーバが該当する message_id を返却
5. 接続先サーバが全結果を集約して受信者に返す

### 8.5 FETCH の動作

1. 受信者が message_id を指定して FETCH（署名付き）
2. メール本体が保管サーバにある場合:
   - 接続先サーバ = 保管サーバ → 直接返却
   - 接続先サーバ ≠ 保管サーバ → 保管サーバから中継して返却

### 8.6 ノード発見

既知のシードノードに接続し、他のノード情報を取得する（BTR と同様の方式）。

---

## 9. コマンドプロトコル

全コマンドに署名が必須。署名なしのリクエストはすべて拒否される。

### 9.1 コマンド一覧

| コマンド | 用途 | 署名対象 | 署名鍵 |
|---|---|---|---|
| SEND | メール送信 | `message_id` | 送信者の秘密鍵 `a` |
| LOOK | メール存在確認 | `"LOOK" \|\| timestamp` | 受信者の秘密鍵 `x` |
| FETCH | メール取得 | `"FETCH" \|\| timestamp` | 受信者の秘密鍵 `x` |
| ACK | 受信確認 + 削除 | `message_id` | 受信者の秘密鍵 `x` |
| DELETE | 未読削除 | `message_id` | 受信者の秘密鍵 `x` |
| COUNT | 件数確認 | `"COUNT" \|\| timestamp` | 受信者の秘密鍵 `x` |

### 9.2 タイムスタンプ検証

- SEND コマンド: サーバは `|現在時刻 - メール内timestamp| ≤ 300秒` を検証
- LOOK / FETCH / COUNT: サーバは署名内の timestamp が現在時刻から ±300秒以内であることを検証（リプレイ防止）

### 9.3 署名検証フロー

```
サーバ
  │
  ├─ 1. コマンドと公開鍵を受信
  ├─ 2. 公開鍵が有効な P-256 点か検証
  ├─ 3. 署名を公開鍵で検証
  ├─ 4. タイムスタンプの鮮度を検証
  ├─ 5. 検証失敗 → 拒否
  └─ 6. 検証成功 → コマンド実行
```

---

## 10. セキュリティ分析

### 10.1 攻撃シナリオと対策

| 攻撃 | 対策 |
|---|---|
| 盗聴 | SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) による E2E 暗号化。鍵は ECDH 共有秘密から導出 |
| 改ざん | HMAC タグによる検知 |
| なりすまし | Schnorr 署名による送信者認証 |
| サーバによる盗聴 | サーバは暗号文のみ保管。秘密鍵を持たないため復号不可 |
| リプレイ攻撃 | タイムスタンプ ±5分 検証 + IV のランダム性 |
| 小さい部分群攻撃 | P-256 は余因子 h=1。部分群攻撃は成立しない |
| Invalid curve attack | 受信時に A が P-256 上の有効な点であることを検証 |
| 偽 ACK（第三者によるメール削除） | ACK に受信者の Schnorr 署名が必要。秘密鍵なしでは作成不可 |
| 偽 FETCH（第三者によるメール窃取） | FETCH に受信者の Schnorr 署名が必要 |
| MITM | 攻撃者は a を知らないため (a+f)×Y を計算不可。偽の A は署名検証で発覚 |
| アカウント大量作成 | 許容する（鍵ペア生成のみで作成可能、Bitcoin と同等のモデル） |

### 10.2 セキュリティレベル

| 項目 | レベル |
|---|---|
| ECDLP 安全性 | 128 bit（Pollard's rho） |
| 共通鍵暗号 安全性 | 256 bit |
| SHA-256 衝突耐性 | 128 bit |
| 全体の安全性 | 128 bit（最弱のリンクに依存） |

### 10.3 サーバが知り得る情報

| 情報 | 可否 |
|---|---|
| 送信者のアドレス（公開鍵） | ○ 可（A は平文） |
| 受信者のアドレス（公開鍵） | ○ 可（宛先として必要） |
| メッセージ本文 | × 不可（E2E 暗号化） |
| メッセージの送信時刻 | ○ 可（timestamp） |
| メッセージのサイズ | ○ 可（メタデータ） |
| メッセージの存在 | ○ 可（message_id） |

### 10.4 Forward Secrecy に関する注記

本プロトコルは静的鍵ベースの f-offset ECDH を採用しており、長期秘密鍵の漏洩時に過去のメッセージが復号される可能性がある（f は平文で送信されるため）。これは Bitcoin、Ethereum 等と同等のセキュリティモデルであり、設計上の意図的なトレードオフである。

---

## 11. 実装ノート

### 11.1 依存ライブラリ

| モジュール | 用途 |
|---|---|
| `p-256.ts` | P-256 楕円曲線演算（点加算、スカラー倍、ECDH） |
| `cipher.ts` | SHA256-CTR + HMAC-SHA256 (Encrypt-then-MAC) 暗号化/復号 |
| `ecsh.ts` | P-256 Schnorr 署名（ECCHI 署名モジュール） |

### 11.2 新規実装が必要なもの

- `ecchimail.ts`: メール生成・パース・送受信ロジック
- `node.ts`: サーバノード（メールボックス管理、署名検証、ノード間通信）
- `client.ts`: クライアント（LOOK / FETCH / SEND / ACK）
- HKDF-SHA256 鍵導出関数（未実装の場合）

### 11.3 メッセージのシリアライゼーション

```typescript
// メール構築
function composeMail(
  senderPriv: bigint,              // a
  senderPub: [bigint, bigint],     // A
  recipientPub: [bigint, bigint],  // Y
  plaintext: Uint8Array
): Uint8Array {
  // 1. f を生成
  const f = randomScalar();  // 1 ≤ f < N

  // 2. 共有秘密
  const aPrime = (senderPriv + f) % N;
  const S = scalarMul(recipientPub, aPrime);

  // 3. 共有鍵導出
  const salt = sha256(concat(encode(senderPub), encode(recipientPub), encodeBigInt(f)));
  const sharedKey = hkdf(S.x, salt, "ECCHImail-v2", 32);

  // 4. 暗号化 (SHA256-CTR + HMAC-SHA256)
  const iv = randomBytes(16);
  const { ciphertext, hmac } = encryptThenMAC(sharedKey, iv, plaintext);

  // 5. message_id
  const timestamp = BigInt(Math.floor(Date.now() / 1000));
  const [minKey, maxKey] = sortKeys(senderPub, recipientPub);
  const messageId = sha256(concat(
    encodeUint64(timestamp),
    encode(minKey),
    encode(maxKey),
    iv
  ));

  // 6. 署名
  const sig = schnorrSign(senderPriv, messageId);

  // 7. 組み立て
  return concat(
    encode(senderPub),      // 65 bytes
    encode(recipientPub),   // 65 bytes
    encodeBigInt(f),         // 32 bytes
    encodeUint64(timestamp), // 8 bytes
    iv,                      // 16 bytes
    ciphertext,              // variable
    hmac,                    // 32 bytes
    sig                      // 64 bytes
  );
}
```

```typescript
// メール開封
function openMail(
  recipientPriv: bigint,              // x
  recipientPub: [bigint, bigint],     // Y
  mail: Uint8Array
): Uint8Array | null {
  // 1. パース
  const A = decodePoint(mail.slice(0, 65));
  const Y = decodePoint(mail.slice(65, 130));
  const f = decodeBigInt(mail.slice(130, 162));
  const timestamp = decodeUint64(mail.slice(162, 170));
  const iv = mail.slice(170, 186);
  const ciphertext = mail.slice(186, -96);  // variable
  const hmac = mail.slice(-96, -64);          // 32 bytes
  const sig = mail.slice(-64);               // 64 bytes

  // 2. 点の有効性検証
  if (!isOnCurve(A) || !isOnCurve(Y)) return null;

  // 3. message_id 再計算 + 署名検証
  const [minKey, maxKey] = sortKeys(A, recipientPub);
  const messageId = sha256(concat(
    encodeUint64(timestamp),
    encode(minKey),
    encode(maxKey),
    iv
  ));
  if (!schnorrVerify(A, messageId, sig)) return null;

  // 4. 共有秘密
  const fG = scalarMul(G, f);
  const APrime = pointAdd(A, fG);  // A + fG
  const S = scalarMul(APrime, recipientPriv);

  // 5. 共有鍵導出
  const salt = sha256(concat(encode(A), encode(recipientPub), encodeBigInt(f)));
  const sharedKey = hkdf(S.x, salt, "ECCHImail-v2", 32);

  // 6. 復号 (SHA256-CTR + HMAC-SHA256 検証)
  return decryptThenVerify(sharedKey, iv, ciphertext, hmac);
}
```

---

## 12. 将来の拡張

- **ML-DSA ハイブリッド署名:** P-256 Schnorr + ML-DSA-44 のデュアル署名による耐量子性
- **エフェメラル ECDH 併用:** 完全な Forward Secrecy の実現
- **グループメール:** マルチパーティ f-offset ECDH の検討
- **メッセージ有効期限:** サーバ上での自動削除機能
- **Tor 統合:** ネットワーク層の匿名性強化
- **ブロックチェーン統合:** サーバ連合の代替としてオンチェーン配送

---

## Appendix A: P-256 曲線パラメータ

```
p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
h  = 1
```