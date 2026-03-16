import { ecchimailclientAPI } from "./api.js";
import { PointPairSchnorrP256 } from "./cryptos/ecdsa.js";
// ─── State ──────────────────────────────────────────────
let client = null;
let privKeyHex = "";
let pubKeyHex = "";
const schnorr = new PointPairSchnorrP256();
// ─── UI構築 ─────────────────────────────────────────────
function buildUI() {
    document.body.innerHTML = "";
    const app = el("div", "app");
    app.innerHTML = `
        <div class="header">
            <div class="logo">ECCHImail</div>
            <div class="status" id="status">未接続</div>
        </div>

        <!-- 新規鍵生成表示パネル -->
        <div class="panel hidden" id="newKeyPanel">
            <h2>鍵ペアを生成しました</h2>
            <div class="warning">この秘密鍵を安全に保管してください。再表示できません。</div>
            <div class="field">
                <label>秘密鍵</label>
                <div class="key-display" id="newPrivKey"></div>
            </div>
            <div class="field">
                <label>公開鍵 (アドレス)</label>
                <div class="key-display" id="newPubKey"></div>
            </div>
            <div class="field">
                <label>PINコード（ブラウザに鍵を保存する場合）</label>
                <input type="password" inputmode="numeric" id="newPinInput" placeholder="数字を入力（空欄でスキップ）" />
            </div>
            <button id="newKeyOk">確認しました</button>
        </div>

        <!-- PIN入力パネル (保存済み鍵がある場合) -->
        <div class="panel hidden" id="pinPanel">
            <h2>鍵の復元</h2>
            <div class="field">
                <label>PINコード</label>
                <input type="password" inputmode="numeric" id="pinInput" placeholder="PINを入力" />
            </div>
            <button id="pinUnlockBtn">復元</button>
            <div class="result" id="pinResult"></div>
            <div style="margin-top:12px;text-align:center;">
                <span class="wipe-link" id="wipeBtn">保存済みデータをすべて破棄</span>
            </div>
        </div>

        <!-- 接続パネル -->
        <div class="panel hidden" id="connectPanel">
            <h2>接続設定</h2>

            <div class="toggle-row">
                <button class="toggle-btn active" id="toggleSeed">DNS Seed</button>
                <button class="toggle-btn" id="toggleDirect">直接接続</button>
            </div>

            <!-- DNS Seed モード -->
            <div id="seedMode">
                <div class="field">
                    <label>DNS Seed</label>
                    <input type="text" id="dnsSeed" placeholder="_ecchimail.example.com" />
                </div>
            </div>

            <!-- 直接接続モード -->
            <div id="directMode" class="hidden">
                <div class="field">
                    <label>プロトコル</label>
                    <div class="toggle-row">
                        <button class="toggle-btn small active" id="toggleWs">ws://</button>
                        <button class="toggle-btn small" id="toggleWss">wss://</button>
                    </div>
                </div>
                <div class="field">
                    <label>アドレス</label>
                    <input type="text" id="directHost" placeholder="localhost" />
                </div>
                <div class="field">
                    <label>ポート</label>
                    <input type="number" id="directPort" placeholder="3000" value="3000" />
                </div>
            </div>

            <div class="field">
                <label>秘密鍵 (hex) — 空欄で新規生成</label>
                <input type="text" id="privKeyInput" placeholder="省略すると自動生成" />
            </div>
            <button id="connectBtn">接続</button>
        </div>

        <!-- メインパネル (接続後表示) -->
        <div class="panel hidden" id="mainPanel">
            <div class="address-box">
                <label>あなたのアドレス</label>
                <div class="address" id="myAddress"></div>
                <div class="address-actions">
                    <button class="small-btn" id="copyAddr">コピー</button>
                </div>
            </div>

            <!-- 送信 -->
            <div class="section">
                <h3>送信</h3>
                <div class="field">
                    <label>宛先アドレス (hex 130文字)</label>
                    <input type="text" id="toAddress" placeholder="04..." />
                </div>
                <div class="field">
                    <label>メッセージ</label>
                    <textarea id="messageBody" rows="4" placeholder="こんにちは"></textarea>
                </div>
                <button id="sendBtn">送信</button>
                <div class="result" id="sendResult"></div>
            </div>

            <!-- 受信 -->
            <div class="section">
                <h3>受信</h3>
                <button id="lookBtn">メール確認</button>
                <span class="count" id="mailCount"></span>
                <div id="mailList"></div>
            </div>

            <!-- 保存済み -->
            <div class="section">
                <h3>保存済みメール</h3>
                <button id="savedBtn">一覧を表示</button>
                <div id="savedList"></div>
            </div>

            <!-- ログ -->
            <div class="section">
                <h3>ログ</h3>
                <div class="log" id="log"></div>
            </div>
        </div>

        <!-- 秘密鍵表示フローティングボタン -->
        <button class="fab hidden" id="privKeyFab">鍵</button>
        <div class="fab-popup hidden" id="privKeyPopup">
            <label>秘密鍵</label>
            <div class="key-display" id="fabPrivKey"></div>
            <button class="small-btn" id="fabCopyPriv">コピー</button>
        </div>
    `;
    document.body.appendChild(app);
    applyStyles();
    bindEvents();
}
function el(tag, className) {
    const e = document.createElement(tag);
    if (className)
        e.className = className;
    return e;
}
// ─── スタイル ───────────────────────────────────────────
function applyStyles() {
    const style = document.createElement("style");
    style.textContent = `
        :root {
            --bg: #0a0a0f;
            --surface: #12121a;
            --surface2: #1a1a28;
            --border: #2a2a3a;
            --accent: #00d4aa;
            --accent2: #00a888;
            --text: #e0e0e8;
            --text2: #8888aa;
            --danger: #ff4466;
            --success: #00d4aa;
            --radius: 8px;
        }

        body {
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }

        .app {
            max-width: 640px;
            margin: 0 auto;
            padding: 16px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 16px;
        }

        .logo {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }

        .status {
            font-size: 13px;
            padding: 4px 12px;
            border-radius: 99px;
            background: var(--surface2);
            color: var(--text2);
        }
        .status.connected {
            background: #002a20;
            color: var(--success);
        }

        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            margin-bottom: 16px;
        }
        .panel.hidden { display: none; }
        .hidden { display: none !important; }

        h2 {
            margin: 0 0 16px;
            font-size: 16px;
            font-weight: 600;
        }
        h3 {
            margin: 0 0 12px;
            font-size: 14px;
            font-weight: 600;
            color: var(--accent);
        }

        .field {
            margin-bottom: 12px;
        }
        .field label {
            display: block;
            font-size: 12px;
            color: var(--text2);
            margin-bottom: 4px;
        }

        input, textarea {
            width: 100%;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            color: var(--text);
            padding: 10px 12px;
            font-size: 14px;
            font-family: inherit;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.2s;
        }
        input:focus, textarea:focus {
            border-color: var(--accent);
        }
        textarea {
            resize: vertical;
        }
        input[type="number"] {
            -moz-appearance: textfield;
        }
        input[type="number"]::-webkit-inner-spin-button,
        input[type="number"]::-webkit-outer-spin-button {
            -webkit-appearance: none;
        }

        button {
            background: var(--accent);
            color: #000;
            border: none;
            border-radius: var(--radius);
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        button:hover { opacity: 0.85; }
        button:active { opacity: 0.7; }
        button:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        .small-btn {
            padding: 4px 12px;
            font-size: 12px;
            margin-top: 6px;
        }
        .small-btn.secondary {
            background: var(--surface2);
            color: var(--text2);
            border: 1px solid var(--border);
        }

        .toggle-row {
            display: flex;
            gap: 0;
            margin-bottom: 12px;
        }
        .toggle-btn {
            flex: 1;
            background: var(--surface2);
            color: var(--text2);
            border: 1px solid var(--border);
            border-radius: 0;
            padding: 8px 12px;
            font-size: 13px;
            font-weight: 500;
        }
        .toggle-btn:first-child {
            border-radius: var(--radius) 0 0 var(--radius);
        }
        .toggle-btn:last-child {
            border-radius: 0 var(--radius) var(--radius) 0;
            border-left: none;
        }
        .toggle-btn.active {
            background: var(--accent);
            color: #000;
            border-color: var(--accent);
        }
        .toggle-btn.small {
            padding: 6px 16px;
            font-size: 12px;
        }

        .section {
            border-top: 1px solid var(--border);
            padding-top: 16px;
            margin-top: 16px;
        }

        .address-box {
            background: var(--surface2);
            border-radius: var(--radius);
            padding: 12px;
            margin-bottom: 8px;
        }
        .address-box label {
            font-size: 12px;
            color: var(--text2);
        }
        .address {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            word-break: break-all;
            color: var(--accent);
            margin-top: 4px;
            line-height: 1.5;
        }
        .address-actions {
            display: flex;
            gap: 8px;
            margin-top: 8px;
        }

        .count {
            font-size: 13px;
            color: var(--text2);
            margin-left: 8px;
        }

        .mail-item {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 12px;
            margin-top: 8px;
        }
        .mail-item .from {
            font-size: 11px;
            color: var(--text2);
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }
        .mail-item .body {
            margin-top: 8px;
            font-size: 14px;
            white-space: pre-wrap;
        }
        .mail-item .meta {
            font-size: 11px;
            color: var(--text2);
            margin-top: 6px;
        }

        .result {
            margin-top: 8px;
            font-size: 13px;
        }
        .result.ok { color: var(--success); }
        .result.err { color: var(--danger); }

        .log {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            max-height: 200px;
            overflow-y: auto;
            color: var(--text2);
        }
        .log div { margin-bottom: 2px; }
        .log .err { color: var(--danger); }
        .log .ok { color: var(--success); }

        .key-display {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            word-break: break-all;
            color: var(--accent);
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 8px;
            margin-top: 4px;
            line-height: 1.5;
            user-select: all;
        }

        .warning {
            background: #2a1a00;
            border: 1px solid #664400;
            border-radius: var(--radius);
            color: #ffaa44;
            font-size: 12px;
            padding: 8px 12px;
            margin-bottom: 12px;
        }

        .fab {
            position: fixed;
            bottom: 20px;
            left: 20px;
            width: 44px;
            height: 44px;
            border-radius: 50%;
            background: var(--surface2);
            color: var(--text2);
            border: 1px solid var(--border);
            font-size: 12px;
            font-weight: 600;
            padding: 0;
            cursor: pointer;
            z-index: 100;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .fab:hover {
            background: var(--surface);
            border-color: var(--accent);
            color: var(--accent);
        }
        .fab.hidden { display: none; }

        .fab-popup {
            position: fixed;
            bottom: 74px;
            left: 20px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 12px;
            width: 300px;
            max-width: calc(100vw - 56px);
            z-index: 100;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }
        .fab-popup.hidden { display: none; }
        .fab-popup label {
            font-size: 12px;
            color: var(--text2);
        }

        .mail-row {
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 10px 12px;
            margin-top: 6px;
        }
        .mail-id {
            flex: 1;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: var(--text2);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .saved-name {
            flex: 1;
            font-size: 13px;
            color: var(--text);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .open-mail-btn {
            flex-shrink: 0;
        }

        .modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 200;
            padding: 16px;
        }
        .modal {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            width: 100%;
            max-width: 560px;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
        }
        .modal-header h3 {
            margin: 0;
            color: var(--text);
        }
        .modal-close {
            background: none;
            border: none;
            color: var(--text2);
            font-size: 20px;
            cursor: pointer;
            padding: 0 4px;
            line-height: 1;
        }
        .modal-close:hover {
            color: var(--text);
        }
        .modal-body {
            padding: 20px;
        }
        .modal-field {
            margin-bottom: 16px;
        }
        .modal-field label {
            display: block;
            font-size: 12px;
            color: var(--text2);
            margin-bottom: 4px;
        }
        .modal-value {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 10px;
            font-size: 13px;
            color: var(--text);
            word-break: break-all;
            line-height: 1.5;
        }
        .modal-value.mono {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: var(--accent);
        }
        .modal-value.message {
            white-space: pre-wrap;
            font-size: 14px;
        }
        .modal-loading {
            color: var(--text2);
            font-size: 13px;
            text-align: center;
            padding: 20px;
        }
        .modal-error {
            color: var(--danger);
            font-size: 13px;
            text-align: center;
            padding: 20px;
        }

        .modal-save {
            display: flex;
            justify-content: flex-end;
            margin-top: 16px;
        }
        .save-btn {
            background: var(--surface2);
            color: var(--text);
            border: 1px solid var(--border);
            padding: 8px 20px;
            font-size: 13px;
        }
        .save-btn:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .save-confirm-btn {
            width: 100%;
            margin-top: 8px;
        }

        .wipe-link {
            color: var(--danger);
            cursor: pointer;
            font-size: 12px;
            text-decoration: underline;
        }
        .wipe-link:hover {
            opacity: 0.8;
        }
    `;
    document.head.appendChild(style);
}
// ─── ログ ───────────────────────────────────────────────
function log(msg, type = "") {
    const logEl = document.getElementById("log");
    if (!logEl)
        return;
    const d = document.createElement("div");
    if (type)
        d.className = type;
    const time = new Date().toLocaleTimeString();
    d.textContent = `[${time}] ${msg}`;
    logEl.prepend(d);
}
// ─── 接続モード状態 ────────────────────────────────────
let connectMode = "seed";
let protocol = "ws";
// ─── イベント ───────────────────────────────────────────
function bindEvents() {
    const connectBtn = document.getElementById("connectBtn");
    const sendBtn = document.getElementById("sendBtn");
    const lookBtn = document.getElementById("lookBtn");
    const copyAddr = document.getElementById("copyAddr");
    const newKeyOk = document.getElementById("newKeyOk");
    const privKeyFab = document.getElementById("privKeyFab");
    const privKeyPopup = document.getElementById("privKeyPopup");
    const fabCopyPriv = document.getElementById("fabCopyPriv");
    // 接続モード切替
    const toggleSeed = document.getElementById("toggleSeed");
    const toggleDirect = document.getElementById("toggleDirect");
    toggleSeed.addEventListener("click", () => {
        connectMode = "seed";
        toggleSeed.classList.add("active");
        toggleDirect.classList.remove("active");
        document.getElementById("seedMode").classList.remove("hidden");
        document.getElementById("directMode").classList.add("hidden");
    });
    toggleDirect.addEventListener("click", () => {
        connectMode = "direct";
        toggleDirect.classList.add("active");
        toggleSeed.classList.remove("active");
        document.getElementById("directMode").classList.remove("hidden");
        document.getElementById("seedMode").classList.add("hidden");
    });
    // プロトコル切替
    const toggleWs = document.getElementById("toggleWs");
    const toggleWss = document.getElementById("toggleWss");
    toggleWs.addEventListener("click", () => {
        protocol = "ws";
        toggleWs.classList.add("active");
        toggleWss.classList.remove("active");
    });
    toggleWss.addEventListener("click", () => {
        protocol = "wss";
        toggleWss.classList.add("active");
        toggleWs.classList.remove("active");
    });
    connectBtn.addEventListener("click", handleConnect);
    sendBtn.addEventListener("click", handleSend);
    lookBtn.addEventListener("click", handleLook);
    const savedBtn = document.getElementById("savedBtn");
    savedBtn.addEventListener("click", handleSavedList);
    copyAddr.addEventListener("click", () => {
        navigator.clipboard.writeText(pubKeyHex);
        log("アドレスをコピーしました", "ok");
    });
    // 新規鍵生成確認ボタン
    newKeyOk.addEventListener("click", async () => {
        const newPin = document.getElementById("newPinInput").value.trim();
        if (newPin) {
            // PINで暗号化してlocalStorageに保存
            await savePrivKeyWithPin(newPin, hexToBytes(privKeyHex));
            log("鍵をPINで暗号化して保存しました", "ok");
        }
        document.getElementById("newKeyPanel").classList.add("hidden");
        proceedConnect();
    });
    // 秘密鍵FABトグル
    privKeyFab.addEventListener("click", () => {
        privKeyPopup.classList.toggle("hidden");
    });
    // FABからコピー
    fabCopyPriv.addEventListener("click", () => {
        navigator.clipboard.writeText(privKeyHex);
        log("秘密鍵をコピーしました", "ok");
    });
    // ポップアップ外クリックで閉じる
    document.addEventListener("click", (e) => {
        if (!privKeyPopup.classList.contains("hidden") &&
            !privKeyPopup.contains(e.target) &&
            e.target !== privKeyFab) {
            privKeyPopup.classList.add("hidden");
        }
    });
}
// ─── 接続先を決定 ──────────────────────────────────────
function getTarget() {
    if (connectMode === "seed") {
        const seed = document.getElementById("dnsSeed").value.trim();
        if (!seed)
            throw new Error("DNS Seedを入力してください");
        return seed;
    }
    else {
        const host = document.getElementById("directHost").value.trim();
        const port = document.getElementById("directPort").value.trim();
        if (!host)
            throw new Error("アドレスを入力してください");
        if (!port)
            throw new Error("ポートを入力してください");
        return `${protocol}://${host}:${port}`;
    }
}
// ─── 接続 ───────────────────────────────────────────────
let pendingTarget = "";
async function handleConnect() {
    const connectBtn = document.getElementById("connectBtn");
    const privInput = document.getElementById("privKeyInput").value.trim();
    connectBtn.disabled = true;
    connectBtn.textContent = "接続中...";
    try {
        pendingTarget = getTarget();
        log(`接続先: ${pendingTarget}`);
        // 鍵の準備
        let privKey;
        let isNewKey = false;
        if (privInput) {
            privKey = hexToBytes(privInput);
            log("秘密鍵を読み込みました");
        }
        else {
            const kp = schnorr.generateKeyPair();
            privKey = kp.privateKey;
            isNewKey = true;
            log("新しい鍵ペアを生成しました", "ok");
        }
        privKeyHex = bytesToHex(privKey);
        const pubKeyPair = schnorr.privatekeytoPublicKey(privKey);
        const pubKeyRaw = new Uint8Array(65);
        pubKeyRaw[0] = 0x04;
        pubKeyRaw.set(padTo32(pubKeyPair[0]), 1);
        pubKeyRaw.set(padTo32(pubKeyPair[1]), 33);
        pubKeyHex = bytesToHex(pubKeyRaw);
        if (isNewKey) {
            // 新規鍵を表示して確認を待つ
            document.getElementById("newPrivKey").textContent = privKeyHex;
            document.getElementById("newPubKey").textContent = pubKeyHex;
            document.getElementById("connectPanel").classList.add("hidden");
            document.getElementById("newKeyPanel").classList.remove("hidden");
            // proceedConnect は newKeyOk ボタンから呼ばれる
        }
        else {
            await proceedConnect();
        }
    }
    catch (e) {
        log(`接続失敗: ${e.message}`, "err");
        connectBtn.disabled = false;
        connectBtn.textContent = "接続";
    }
}
async function proceedConnect() {
    const statusEl = document.getElementById("status");
    try {
        client = new ecchimailclientAPI(hexToBytes(privKeyHex));
        await client.connect(pendingTarget);
        // UI切替
        document.getElementById("newKeyPanel").classList.add("hidden");
        document.getElementById("connectPanel").classList.add("hidden");
        document.getElementById("mainPanel").classList.remove("hidden");
        document.getElementById("myAddress").textContent = pubKeyHex;
        statusEl.textContent = "接続中";
        statusEl.className = "status connected";
        // FAB表示 + 秘密鍵セット
        document.getElementById("privKeyFab").classList.remove("hidden");
        document.getElementById("fabPrivKey").textContent = privKeyHex;
        log("サーバに接続しました", "ok");
        log(`アドレス: ${pubKeyHex.slice(0, 20)}...`, "ok");
    }
    catch (e) {
        log(`接続失敗: ${e.message}`, "err");
        const connectBtn = document.getElementById("connectBtn");
        connectBtn.disabled = false;
        connectBtn.textContent = "接続";
        document.getElementById("newKeyPanel").classList.add("hidden");
        document.getElementById("connectPanel").classList.remove("hidden");
    }
}
// ─── 送信 ───────────────────────────────────────────────
async function handleSend() {
    if (!client)
        return;
    const toAddr = document.getElementById("toAddress").value.trim();
    const body = document.getElementById("messageBody").value;
    const resultEl = document.getElementById("sendResult");
    if (!toAddr || !body) {
        resultEl.textContent = "宛先とメッセージを入力してください";
        resultEl.className = "result err";
        return;
    }
    const sendBtn = document.getElementById("sendBtn");
    sendBtn.disabled = true;
    try {
        const to = hexToBytes(toAddr);
        const plaintext = new TextEncoder().encode(body);
        await client.send(to, plaintext);
        resultEl.textContent = "送信しました ✓";
        resultEl.className = "result ok";
        document.getElementById("messageBody").value = "";
        log(`送信完了 → ${toAddr.slice(0, 16)}...`, "ok");
    }
    catch (e) {
        resultEl.textContent = `送信失敗: ${e.message}`;
        resultEl.className = "result err";
        log(`送信エラー: ${e.message}`, "err");
    }
    sendBtn.disabled = false;
}
// ─── 受信 ───────────────────────────────────────────────
async function handleLook() {
    if (!client)
        return;
    const lookBtn = document.getElementById("lookBtn");
    const countEl = document.getElementById("mailCount");
    const listEl = document.getElementById("mailList");
    lookBtn.disabled = true;
    lookBtn.textContent = "確認中...";
    log("メールを確認中...");
    try {
        const ids = await client.look();
        countEl.textContent = `${ids.length}件`;
        if (ids.length === 0) {
            listEl.innerHTML = '<div style="color:var(--text2);font-size:13px;margin-top:8px;">メールはありません</div>';
            log("メールなし");
        }
        else {
            listEl.innerHTML = "";
            log(`${ids.length}件のメールを検出`, "ok");
            for (const id of ids) {
                const row = document.createElement("div");
                row.className = "mail-row";
                row.innerHTML = `
                    <span class="mail-id">${id}</span>
                    <button class="small-btn open-mail-btn">開封</button>
                `;
                row.querySelector(".open-mail-btn").addEventListener("click", () => openMailModal(id));
                listEl.appendChild(row);
            }
        }
    }
    catch (e) {
        log(`LOOK失敗: ${e.message}`, "err");
    }
    lookBtn.disabled = false;
    lookBtn.textContent = "メール確認";
}
async function openMailModal(messageId) {
    if (!client)
        return;
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    const modal = document.createElement("div");
    modal.className = "modal";
    modal.innerHTML = `
        <div class="modal-header">
            <h3>メール詳細</h3>
            <button class="modal-close">x</button>
        </div>
        <div class="modal-body">
            <div class="modal-loading">取得中...</div>
        </div>
    `;
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    let acked = false;
    const doAck = async () => {
        if (acked || !client)
            return;
        acked = true;
        try {
            await client.ack(messageId);
            log(`ACK送信: ${messageId.slice(0, 16)}...`, "ok");
        }
        catch (e) {
            log(`ACK失敗: ${e.message}`, "err");
        }
    };
    const close = async () => {
        await doAck();
        overlay.remove();
    };
    overlay.addEventListener("click", async (e) => { if (e.target === overlay)
        await close(); });
    modal.querySelector(".modal-close").addEventListener("click", async () => await close());
    try {
        const result = await client.fetch(messageId);
        const body = modal.querySelector(".modal-body");
        if (result) {
            const text = new TextDecoder().decode(result.plaintext);
            body.innerHTML = `
                <div class="modal-field">
                    <label>Message ID</label>
                    <div class="modal-value mono">${escapeHtml(result.messageId)}</div>
                </div>
                <div class="modal-field">
                    <label>送信者</label>
                    <div class="modal-value mono">${escapeHtml(result.sender)}</div>
                </div>
                <div class="modal-field">
                    <label>本文</label>
                    <div class="modal-value message">${escapeHtml(text)}</div>
                </div>
                <div class="modal-save">
                    <button class="save-btn">保存</button>
                </div>
            `;
            // 保存ボタン
            body.querySelector(".save-btn").addEventListener("click", () => {
                showSaveDialog(result.rawMail, async () => {
                    await doAck();
                });
            });
            log(`メール開封: ${messageId.slice(0, 16)}...`, "ok");
        }
        else {
            body.innerHTML = `<div class="modal-error">復号に失敗しました</div>`;
            log(`メール復号失敗: ${messageId.slice(0, 16)}...`, "err");
        }
    }
    catch (e) {
        const body = modal.querySelector(".modal-body");
        body.innerHTML = `<div class="modal-error">取得エラー: ${escapeHtml(e.message)}</div>`;
        log(`メール取得失敗: ${e.message}`, "err");
    }
}
// ─── 保存ダイアログ ─────────────────────────────────────
function showSaveDialog(rawMail, onSaved) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.style.zIndex = "300";
    const dialog = document.createElement("div");
    dialog.className = "modal";
    dialog.style.maxWidth = "400px";
    dialog.innerHTML = `
        <div class="modal-header">
            <h3>メールを保存</h3>
            <button class="modal-close">x</button>
        </div>
        <div class="modal-body">
            <div class="field">
                <label>保存名（一意の名前をつけてください）</label>
                <input type="text" class="save-name-input" placeholder="例: 友人からのメール" />
            </div>
            <div class="save-error hidden"></div>
            <button class="save-confirm-btn">保存する</button>
        </div>
    `;
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.addEventListener("click", (e) => { if (e.target === overlay)
        close(); });
    dialog.querySelector(".modal-close").addEventListener("click", close);
    const input = dialog.querySelector(".save-name-input");
    const errorEl = dialog.querySelector(".save-error");
    const confirmBtn = dialog.querySelector(".save-confirm-btn");
    confirmBtn.addEventListener("click", () => {
        const name = input.value.trim();
        if (!name) {
            errorEl.textContent = "名前を入力してください";
            errorEl.classList.remove("hidden");
            errorEl.style.color = "var(--danger)";
            errorEl.style.fontSize = "12px";
            errorEl.style.marginBottom = "8px";
            return;
        }
        const key = `ecchimail_saved_${name}`;
        if (localStorage.getItem(key) !== null) {
            errorEl.textContent = "この名前は既に使われています";
            errorEl.classList.remove("hidden");
            errorEl.style.color = "var(--danger)";
            errorEl.style.fontSize = "12px";
            errorEl.style.marginBottom = "8px";
            return;
        }
        // 暗号文をBase64で保存
        localStorage.setItem(key, uint8ToBase64(rawMail));
        log(`メール保存: "${name}"`, "ok");
        onSaved();
        close();
    });
}
// ─── 保存済みメール一覧 ────────────────────────────────
function getSavedMailNames() {
    const names = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith("ecchimail_saved_")) {
            names.push(key.slice("ecchimail_saved_".length));
        }
    }
    return names.sort();
}
function loadSavedMail(name) {
    const data = localStorage.getItem(`ecchimail_saved_${name}`);
    if (!data)
        return null;
    return base64ToUint8(data);
}
function deleteSavedMail(name) {
    localStorage.removeItem(`ecchimail_saved_${name}`);
}
// ─── 保存済み一覧表示 ──────────────────────────────────
function handleSavedList() {
    const listEl = document.getElementById("savedList");
    const names = getSavedMailNames();
    if (names.length === 0) {
        listEl.innerHTML = '<div style="color:var(--text2);font-size:13px;margin-top:8px;">保存済みメールはありません</div>';
        return;
    }
    listEl.innerHTML = "";
    for (const name of names) {
        const row = document.createElement("div");
        row.className = "mail-row";
        row.innerHTML = `
            <span class="saved-name">${escapeHtml(name)}</span>
            <button class="small-btn open-saved-btn">開く</button>
            <button class="small-btn secondary delete-saved-btn">削除</button>
        `;
        row.querySelector(".open-saved-btn").addEventListener("click", () => openSavedMailModal(name));
        row.querySelector(".delete-saved-btn").addEventListener("click", () => {
            deleteSavedMail(name);
            log(`保存済みメール削除: "${name}"`, "ok");
            handleSavedList(); // 再描画
        });
        listEl.appendChild(row);
    }
}
// ─── 保存済みメール開封モーダル ─────────────────────────
function openSavedMailModal(name) {
    if (!client)
        return;
    const rawMail = loadSavedMail(name);
    if (!rawMail) {
        log(`保存済みメール "${name}" が見つかりません`, "err");
        return;
    }
    const result = client.openLocal(rawMail);
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    const modal = document.createElement("div");
    modal.className = "modal";
    if (result) {
        const text = new TextDecoder().decode(result.plaintext);
        modal.innerHTML = `
            <div class="modal-header">
                <h3>${escapeHtml(name)}</h3>
                <button class="modal-close">x</button>
            </div>
            <div class="modal-body">
                <div class="modal-field">
                    <label>Message ID</label>
                    <div class="modal-value mono">${escapeHtml(result.messageId)}</div>
                </div>
                <div class="modal-field">
                    <label>送信者</label>
                    <div class="modal-value mono">${escapeHtml(result.sender)}</div>
                </div>
                <div class="modal-field">
                    <label>本文</label>
                    <div class="modal-value message">${escapeHtml(text)}</div>
                </div>
            </div>
        `;
        log(`保存済みメール開封: "${name}"`, "ok");
    }
    else {
        modal.innerHTML = `
            <div class="modal-header">
                <h3>${escapeHtml(name)}</h3>
                <button class="modal-close">x</button>
            </div>
            <div class="modal-body">
                <div class="modal-error">復号に失敗しました（秘密鍵が異なる可能性があります）</div>
            </div>
        `;
        log(`保存済みメール復号失敗: "${name}"`, "err");
    }
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.addEventListener("click", (e) => { if (e.target === overlay)
        close(); });
    modal.querySelector(".modal-close").addEventListener("click", close);
}
function uint8ToBase64(bytes) {
    let binary = "";
    for (const b of bytes)
        binary += String.fromCharCode(b);
    return btoa(binary);
}
function base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
// ─── ユーティリティ ─────────────────────────────────────
function hexToBytes(hex) {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
function padTo32(bytes) {
    if (bytes.length === 32)
        return bytes;
    const out = new Uint8Array(32);
    out.set(bytes, 32 - bytes.length);
    return out;
}
function escapeHtml(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
// ─── PBKDF2 (WebCrypto API) ────────────────────────────
async function deriveKeyFromPin(pin, salt) {
    const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt: salt,
        iterations: 1000000,
        hash: "SHA-256",
    }, keyMaterial, 256);
    return new Uint8Array(bits);
}
// ─── 秘密鍵のPIN暗号化保存 ────────────────────────────
const cipherInstance = new (await import("./cryptos/xor.js")).cipher();
async function savePrivKeyWithPin(pin, privKey) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aesKey = await deriveKeyFromPin(pin, salt);
    const encrypted = cipherInstance.encrypt(privKey, aesKey);
    localStorage.setItem("ecchimail_salt", uint8ToBase64(salt));
    localStorage.setItem("ecchimail_encrypted_key", uint8ToBase64(encrypted));
}
async function loadPrivKeyWithPin(pin) {
    const saltB64 = localStorage.getItem("ecchimail_salt");
    const encB64 = localStorage.getItem("ecchimail_encrypted_key");
    if (!saltB64 || !encB64)
        return null;
    const salt = base64ToUint8(saltB64);
    const encrypted = base64ToUint8(encB64);
    const aesKey = await deriveKeyFromPin(pin, salt);
    return cipherInstance.decrypt(encrypted, aesKey);
}
function hasSavedKey() {
    return localStorage.getItem("ecchimail_encrypted_key") !== null;
}
function wipeSavedData() {
    localStorage.removeItem("ecchimail_salt");
    localStorage.removeItem("ecchimail_encrypted_key");
    // 保存済みメールも全削除
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith("ecchimail_"))
            keys.push(k);
    }
    keys.forEach(k => localStorage.removeItem(k));
}
// ─── 起動 ───────────────────────────────────────────────
buildUI();
// 保存済み鍵があればPINパネル、なければ接続パネルを表示
if (hasSavedKey()) {
    document.getElementById("pinPanel").classList.remove("hidden");
    const pinUnlockBtn = document.getElementById("pinUnlockBtn");
    const pinInput = document.getElementById("pinInput");
    const pinResult = document.getElementById("pinResult");
    const wipeBtn = document.getElementById("wipeBtn");
    // 数字のみ
    pinInput.addEventListener("input", () => {
        pinInput.value = pinInput.value.replace(/[^0-9]/g, "");
    });
    pinUnlockBtn.addEventListener("click", async () => {
        const pin = pinInput.value;
        if (!pin) {
            pinResult.textContent = "PINを入力してください";
            pinResult.className = "result err";
            return;
        }
        pinUnlockBtn.disabled = true;
        pinUnlockBtn.textContent = "復元中...";
        const privKey = await loadPrivKeyWithPin(pin);
        if (privKey) {
            privKeyHex = bytesToHex(privKey);
            const pubKeyPair = schnorr.privatekeytoPublicKey(privKey);
            const pubKeyRaw = new Uint8Array(65);
            pubKeyRaw[0] = 0x04;
            pubKeyRaw.set(padTo32(pubKeyPair[0]), 1);
            pubKeyRaw.set(padTo32(pubKeyPair[1]), 33);
            pubKeyHex = bytesToHex(pubKeyRaw);
            // PINパネル非表示 → 接続パネル表示（秘密鍵は自動入力済み）
            document.getElementById("pinPanel").classList.add("hidden");
            document.getElementById("connectPanel").classList.remove("hidden");
            document.getElementById("privKeyInput").value = privKeyHex;
            log("鍵を復元しました", "ok");
        }
        else {
            pinResult.textContent = "PINが間違っています";
            pinResult.className = "result err";
            pinUnlockBtn.disabled = false;
            pinUnlockBtn.textContent = "復元";
        }
    });
    wipeBtn.addEventListener("click", () => {
        if (confirm("保存済みの鍵とメールをすべて削除しますか？")) {
            wipeSavedData();
            location.reload();
        }
    });
}
else {
    document.getElementById("connectPanel").classList.remove("hidden");
}
