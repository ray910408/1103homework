# CLAUDE.md

## 專案概要
資安攻擊手法互動教學網站（課堂作業）。目標讀者：資安新手。
用互動操作 + 圖像化，讓人幾分鐘內看懂一種攻擊「為什麼會成功、要怎麼修」。

- 第一版主題（5 個）：SQL Injection、XSS、SSRF、CSRF、Command Injection
- 第二批（OWASP Top 10:2025 其他分類）：IDOR、Path Traversal（A01）、JWT 竄改（A04）、Brute Force（A07）
- 每個主題在 `topics.ts` 標 OWASP Top 10:2025 分類（`owasp` 欄位），首頁卡片會顯示
- 部署：GitHub Pages（純靜態網站）
- 介面語言：繁體中文；技術名詞保留英文，第一次出現時附中文，例如「SQL Injection（SQL 注入）」

## 技術棧
- Vite + React + TypeScript（strict）
- 路由：`react-router` 的 `HashRouter`（GitHub Pages 沒有 SPA fallback，用 hash 避免重新整理時 404）
- 樣式：Vite 內建 CSS Modules + `src/styles/global.css` 的 CSS 變數；不加 UI 框架
- 圖像化：React 直接畫 SVG + CSS transition；真的不夠用再加動畫套件
- SQLi 引擎：`sql.js`（在瀏覽器裡跑的 SQLite WASM）
- 測試：Vitest
- 新增任何 dependency 前，先確認瀏覽器原生 API 或現有套件做不到

## 指令
```bash
npm install
npm run dev        # 開發伺服器
npm run build      # tsc -b && vite build
npm run preview    # 預覽 build 結果
npm test           # vitest run
npm run lint
```

## 架構
```
src/
  main.tsx / App.tsx     HashRouter、首頁、模組路由
  components/ui.tsx      跨模組共用元件（至少 2 個模組用到才抽出來）
  styles/global.css      色彩語意變數 + 共用元件樣式
  modules/<topic>/       topic = sqli | xss | ssrf | csrf | idor | path | jwt | brute（cmdi 尚未建立）
    index.tsx            模組頁面
    engine.ts            模擬邏輯：純 TS 函式，不依賴 React
    engine.test.ts
```

### 每個模組固定 4 段（結構一致，新手只需要學一次怎麼看）
1. **情境**：一個假網站介面 + 一句話說明攻擊者想做什麼
2. **動手攻擊 + 即時視覺化**：使用者輸入時，同步畫出伺服器內部發生的事
3. **漏洞版 ↔ 修補版切換**：同一個輸入，並排對照兩種程式碼與執行結果
4. **挑戰**：給一個目標讓使用者自己完成，提示分段揭露，最後才給解答

### 色彩語意（所有模組共用，不可各自定義）
| 變數 | 意義 |
|---|---|
| `--c-attack` | 使用者 / 攻擊者輸入（紅） |
| `--c-code` | 伺服器端程式碼、系統結構（藍） |
| `--c-safe` | 修補後、被擋下（綠） |
| `--c-leak` | 外洩的資料（黃） |

顏色不能是唯一的訊號：同時加 icon 或文字標籤。

### 共用元件（`src/components/ui.tsx`，新模組先用這些，不要自己再做一份）
- 版面：`Section`、`Term`（名詞解釋）、`FakeSite`（有網址列的假網站外框）
- 輸入：`TextField`、`Presets`（快速填入範例）
- 結果：`ResultBox` 的 tone：攻擊成功 = `attack`（紅）、資料外洩 = `leak`（黃）、修補版擋下 = `ok`（綠）、一般失敗 = `fail`（灰）
- 說明：`Insights`（💡 發生了什麼事）、`SegmentView` + `SegmentLegend`（把 SQL / HTML / shell 指令依 code / data / injected / comment 上色）
- 挑戰：`ChallengeCard`（hints 最後一項是解答）
- 圖解：`<svg className="diagram">`，搭配 global.css 的 `box-*`、`arrow-*`、`label-*`、`dash`。箭頭定義 `<DiagramDefs />` 已在 App.tsx 全站放一份，模組不要再放（id 會重複）

## 各模組模擬方式
- **SQLi**：`sql.js` 建假的 `users` 表。漏洞版用字串拼接，視覺化標出輸入在 SQL 中的邊界（哪一段從「資料」變成了「指令」）；修補版用 `prepare` + `bind`。WASM 要用 `import wasmUrl from 'sql.js/dist/sql-wasm-browser.wasm?url'`（瀏覽器會載入 `sql-wasm-browser.js`，兩者要成對） 搭配 `initSqlJs({ locateFile: () => wasmUrl })`，部署後路徑才會正確。
- **XSS**（Reflected / Stored / DOM-based）：payload 只在 `<iframe sandbox="allow-scripts" srcdoc=...>` 裡執行，**絕不加 `allow-same-origin`**。「偷 cookie」用 `postMessage` 傳回父頁（父頁要驗證 `event.source === iframe.contentWindow`），再畫成動畫。修補版示範 escape、`textContent`、CSP（CSP 寫在 srcdoc 內的 `<meta http-equiv>`）。
- **SSRF**：網路拓撲圖（攻擊者 → Web Server → 內網：`169.254.169.254` metadata、`localhost` admin 後台、內部 DB）。`serverFetch(url)` 用 `new URL()` 解析，再查記憶體裡的假 DNS / 假服務表。`new URL()` 會把 `2130706433`、`0x7f.1` 正規化成 `127.0.0.1`，正好拿來示範「字串黑名單為什麼擋不住」。修補版：allowlist + 解析後擋 private / loopback / link-local 位址。
- **CSRF**：同一頁並排兩個假網站 `bank.test` 與 `evil.test`，用假的 cookie jar 視覺化「瀏覽器會自動帶上 cookie」。修補版：CSRF token、`SameSite=Lax`。
- **IDOR**：假商店 `shop.test`，訂單 / 會員是記憶體裡的表。圖解並排「你是誰」（session）與「你要什麼」（網址裡的編號），看伺服器有沒有比對。修補版：查詢條件加 `owner = session.user`，不是你的就回 404；寫入路徑回 403。
- **Path Traversal**：假檔案系統 + 自寫 POSIX `join` / `resolve`（不用 Node `path`）。目錄樹 SVG 一步一步畫出 `..` 往上爬。三種模式：直接拼接、只刪一次 `../` 的過濾版、修補版（resolve 後檢查 `startsWith(BASE + '/')`）。
- **JWT**：Web Crypto（`crypto.subtle` HMAC-SHA256）真的算簽章，密鑰 `demo-secret-key`。三台伺服器：只 decode、相信 header 的 `alg`（接受 `none`）、修補版（固定 `algorithms: ['HS256']` + 驗 `exp`）。畫面只露伺服器簽章前 6 碼，避免直接複製。
- **Brute Force**：模擬時鐘（engine 不用真的 timer），字典是 18 組最常見密碼。修補版：連續失敗 N 次鎖 M 分鐘；挑戰 2 讓使用者自己調 N / M，同時不能鎖死打錯 2 次的正常使用者。
- **Command Injection**：假的「ping 工具」。自寫最小 shell tokenizer（`;` `&&` `||` `|` `$()` 反引號、換行）+ 假檔案系統 + 假指令（`ping` `ls` `cat` `whoami` `id`），視覺化一行輸入如何被拆成多個 process。修補版：argv 陣列（`execFile` 的概念）+ 輸入格式驗證。

## 安全硬規則（不可違反）
1. **所有攻擊只在瀏覽器內模擬**：不對使用者輸入的 URL / host 發出任何真實請求；本專案不需要、也不准有後端。
2. 主頁面禁用 `eval`、`new Function`、`dangerouslySetInnerHTML`；不可信的 HTML 只能進 sandbox iframe。
3. 主頁面不加嚴格 CSP：srcdoc iframe 會繼承父頁的 CSP，會讓 XSS demo 失效。
4. 所有「機密資料」都是一看就知道是假的（`FLAG{...}`、`demo-secret-key`），不放任何像真實格式的金鑰或個資。
5. 內容以理解原理 + 防禦為主：只用教科書等級的經典 payload；不收錄 WAF 繞過大全、不寫針對特定真實產品的 exploit。
6. 每頁顯示免責聲明：僅供教學用途；未經授權攻擊他人系統觸犯《刑法》妨害電腦使用罪（第 358 條起）。

## 開發規則
- engine 是核心邏輯：每個 `engine.test.ts` 至少驗證「經典 payload 在漏洞版成功、在修補版失敗」。
- UI 改動要用 `npm run dev` 在瀏覽器實際操作確認；宣稱完成前跑 `npm test` 與 `npm run build`。
- 新手導向：每個專有名詞第一次出現要有白話解釋（tooltip 或旁註）；一個畫面只講一個概念。
- 無障礙基本款：所有互動都能用鍵盤操作；尊重 `prefers-reduced-motion`。
- `useEffect` 的 arrow function 一律加大括號，不要隱式回傳：新版瀏覽器的 `window.scrollTo` 等 API 會回傳 Promise，被 React 當成 cleanup 執行就整頁 crash。
- 模組完成的定義：4 段齊全、engine 測試通過、build 通過、有免責聲明。

## 部署
- `vite.config.ts` 設 `base: './'`（相對路徑，不管 repo 叫什麼名字都能用）
- CI/CD：`.github/workflows/ci-cd.yml`。push / PR 都跑 lint → test → build；push 到 `main` 且 CI 通過才部署到 GitHub Pages
- Actions 一律用 commit SHA 釘版本（後面註解版號），更新時到 https://vite.dev/guide/static-deploy 對照
- 網址：https://ray910408.github.io/1103homework/

## 開發順序
1. ✅ Scaffold：`npm create vite@latest . -- --template react-ts`。資料夾非空時選「Ignore files and continue」，**不要選 Remove existing files**（會刪掉這份 CLAUDE.md）。接著加 `react-router`、`sql.js`、`vitest`，在 `package.json` 加 `"test": "vitest run"`，然後 `git init`。
2. ✅ 首頁 + 共用版型 + 色彩變數
3. ✅ **SQLi 先做完，當範本模組**：確立 4 段結構後，其他模組照抄結構
4. ✅ XSS、SSRF、CSRF（各自 fork 子代理平行開發，主對話整合 + 瀏覽器 QA）
   - ⏸ Command Injection：子代理產生內容時被安全檢查攔下，目前只保留在 topics.ts（`ready: false`），沒有模組資料夾與路由。
5. ✅ GitHub Pages 部署（CI/CD）
6. ✅ OWASP 第二批：IDOR、Path Traversal、JWT、Brute Force（同樣 fork 子代理平行開發，主對話整合 + 瀏覽器 QA + 獨立審查）
