# 🛡️ 資安攻擊互動圖解

用互動操作 + 圖像化，讓資安新手幾分鐘內看懂一種攻擊「為什麼會成功、要怎麼修」。

每個主題都是一個假網站：你親手輸入攻擊字串，畫面同步畫出伺服器內部發生的事，再切到修補版，看同一招為什麼失效。
**所有攻擊都在瀏覽器內模擬，不會連到任何真實系統。**

線上展示：<https://ray910408.github.io/1103homework/>

## 主題進度

| 主題 | 狀態 |
|---|---|
| SQL Injection（SQL 注入） | ✅ 完成 |
| XSS（跨站腳本攻擊） | 🚧 製作中 |
| SSRF（伺服器端請求偽造） | 🚧 製作中 |
| CSRF（跨站請求偽造） | 🚧 製作中 |
| Command Injection（命令注入） | 🚧 製作中 |

## 每個主題的 4 段結構

1. **情境**：一個假網站介面，說明攻擊者想做什麼
2. **動手攻擊 + 即時視覺化**：每打一個字，同步畫出伺服器內部發生的事
3. **漏洞版 ↔ 修補版對照**：同一個輸入，並排比較兩種程式碼與結果
4. **挑戰**：給一個目標讓你自己完成，提示分段給

以 SQL Injection 為例：在瀏覽器裡用 [sql.js](https://sql.js.org/)（SQLite WASM）跑真的 SQL 查詢，
用顏色標出你的輸入哪一段還是「資料」、哪一段跳出引號變成了「指令」。

## 本機執行

需要 Node.js 20 以上。

```bash
npm install
npm run dev        # 開發伺服器，預設 http://localhost:5173
npm test           # 執行模擬引擎的單元測試
npm run build      # 產生 dist/ 靜態網站
npm run preview    # 預覽 build 結果
```

## 技術棧

- [Vite](https://vite.dev/) + React + TypeScript
- [react-router](https://reactrouter.com/)（`HashRouter`，GitHub Pages 不支援 SPA fallback）
- [sql.js](https://sql.js.org/)：瀏覽器內的 SQLite
- [Vitest](https://vitest.dev/)：測試
- [oxlint](https://oxc.rs/)：lint

## 專案結構

```
src/
  App.tsx, Home.tsx      版型、首頁、路由
  topics.ts              主題清單
  components/ui.tsx      共用元件（段落、名詞解釋）
  styles/global.css      全站樣式與色彩語意變數
  modules/<topic>/
    index.tsx            模組頁面
    engine.ts            模擬邏輯（純 TS，不依賴 React）
    engine.test.ts       測試：經典 payload 在漏洞版成功、在修補版失敗
```

## 部署

CI/CD 由 GitHub Actions 執行（`.github/workflows/ci-cd.yml`）：

- **CI**：每次 push 到 `main` 或開 PR，都會跑 lint → test → build
- **CD**：push 到 `main` 且 CI 全部通過，自動部署到 GitHub Pages

repo 的 **Settings → Pages → Build and deployment → Source** 必須設為 **GitHub Actions**。

## 免責聲明

本專案僅供教學用途。所有攻擊都在瀏覽器沙箱內模擬，資料皆為假資料。
未經授權攻擊他人系統，觸犯《刑法》妨害電腦使用罪（第 358 條起）。
