export type Level = 1 | 2 | 3
export const LEVEL_LABEL: Record<Level, string> = { 1: "低", 2: "中", 3: "高" }

export interface Topic {
  id: string
  title: string
  zh: string
  /** OWASP Top 10:2025 分類 */
  owasp: string
  /** 難度：1 低、2 中、3 高 */
  level: Level
  summary: string
  ready: boolean
}

export const TOPICS: Topic[] = [
  { id: 'sqli', level: 1, title: 'SQL Injection', zh: 'SQL 注入', owasp: 'A05 Injection', ready: true,
    summary: '輸入一個單引號，就能讓資料庫把你的「資料」當成「指令」執行。' },
  { id: 'xss', level: 2, title: 'XSS', zh: '跨站腳本攻擊', owasp: 'A05 Injection', ready: true,
    summary: '把 JavaScript 藏進留言裡，讓別人的瀏覽器幫你執行。' },
  { id: 'ssrf', level: 3, title: 'SSRF', zh: '伺服器端請求偽造', owasp: 'A01 Broken Access Control', ready: true,
    summary: '騙伺服器幫你連進它自己的內網，拿到外人碰不到的資料。' },
  { id: 'csrf', level: 2, title: 'CSRF', zh: '跨站請求偽造', owasp: 'A01 Broken Access Control', ready: true,
    summary: '讓已登入的使用者在不知情的情況下，幫你送出轉帳請求。' },
  { id: 'idor', level: 1, title: 'IDOR', zh: '不安全的直接物件參考', owasp: 'A01 Broken Access Control', ready: true,
    summary: '把網址裡的訂單編號加 1，就看到別人的姓名、地址和電話。' },
  { id: 'path', level: 1, title: 'Path Traversal', zh: '路徑穿越', owasp: 'A01 Broken Access Control', ready: true,
    summary: '在檔名前面加幾個 ../，就能下載伺服器上不該公開的檔案。' },
  { id: 'jwt', level: 3, title: 'JWT', zh: 'JWT 竄改', owasp: 'A04 Cryptographic Failures', ready: true,
    summary: '把 token 裡的 role 改成 admin；伺服器不驗簽章，你就是管理員。' },
  { id: 'brute', level: 1, title: 'Brute Force', zh: '暴力破解', owasp: 'A07 Authentication Failures', ready: true,
    summary: '登入沒有次數限制，拿常見密碼清單一個一個試，總會試中。' },
  { id: 'cmdi', level: 2, title: 'Command Injection', zh: '命令注入', owasp: 'A05 Injection', ready: true,
    summary: '在「輸入 IP」的欄位多打一個分號，就能在伺服器上執行任意指令。' },
]
