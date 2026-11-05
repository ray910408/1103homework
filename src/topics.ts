export interface Topic {
  id: string
  title: string
  zh: string
  /** OWASP Top 10:2025 分類 */
  owasp: string
  summary: string
  ready: boolean
}

export const TOPICS: Topic[] = [
  { id: 'sqli', title: 'SQL Injection', zh: 'SQL 注入', owasp: 'A05 Injection', ready: true,
    summary: '輸入一個單引號，就能讓資料庫把你的「資料」當成「指令」執行。' },
  { id: 'xss', title: 'XSS', zh: '跨站腳本攻擊', owasp: 'A05 Injection', ready: true,
    summary: '把 JavaScript 藏進留言裡，讓別人的瀏覽器幫你執行。' },
  { id: 'ssrf', title: 'SSRF', zh: '伺服器端請求偽造', owasp: 'A01 Broken Access Control', ready: true,
    summary: '騙伺服器幫你連進它自己的內網，拿到外人碰不到的資料。' },
  { id: 'csrf', title: 'CSRF', zh: '跨站請求偽造', owasp: 'A01 Broken Access Control', ready: true,
    summary: '讓已登入的使用者在不知情的情況下，幫你送出轉帳請求。' },
  { id: 'idor', title: 'IDOR', zh: '不安全的直接物件參考', owasp: 'A01 Broken Access Control', ready: true,
    summary: '把網址裡的訂單編號加 1，就看到別人的姓名、地址和電話。' },
  { id: 'path', title: 'Path Traversal', zh: '路徑穿越', owasp: 'A01 Broken Access Control', ready: true,
    summary: '在檔名前面加幾個 ../，就能下載伺服器上不該公開的檔案。' },
  { id: 'jwt', title: 'JWT', zh: 'JWT 竄改', owasp: 'A04 Cryptographic Failures', ready: true,
    summary: '把 token 裡的 role 改成 admin；伺服器不驗簽章，你就是管理員。' },
  { id: 'brute', title: 'Brute Force', zh: '暴力破解', owasp: 'A07 Authentication Failures', ready: true,
    summary: '登入沒有次數限制，拿常見密碼清單一個一個試，總會試中。' },
  { id: 'cmdi', title: 'Command Injection', zh: '命令注入', owasp: 'A05 Injection', ready: true,
    summary: '在「輸入 IP」的欄位多打一個分號，就能在伺服器上執行任意指令。' },
]
