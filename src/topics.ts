export interface Topic {
  id: string
  title: string
  zh: string
  summary: string
  ready: boolean
}

export const TOPICS: Topic[] = [
  { id: 'sqli', title: 'SQL Injection', zh: 'SQL 注入', ready: true,
    summary: '輸入一個單引號，就能讓資料庫把你的「資料」當成「指令」執行。' },
  { id: 'xss', title: 'XSS', zh: '跨站腳本攻擊', ready: true,
    summary: '把 JavaScript 藏進留言裡，讓別人的瀏覽器幫你執行。' },
  { id: 'ssrf', title: 'SSRF', zh: '伺服器端請求偽造', ready: true,
    summary: '騙伺服器幫你連進它自己的內網，拿到外人碰不到的資料。' },
  { id: 'csrf', title: 'CSRF', zh: '跨站請求偽造', ready: true,
    summary: '讓已登入的使用者在不知情的情況下，幫你送出轉帳請求。' },
  { id: 'cmdi', title: 'Command Injection', zh: '命令注入', ready: false,
    summary: '在「輸入 IP」的欄位多打一個分號，就能在伺服器上執行任意指令。' },
]
