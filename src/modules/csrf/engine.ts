// CSRF 模擬引擎：瀏覽器「要不要帶 cookie」的規則 + 銀行伺服器。純 TS，不依賴 React。

export type SameSite = 'None' | 'Lax' | 'Strict'
export type Site = 'bank.demo' | 'evil.test'
/** form-post = 自動送出的隱藏表單；img-get = <img src>；link-navigation = 誘騙點連結（頂層導覽 GET） */
export type RequestKind = 'form-post' | 'img-get' | 'link-navigation'

export interface BankConfig { sameSite: SameSite; checkToken: boolean; acceptGet: boolean }
export const VULNERABLE: BankConfig = { sameSite: 'None', checkToken: false, acceptGet: false }
export const PATCHED: BankConfig = { sameSite: 'Lax', checkToken: true, acceptGet: false }

/** 假資料：一看就知道是假的 */
export const SESSION = 'demo-session-alice'
export const CSRF_TOKEN = 'demo-csrf-7f3a9c'
export const START_BALANCE = 50_000
export const ATTACKER = 'attacker'

export const setCookie = (sameSite: SameSite) => `Set-Cookie: session=${SESSION}; Secure; HttpOnly; SameSite=${sameSite}`

/** 攻擊者在 evil.test 上設計的攻擊 */
export interface Attack { kind: RequestKind; to: string; amount: string }

export interface BrowserRequest {
  initiator: Site
  kind: RequestKind
  method: 'GET' | 'POST'
  params: Record<string, string>
}

export function attackRequest(a: Attack): BrowserRequest {
  return { initiator: 'evil.test', kind: a.kind, method: a.kind === 'form-post' ? 'POST' : 'GET', params: { to: a.to, amount: a.amount } }
}

/** Alice 自己在 bank.demo 送出轉帳表單（表單裡有銀行塞的 token） */
export function aliceRequest(to: string, amount: string): BrowserRequest {
  return { initiator: 'bank.demo', kind: 'form-post', method: 'POST', params: { to, amount, csrf_token: CSRF_TOKEN } }
}

/** 瀏覽器決定這個請求要不要帶 bank.demo 的 cookie */
export function cookieDecision(sameSite: SameSite, req: BrowserRequest): { sent: boolean; reason: string } {
  if (req.initiator === 'bank.demo') return { sent: true, reason: '同一個網站自己發出的請求，cookie 一定會帶。' }
  if (sameSite === 'None') return { sent: true, reason: 'SameSite=None：不管是哪個網站發起的，瀏覽器都會帶上 cookie。' }
  if (sameSite === 'Strict') return { sent: false, reason: 'SameSite=Strict：只要是別的網站發起的請求，一律不帶 cookie。' }
  if (req.kind === 'link-navigation') return { sent: true, reason: 'SameSite=Lax：使用者點連結、整個分頁跳過去（頂層導覽的 GET），還是會帶 cookie。' }
  return { sent: false, reason: `SameSite=Lax：別的網站發起的${req.kind === 'form-post' ? ' POST 表單' : ' <img> 請求'}不帶 cookie。` }
}

export interface Header { name: string; value: string; /** 瀏覽器自動帶上的 cookie */ auto?: boolean }
export interface Check { ok: boolean; text: string }
export type BlockedBy = 'method' | 'samesite' | 'token' | 'input'

export interface Trace {
  initiator: Site
  /** 瀏覽器組出的 HTTP request */
  startLine: string
  headers: Header[]
  body?: string
  cookie: { sent: boolean; reason: string }
  /** 銀行一步一步的判斷 */
  checks: Check[]
  status: number
  transferred: boolean
  blockedBy?: BlockedBy
  to: string
  amount: number
  balanceAfter: number
}

const qs = (p: Record<string, string>) => new URLSearchParams(p).toString()

/** 每次都從起始餘額開始算，不累積：demo 可以一直重玩 */
export function simulate(req: BrowserRequest, cfg: BankConfig): Trace {
  const cookie = cookieDecision(cfg.sameSite, req)
  const query = qs(req.params)
  const headers: Header[] = [{ name: 'Host', value: 'bank.demo' }]
  // 跨站 POST 會帶 Origin；GET 的 <img> 與導覽只有 Referer（預設政策只送網域）
  if (req.method === 'POST') headers.push({ name: 'Origin', value: `https://${req.initiator}` })
  headers.push({ name: 'Referer', value: req.initiator === 'bank.demo' ? 'https://bank.demo/account' : 'https://evil.test/' })
  if (req.method === 'POST') headers.push({ name: 'Content-Type', value: 'application/x-www-form-urlencoded' })
  if (cookie.sent) headers.push({ name: 'Cookie', value: `session=${SESSION}`, auto: true })

  const to = req.params.to ?? ''
  const amount = Number(req.params.amount)
  const checks: Check[] = []
  const done = (status: number, blockedBy?: BlockedBy): Trace => ({
    initiator: req.initiator,
    startLine: `${req.method} /transfer${req.method === 'GET' ? `?${query}` : ''} HTTP/1.1`,
    headers,
    body: req.method === 'POST' ? query : undefined,
    cookie, checks, status, blockedBy, to, amount,
    transferred: status === 200,
    balanceAfter: status === 200 ? START_BALANCE - amount : START_BALANCE,
  })

  if (req.method === 'GET' && !cfg.acceptGet) {
    checks.push({ ok: false, text: '轉帳 API 只接受 POST，GET 一律拒絕（405）' })
    return done(405, 'method')
  }
  if (!cookie.sent) {
    checks.push({ ok: false, text: '沒收到 session cookie → 不知道你是誰，當作沒登入（401）' })
    return done(401, 'samesite')
  }
  checks.push({ ok: true, text: `cookie session=${SESSION} 正確 → 認定是 Alice 本人` })
  if (cfg.checkToken) {
    if (req.params.csrf_token !== CSRF_TOKEN) {
      checks.push({ ok: false, text: `${req.params.csrf_token ? 'csrf_token 不對' : '請求裡沒有 csrf_token'} → 拒絕（403）` })
      return done(403, 'token')
    }
    checks.push({ ok: true, text: 'csrf_token 正確 → 確定是從 bank.demo 自己的頁面送出' })
  }
  if (!to || !Number.isInteger(amount) || amount <= 0 || amount > START_BALANCE) {
    checks.push({ ok: false, text: '收款人空白，或金額不是 1 到餘額之間的整數（400）' })
    return done(400, 'input')
  }
  checks.push({ ok: true, text: `從 Alice 的帳戶轉 ${amount} 元給 ${to}` })
  return done(200)
}

// ---------- 攻擊者網頁的 HTML（只當文字顯示，不會 render） ----------

export interface HtmlLine { text: string; /** 這行會讓瀏覽器對 bank.demo 送出請求 */ danger: boolean }

const esc = (v: string) => v.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

export function attackerHtml(a: Attack): HtmlLine[] {
  // URLSearchParams 已經把引號、< 等字元編碼成 %22、%3C，網址不用再跳脫
  const url = `https://bank.demo/transfer?${qs({ to: a.to, amount: a.amount })}`
  const head: HtmlLine = { text: '<h1>🎁 恭喜！你抽中 iPhone！</h1>', danger: false }
  switch (a.kind) {
    case 'form-post':
      return [head,
        { text: '<form id="f" action="https://bank.demo/transfer" method="POST">', danger: true },
        { text: `  <input type="hidden" name="to" value="${esc(a.to)}">`, danger: true },
        { text: `  <input type="hidden" name="amount" value="${esc(a.amount)}">`, danger: true },
        { text: '</form>', danger: true },
        { text: "<script>document.getElementById('f').submit()</script>", danger: true }]
    case 'img-get':
      return [head, { text: `<img src="${url}" width="0" height="0">`, danger: true }]
    case 'link-navigation':
      return [head, { text: `<a href="${url}">👉 點我領獎</a>`, danger: true }]
  }
}
