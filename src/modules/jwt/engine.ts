/**
 * JWT 驗證模擬：三台伺服器用三種方式檢查同一個 token。
 * 純 TS，不依賴 React。簽章用瀏覽器 / Node 內建的 Web Crypto（HMAC-SHA256），所以 verify 是 async。
 */

/** 只存在「伺服器」裡的密鑰（教學用假值） */
export const SECRET = 'demo-secret-key'
export const FLAG = 'FLAG{jwt_p4yl04d_1s_n0t_s3cr3t}'

/**
 * decodeOnly = 漏洞 A：只 decode，不驗簽章
 * trustAlg   = 漏洞 B：用哪個演算法驗，由 token header 的 alg 決定（alg: none 就不驗）
 * patched    = 修補版：演算法由伺服器寫死 HS256，驗簽章、檢查 exp
 */
export type Mode = 'decodeOnly' | 'trustAlg' | 'patched'

export const GUEST_HEADER = { alg: 'HS256', typ: 'JWT' }
/** exp 4102444800 = 2100-01-01，示範用的「還沒過期」 */
export const GUEST_PAYLOAD = { sub: 'guest', role: 'user', exp: 4102444800 }
/** 伺服器登入時發給 guest 的原始 token（engine.test.ts 會驗證它真的是用 SECRET 簽的） */
export const GUEST_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOiJ1c2VyIiwiZXhwIjo0MTAyNDQ0ODAwfQ.-0sEWuhqBBTptB_quSdqUljLQhBRb_y8lgsLAQy5yZU'

// ---------- base64url ----------

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** 文字 → base64url（UTF-8，中文也可以） */
export function b64urlEncode(text: string): string {
  return bytesToB64url(new TextEncoder().encode(text))
}

/** base64url → 文字；格式不對回傳 undefined */
export function b64urlDecode(part: string): string | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(part) || part.length % 4 === 1) return undefined
  try {
    const bin = atob(part.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part.length / 4) * 4, '='))
    return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))
  } catch {
    return undefined
  }
}

// ---------- 簽章 ----------

/** HMAC-SHA256(data, secret)，輸出 base64url */
export async function hmacSign(data: string, secret = SECRET): Promise<string> {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return bytesToB64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data))))
}

/** 伺服器的「發 token」：用 SECRET 簽一張 HS256 token */
export async function sign(header: object, payload: object, secret = SECRET): Promise<string> {
  const body = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`
  return `${body}.${await hmacSign(body, secret)}`
}

/** 編輯器裡的 JSON（可能有換行縮排）壓成一行再編碼；不是合法 JSON 就照原文編碼 */
function compact(text: string): string {
  try { return JSON.stringify(JSON.parse(text)) } catch { return text }
}

/** 攻擊者的編輯器：header / payload JSON + 簽章 → token 字串 */
export function buildToken(header: string, payload: string, sig: string): string {
  return `${b64urlEncode(compact(header))}.${b64urlEncode(compact(payload))}.${sig.trim()}`
}

// ---------- 驗證 ----------

export type StepId = 'decode' | 'alg' | 'hmac' | 'compare' | 'exp' | 'role'
export const STEP_ORDER: StepId[] = ['decode', 'alg', 'hmac', 'compare', 'exp', 'role']

/** pass = 檢查通過、fail = 擋下、unsafe = 該檢查卻沒檢查 / 相信了 token、idle = 沒執行到 */
export type StepStatus = 'pass' | 'fail' | 'unsafe' | 'idle'
export interface Step { id: StepId; status: StepStatus; text: string }

export interface VerifyResult {
  /** 伺服器接受了這個 token */
  accepted: boolean
  /** 接受了，而且 role 是 admin → /admin 開門 */
  admin: boolean
  sub?: string
  role?: string
  alg?: string
  steps: Step[]
  /** token 帶的簽章跟伺服器用 SECRET 重算的一不一致（不論這台伺服器有沒有檢查） */
  sigMatch: boolean
  /** 伺服器重算出的正確簽章（UI 只能露出前幾碼，不然就能拿來偽造） */
  expected: string
}

const isObject = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x)

/** 拆三段、base64url 解碼、JSON 解析；失敗回傳錯誤訊息 */
function decode(parts: string[]): { header: Record<string, unknown>; payload: Record<string, unknown> } | string {
  if (parts.length !== 3) return `要有 3 段（用 . 分開），這個有 ${parts.length} 段`
  try {
    const header: unknown = JSON.parse(b64urlDecode(parts[0]) ?? '')
    const payload: unknown = JSON.parse(b64urlDecode(parts[1]) ?? '')
    if (!isObject(header) || !isObject(payload)) return 'header / payload 要是 JSON 物件'
    return { header, payload }
  } catch {
    return 'base64url 或 JSON 格式錯誤'
  }
}

export async function verify(token: string, mode: Mode, now = Date.now() / 1000): Promise<VerifyResult> {
  const steps: Step[] = []
  const parts = token.trim().split('.')
  const expected = parts.length === 3 ? await hmacSign(`${parts[0]}.${parts[1]}`) : ''
  // 教學用直接 ===；真實程式請用 JWT 函式庫的 verify，或 constant-time 比對（crypto.timingSafeEqual）
  const base = { sigMatch: parts.length === 3 && parts[2] === expected, expected }

  const finish = (accepted: boolean, extra: Partial<VerifyResult> = {}): VerifyResult => {
    for (const id of STEP_ORDER.slice(steps.length)) steps.push({ id, status: 'idle', text: '沒執行到' })
    return { ...base, ...extra, accepted, admin: accepted && extra.role === 'admin', steps }
  }

  // ① 拆開、解碼
  const d = decode(parts)
  if (typeof d === 'string') {
    steps.push({ id: 'decode', status: 'fail', text: d })
    return finish(false)
  }
  const { header, payload } = d
  // 只認字串：["admin"] 這種陣列不能被當成 'admin'（跟頁面上程式碼的 === 一致）
  const str = (x: unknown) => (typeof x === 'string' ? x : '')
  const claims = { sub: str(payload.sub), role: str(payload.role), alg: str(header.alg) }
  // 使用者可控的字串放進圖裡要截短，免得蓋到標題
  const cut = (x: string) => (x.length > 14 ? `${x.slice(0, 14)}…` : x)
  steps.push({ id: 'decode', status: 'pass', text: `解碼成功：sub = ${cut(claims.sub)}` })

  const fail = (id: StepId, text: string) => {
    steps.push({ id, status: 'fail', text })
    return finish(false, claims)
  }
  // ③④ 用 SECRET 重算簽章、比對
  const checkSig = () => {
    steps.push({ id: 'hmac', status: 'pass', text: `算出 ${expected.slice(0, 6)}…` })
    if (!base.sigMatch) return fail('compare', '簽章不符 → 拒絕')
    steps.push({ id: 'compare', status: 'pass', text: '簽章一致' })
  }
  // ⑤ 到期時間
  const checkExp = () => {
    if (payload.exp === undefined) return fail('exp', 'token 沒有 exp（到期時間）')
    if (typeof payload.exp !== 'number') return fail('exp', 'exp 必須是數字')
    // RFC 7519：現在時間 >= exp 就算過期
    if (payload.exp <= now) return fail('exp', 'token 已經過期')
    steps.push({ id: 'exp', status: 'pass', text: '還沒過期' })
  }

  if (mode === 'decodeOnly') {
    steps.push(
      { id: 'alg', status: 'unsafe', text: '沒看（只 decode）' },
      { id: 'hmac', status: 'unsafe', text: '沒算' },
      { id: 'compare', status: 'unsafe', text: '沒比對：payload 寫什麼就信什麼' },
      { id: 'exp', status: 'unsafe', text: '沒檢查' },
    )
  } else if (mode === 'trustAlg') {
    // ⚠️ 漏洞：由 token 自己決定要不要驗
    if (claims.alg === 'none') {
      steps.push(
        { id: 'alg', status: 'unsafe', text: 'token 說 none，就照做' },
        { id: 'hmac', status: 'unsafe', text: 'alg 是 none → 不算' },
        { id: 'compare', status: 'unsafe', text: 'alg 是 none → 跳過' },
        // 走的是 jwt.decode，跟漏洞 A 一樣不看 exp
        { id: 'exp', status: 'unsafe', text: '沒檢查（decode 不看 exp）' },
      )
    } else if (claims.alg === 'HS256') {
      steps.push({ id: 'alg', status: 'pass', text: 'token 說 HS256，就用 HS256' })
      const r = checkSig() ?? checkExp()
      if (r) return r
    } else {
      return fail('alg', `不支援的演算法「${cut(claims.alg)}」`)
    }
  } else {
    // 修補版：演算法是伺服器決定的，不看 token 的臉色
    if (claims.alg !== 'HS256') return fail('alg', `只接受 HS256，token 寫 ${cut(claims.alg) || '（空）'} → 拒絕`)
    steps.push({ id: 'alg', status: 'pass', text: '伺服器指定 HS256' })
    const r = checkSig() ?? checkExp()
    if (r) return r
  }

  steps.push({ id: 'role', status: 'pass', text: claims.role === 'admin' ? 'role = admin → 開門' : `role = ${cut(claims.role) || '（空）'} → 不給進` })
  return finish(true, claims)
}
