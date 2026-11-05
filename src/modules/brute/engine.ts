// Brute Force 模擬引擎：純函式，不依賴 React。時間全部是「模擬時鐘」（毫秒），不用真的計時器。

export const MINUTE = 60_000
export const HOUR = 60 * MINUTE
/** 攻擊腳本每送一次登入請求，模擬時鐘前進 0.2 秒 */
export const ATTEMPT_MS = 200

export const FLAG = 'FLAG{br00t3_f0rc3_n0_r4t3_l1m1t}'

export interface User { username: string; password: string; role: string; secret: string }

export const USERS: User[] = [
  { username: 'admin', password: 'sunshine', role: 'admin', secret: FLAG },
  { username: 'alice', password: 'Purple-Tiger-42', role: 'user', secret: '' },
]

/** 教科書等級的「最常見密碼」清單（排行榜常客） */
export const WORDLIST = [
  '123456', 'password', '123456789', '12345678', 'qwerty', 'abc123', '111111', '1234567', 'iloveyou',
  'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'sunshine', 'princess', 'football', '000000',
]

/** maxFails 次失敗 → 鎖 lockMinutes 分鐘；maxFails = Infinity 代表不限次數 */
export interface Policy { maxFails: number; lockMinutes: number }
export const VULNERABLE: Policy = { maxFails: Infinity, lockMinutes: 0 }
export const PATCHED: Policy = { maxFails: 5, lockMinutes: 15 }

export type Reply =
  | { kind: 'ok'; user: User }
  /** lockedUntil 有值 = 這次失敗剛好觸發鎖定 */
  | { kind: 'fail'; lockedUntil?: number }
  /** 帳號鎖定中：連密碼都不檢查 */
  | { kind: 'locked'; until: number }

/** 建立一台登入伺服器；每個帳號各自記失敗次數（per-account lockout） */
export function createServer(policy: Policy) {
  const accounts = new Map<string, { fails: number; lockedUntil: number }>()
  return function login(username: string, password: string, t: number): Reply {
    let a = accounts.get(username)
    if (!a) accounts.set(username, (a = { fails: 0, lockedUntil: 0 }))
    if (t < a.lockedUntil) return { kind: 'locked', until: a.lockedUntil }
    const user = USERS.find((u) => u.username === username && u.password === password)
    if (user) { a.fails = 0; return { kind: 'ok', user } }
    if (++a.fails >= policy.maxFails && policy.lockMinutes > 0) {
      a.fails = 0
      a.lockedUntil = t + policy.lockMinutes * MINUTE
      return { kind: 'fail', lockedUntil: a.lockedUntil }
    }
    return { kind: 'fail' }
  }
}

export interface Attempt { no: number; password: string; t: number; reply: Reply; /** 這組其實是正確密碼 */ correct: boolean }

export interface AttackResult {
  username: string
  attempts: Attempt[]
  cracked: boolean
  elapsedMs: number
  /** 第幾次嘗試觸發了第一次鎖定 */
  lockedAt?: number
  /** 正確密碼送出時帳號正在鎖定，被拒絕了 */
  blockedCorrect: boolean
}

/**
 * 攻擊腳本：照順序把字典裡的密碼一個一個送出去，猜中就停。
 * patient = false：一路狂送，被鎖了也照送（那一組就浪費掉）
 * patient = true ：被鎖就等到解鎖再送同一組；超過 budgetMs 就放棄
 */
export function runAttack(username: string, words: string[], policy: Policy,
  { patient = false, budgetMs = Infinity }: { patient?: boolean; budgetMs?: number } = {}): AttackResult {
  const login = createServer(policy)
  const real = USERS.find((u) => u.username === username)?.password
  const attempts: Attempt[] = []
  let t = 0
  for (const password of words) {
    let reply = login(username, password, t)
    if (reply.kind === 'locked' && patient) {
      t = reply.until
      reply = login(username, password, t)
    }
    if (t > budgetMs) break
    attempts.push({ no: attempts.length + 1, password, t, reply, correct: password === real })
    if (reply.kind === 'ok') break
    t += ATTEMPT_MS
  }
  const last = attempts.at(-1)
  return {
    username,
    attempts,
    cracked: last?.reply.kind === 'ok',
    elapsedMs: last?.t ?? 0,
    lockedAt: attempts.find((a) => a.reply.kind === 'fail' && a.reply.lockedUntil)?.no,
    blockedCorrect: attempts.some((a) => a.correct && a.reply.kind === 'locked'),
  }
}

/** 有耐心的攻擊者（被鎖就等）試完 n 組都猜錯的密碼，總共要多久 */
export function estimateMs(policy: Policy, n = 10_000) {
  return runAttack('nobody', Array.from({ length: n }, (_, i) => `guess-${i}`), policy, { patient: true }).elapsedMs
}

/** 真正的使用者 alice：打錯 2 次、第 3 次打對，每次間隔 5 秒 */
export const ALICE_TRIES = ['purple-tiger-42', 'Purple-Tiger-24', 'Purple-Tiger-42']

export function legitLogin(policy: Policy) {
  const login = createServer(policy)
  const replies = ALICE_TRIES.map((p, i) => login('alice', p, i * 5000))
  return { replies, ok: replies.at(-1)?.kind === 'ok' }
}

/** 挑戰 2：有耐心的攻擊腳本 1 小時內猜不到 admin，而且 alice 還登得進去 */
export function defenseHolds(policy: Policy) {
  const attack = runAttack('admin', WORDLIST, policy, { patient: true, budgetMs: HOUR })
  const alice = legitLogin(policy)
  return { attack, alice, ok: !attack.cracked && alice.ok }
}

// ---------- 顯示用的格式化 ----------

/** 模擬時鐘：m:ss.s */
export function fmtClock(ms: number) {
  const m = Math.floor(ms / MINUTE)
  const s = (ms % MINUTE) / 1000
  return `${String(m).padStart(2, '0')}:${s.toFixed(1).padStart(4, '0')}`
}

export function fmtDuration(ms: number) {
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)} 秒`
  if (s < 3600) return `${(s / 60).toFixed(1)} 分鐘`
  if (s < 86400) return `${(s / 3600).toFixed(1)} 小時`
  return `${(s / 86400).toFixed(1)} 天`
}
