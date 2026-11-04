// SQL Injection 模擬引擎：純 TS，不依賴 React，方便測試。
import type { Database, SqlJsStatic, SqlValue } from 'sql.js'
import type { SegKind, Segment } from '../../components/ui.tsx'

export interface User { id: number; username: string; password: string; role: string }

/** 假資料：一看就知道是假的 */
export const SEED: User[] = [
  { id: 1, username: 'admin', password: 'FLAG{un10n_s3l3ct_l34k3d_m3}', role: 'admin' },
  { id: 2, username: 'alice', password: 'alice123', role: 'user' },
  { id: 3, username: 'bob', password: 'bob-demo-pw', role: 'user' },
]

export type Mode = 'vulnerable' | 'patched'

export const PATCHED_SQL = 'SELECT id, username, role FROM users WHERE username = ? AND password = ?'

const PARTS = ["SELECT id, username, role FROM users WHERE username = '", "' AND password = '", "'"]

/** 漏洞版：直接把輸入黏進 SQL 字串 */
export function vulnerableSql(username: string, password: string): string {
  return PARTS[0] + username + PARTS[1] + password + PARTS[2]
}

/** 每次查詢都用全新的資料庫：DROP TABLE 之類的攻擊不會弄壞下一次 demo */
export function createDb(SQL: SqlJsStatic): Database {
  const db = new SQL.Database()
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
  for (const u of SEED) db.run('INSERT INTO users VALUES (?, ?, ?, ?)', [u.id, u.username, u.password, u.role])
  return db
}

export interface LoginResult {
  sql: string
  rows: SqlValue[][]
  error?: string
  /** 登入成功時，網頁顯示的身分（取查詢結果第一列） */
  user?: { id: string; username: string; role: string }
}

export function login(SQL: SqlJsStatic, username: string, password: string, mode: Mode): LoginResult {
  const db = createDb(SQL)
  try {
    let sql: string
    let rows: SqlValue[][] = []
    if (mode === 'vulnerable') {
      sql = vulnerableSql(username, password)
      try {
        rows = db.exec(sql)[0]?.values ?? []
      } catch (e) {
        return { sql, rows: [], error: (e as Error).message }
      }
    } else {
      sql = PATCHED_SQL
      const stmt = db.prepare(PATCHED_SQL)
      stmt.bind([username, password])
      while (stmt.step()) rows.push(stmt.get())
      stmt.free()
    }
    const r = rows[0]
    return { sql, rows, user: r && { id: String(r[0]), username: String(r[1]), role: String(r[2]) } }
  } finally {
    db.close()
  }
}

// ---------- 視覺化：標出每個字元在 SQL 裡扮演的角色 ----------


interface Tok {
  kind: 'string' | 'comment' | 'word' | 'other'
  start: number
  end: number
  closed?: boolean
  /** 字串裡每組 '' 跳脫的第一個字元位置 */
  escapes?: number[]
}

/** 極簡 SQL lexer：只分得出字串、註解、單字、其他符號，夠用來教學 */
function lex(sql: string): Tok[] {
  const toks: Tok[] = []
  let i = 0
  while (i < sql.length) {
    const start = i
    if (sql[i] === "'") {
      let closed = false
      const escapes: number[] = []
      i++
      while (i < sql.length) {
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") { escapes.push(i); i += 2; continue } // '' 是跳脫後的單引號
          i++; closed = true; break
        }
        i++
      }
      toks.push({ kind: 'string', start, end: i, closed, escapes })
    } else if (sql.startsWith('--', i)) {
      const nl = sql.indexOf('\n', i)
      i = nl === -1 ? sql.length : nl
      toks.push({ kind: 'comment', start, end: i })
    } else if (sql.startsWith('/*', i)) {
      const e = sql.indexOf('*/', i + 2)
      i = e === -1 ? sql.length : e + 2
      toks.push({ kind: 'comment', start, end: i })
    } else if (/[A-Za-z_]/.test(sql[i])) {
      while (i < sql.length && /\w/.test(sql[i])) i++
      toks.push({ kind: 'word', start, end: i })
    } else {
      i++
      toks.push({ kind: 'other', start, end: i })
    }
  }
  return toks
}

export interface Analysis {
  segments: Segment[]
  /** 跳出引號、變成指令的單字或符號（大寫），例如 OR、UNION、-- */
  injectedWords: string[]
  /** 被註解掉的原始程式碼 */
  commentedCode: string
}

export function analyze(username: string, password: string): Analysis {
  const sql = vulnerableSql(username, password)
  const fromInput: boolean[] = []
  for (const [text, isInput] of [[PARTS[0], false], [username, true], [PARTS[1], false], [password, true], [PARTS[2], false]] as const) {
    for (let k = 0; k < text.length; k++) fromInput.push(isInput)
  }

  const kinds: SegKind[] = []
  const injectedWords: string[] = []
  let commentedCode = ''

  for (const t of lex(sql)) {
    for (let i = t.start; i < t.end; i++) {
      const input = fromInput[i]
      let kind: SegKind
      if (t.kind === 'comment') {
        kind = input && i < t.start + 2 ? 'injected' : 'comment'
        if (!input) commentedCode += sql[i]
      } else if (!input) {
        kind = 'code'
      } else if (t.kind === 'string') {
        // 引號本身如果是你打的，代表你把字串「關掉」了
        const delimiter = i === t.start || (t.closed && i === t.end - 1)
        if (delimiter) kind = 'injected'
        else if (sql[i] === "'") {
          // 只有兩個引號都是你打的 ''，才是乖乖跳脫的資料；
          // 你的 ' 跟程式的 ' 湊成一對，代表你提早把字串關掉了
          const first = t.escapes!.includes(i) ? i : i - 1
          kind = fromInput[first] && fromInput[first + 1] ? 'data' : 'injected'
        } else kind = 'data'
      } else {
        kind = 'injected'
      }
      kinds.push(kind)
    }
    const word = sql.slice(t.start, t.end)
    if (t.kind === 'comment' && fromInput[t.start]) injectedWords.push(word.slice(0, 2))
    if ((t.kind === 'word' || t.kind === 'other') && fromInput.slice(t.start, t.end).every(Boolean) && word.trim()) {
      injectedWords.push(word.toUpperCase())
    }
  }

  const segments: Segment[] = []
  for (let i = 0; i < sql.length; i++) {
    const last = segments[segments.length - 1]
    if (last && last.kind === kinds[i]) last.text += sql[i]
    else segments.push({ text: sql[i], kind: kinds[i] })
  }
  return { segments, injectedWords, commentedCode: commentedCode.trim() }
}
