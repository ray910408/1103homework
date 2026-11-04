import initSqlJs, { type SqlJsStatic } from 'sql.js'
import { beforeAll, describe, expect, it } from 'vitest'
import { analyze, login, SEED } from './engine.ts'

let SQL: SqlJsStatic
beforeAll(async () => { SQL = await initSqlJs() })

const ADMIN_PW = SEED[0].password
const UNION = "' UNION SELECT 1, password, role FROM users WHERE username = 'admin' --"

describe('login', () => {
  it('正常帳密：兩個版本都能登入', () => {
    expect(login(SQL, 'alice', 'alice123', 'vulnerable').user?.username).toBe('alice')
    expect(login(SQL, 'alice', 'alice123', 'patched').user?.username).toBe('alice')
  })

  it('密碼錯：兩個版本都登入失敗', () => {
    expect(login(SQL, 'alice', 'wrong', 'vulnerable').user).toBeUndefined()
    expect(login(SQL, 'alice', 'wrong', 'patched').user).toBeUndefined()
  })

  const attacks: [string, string, string, (r: ReturnType<typeof login>) => boolean][] = [
    ['註解掉密碼檢查', "bob' --", 'x', (r) => r.user?.username === 'bob'],
    ["OR '1'='1' 讓條件永遠成立", "' OR '1'='1' --", '', (r) => r.user?.username === 'admin'],
    ['密碼欄位也能注入', 'alice', "' OR '1'='1", (r) => r.rows.length === SEED.length],
    ['UNION 撈出 admin 密碼', UNION, '', (r) => r.user?.username === ADMIN_PW],
  ]
  for (const [name, u, p, success] of attacks) {
    it(`${name}：漏洞版成功、修補版失敗`, () => {
      expect(success(login(SQL, u, p, 'vulnerable'))).toBe(true)
      const patched = login(SQL, u, p, 'patched')
      expect(success(patched)).toBe(false)
      expect(patched.user).toBeUndefined()
    })
  }

  it('單引號讓漏洞版 SQL 語法錯誤，修補版沒事', () => {
    expect(login(SQL, "'", '', 'vulnerable').error).toBeTruthy()
    expect(login(SQL, "'", '', 'patched').error).toBeUndefined()
  })

  it('DROP TABLE 只影響當次查詢，下一次資料庫還在', () => {
    login(SQL, "'; DROP TABLE users; --", '', 'vulnerable')
    expect(login(SQL, 'alice', 'alice123', 'vulnerable').user?.username).toBe('alice')
  })
})

describe('analyze', () => {
  it('正常輸入：全部都是資料，沒有注入', () => {
    const a = analyze('alice', 'alice123')
    expect(a.segments.some((s) => s.kind === 'injected')).toBe(false)
    expect(a.segments.filter((s) => s.kind === 'data').map((s) => s.text)).toEqual(['alice', 'alice123'])
  })

  it("admin' --：引號與 -- 被標成注入，密碼檢查被註解掉", () => {
    const a = analyze("admin' --", 'x')
    // 相鄰的注入字元會合併成同一段
    expect(a.segments.filter((s) => s.kind === 'injected').map((s) => s.text)).toEqual(["' --"])
    expect(a.commentedCode).toContain('password')
    expect(a.injectedWords).toContain('--')
  })

  it('抓得到注入的關鍵字', () => {
    expect(analyze("' OR '1'='1' --", '').injectedWords).toContain('OR')
    expect(analyze(UNION, '').injectedWords).toContain('UNION')
  })

  it("用 '' 跳脫的單引號仍然是資料", () => {
    const a = analyze("it''s", '')
    expect(a.segments.some((s) => s.kind === 'injected')).toBe(false)
  })
})

describe('analyze：單引號', () => {
  it('只打一個 \'：它跟程式的引號湊成一對，算注入', () => {
    expect(analyze("'", '').segments.some((s) => s.kind === 'injected' && s.text === "'")).toBe(true)
  })
})
