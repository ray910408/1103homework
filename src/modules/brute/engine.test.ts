import { describe, expect, it } from 'vitest'
import {
  ATTEMPT_MS, FLAG, MINUTE, PATCHED, VULNERABLE, WORDLIST,
  createServer, defenseHolds, estimateMs, fmtClock, legitLogin, runAttack,
} from './engine.ts'

describe('字典攻擊 admin', () => {
  it('漏洞版：第 15 次猜中 sunshine，拿到 FLAG', () => {
    const r = runAttack('admin', WORDLIST, VULNERABLE)
    expect(r.cracked).toBe(true)
    const hit = r.attempts.at(-1)!
    expect(hit.no).toBe(15)
    expect(hit.password).toBe('sunshine')
    expect(hit.reply.kind === 'ok' && hit.reply.user.secret).toBe(FLAG)
    expect(r.elapsedMs).toBe(14 * ATTEMPT_MS)
  })

  it('修補版：第 5 次失敗後鎖定，連正確密碼也被拒絕', () => {
    const r = runAttack('admin', WORDLIST, PATCHED)
    expect(r.cracked).toBe(false)
    expect(r.lockedAt).toBe(5)
    expect(r.blockedCorrect).toBe(true)
    expect(r.attempts).toHaveLength(WORDLIST.length)
    expect(r.attempts.slice(5).every((a) => a.reply.kind === 'locked')).toBe(true)
  })

  it('alice 的密碼不在字典裡：漏洞版也猜不到', () => {
    expect(runAttack('alice', WORDLIST, VULNERABLE).cracked).toBe(false)
  })
})

describe('登入伺服器', () => {
  it('鎖定期間正確密碼被拒，解鎖後就能登入', () => {
    const login = createServer(PATCHED)
    for (let i = 0; i < 5; i++) login('admin', 'wrong', i)
    expect(login('admin', 'sunshine', 10).kind).toBe('locked')
    expect(login('admin', 'sunshine', 4 + 15 * MINUTE).kind).toBe('ok')
  })

  it('真正的使用者打錯 2 次，修補版仍讓他登入；上限設 2 就被鎖在門外', () => {
    expect(legitLogin(VULNERABLE).ok).toBe(true)
    expect(legitLogin(PATCHED).ok).toBe(true)
    expect(legitLogin({ maxFails: 2, lockMinutes: 15 }).ok).toBe(false)
  })
})

describe('挑戰', () => {
  it('挑戰 1：admin / sunshine 在漏洞版登入成功', () => {
    const r = createServer(VULNERABLE)('admin', 'sunshine', 0)
    expect(r.kind === 'ok' && r.user.secret).toBe(FLAG)
  })

  it('挑戰 2：解答設定擋得住有耐心的攻擊者，也不擋 alice', () => {
    expect(defenseHolds({ maxFails: 5, lockMinutes: 30 }).ok).toBe(true)
    expect(defenseHolds({ maxFails: 3, lockMinutes: 15 }).ok).toBe(true)
  })

  it('挑戰 2：錯誤設定不算過關', () => {
    expect(defenseHolds(PATCHED).attack.cracked).toBe(true) // 5 次鎖 15 分鐘：等 30 分鐘就猜中
    expect(defenseHolds({ maxFails: 5, lockMinutes: 29 }).ok).toBe(false)
    expect(defenseHolds({ maxFails: 15, lockMinutes: 120 }).attack.cracked).toBe(true)
    expect(defenseHolds({ maxFails: 2, lockMinutes: 60 }).alice.ok).toBe(false)
    expect(defenseHolds({ maxFails: 5, lockMinutes: 0 }).ok).toBe(false)
  })
})

describe('試完 10,000 組要多久', () => {
  it('漏洞版約 33 分鐘，修補版超過 20 天', () => {
    expect(estimateMs(VULNERABLE)).toBe(9999 * ATTEMPT_MS)
    expect(estimateMs(PATCHED)).toBeGreaterThan(20 * 24 * 60 * MINUTE)
  })

  it('fmtClock', () => {
    expect(fmtClock(2800)).toBe('00:02.8')
    expect(fmtClock(15 * MINUTE + 800)).toBe('15:00.8')
  })
})
