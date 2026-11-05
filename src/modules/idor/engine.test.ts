import { describe, expect, it } from 'vitest'
import { FLAG_ORDER, getOrder, MY_ID, USERS, updateEmail, type Mode } from './engine.ts'

const MODES: Mode[] = ['vulnerable', 'patched']

describe('getOrder：看訂單', () => {
  for (const m of MODES) {
    it(`${m}：自己的訂單 1002 看得到`, () => {
      const r = getOrder('1002', m)
      expect(r.status).toBe(200)
      expect(r.mine).toBe(true)
      expect(r.leaked).toBe(false)
      expect(r.order?.owner).toBe('alice')
    })
  }

  it('改成別人的編號 1001：漏洞版外洩 bob 的訂單，修補版回 404', () => {
    const v = getOrder('1001', 'vulnerable')
    expect(v.status).toBe(200)
    expect(v.leaked).toBe(true)
    expect(v.order?.owner).toBe('bob')

    const p = getOrder('1001', 'patched')
    expect(p.status).toBe(404)
    expect(p.blocked).toBe(true)
    expect(p.order).toBeUndefined()
  })

  it('挑戰 1 解答 1000：漏洞版拿到 FLAG，修補版沒有', () => {
    expect(getOrder('1000', 'vulnerable').order?.note).toContain(FLAG_ORDER)
    expect(getOrder('1000', 'patched').order).toBeUndefined()
  })

  it('不存在的編號：兩版都是 404，而且不算「被擋下」', () => {
    for (const m of MODES) {
      const r = getOrder('9999', m)
      expect(r.status).toBe(404)
      expect(r.blocked).toBe(false)
    }
  })

  it('編號不是數字：參數化查詢查不到 → 404', () => {
    for (const id of ['abc', '1002 OR 1=1', '']) expect(getOrder(id, 'vulnerable').status).toBe(404)
  })
})

describe('updateEmail：改 Email', () => {
  const bobEmail = () => USERS.find((u) => u.username === 'bob')?.email

  it('挑戰 2 解答：漏洞版把 bob（3 號）的 Email 改掉，而且不改動原陣列', () => {
    const r = updateEmail(USERS, '3', 'attacker@evil.test', 'vulnerable')
    expect(r.status).toBe(200)
    expect(r.takeover).toBe(true)
    expect(r.users.find((u) => u.id === 3)?.email).toBe('attacker@evil.test')
    expect(bobEmail()).toBe('bob@example.test')
  })

  it('修補版：改別人回 403，會員表不變', () => {
    const r = updateEmail(USERS, '3', 'attacker@evil.test', 'patched')
    expect(r.status).toBe(403)
    expect(r.users).toBe(USERS)
  })

  it('修補版：不存在的編號也回 403，不透露它存不存在', () => {
    expect(updateEmail(USERS, '99', 'a@b.test', 'patched').status).toBe(403)
    expect(updateEmail(USERS, '99', 'a@b.test', 'vulnerable').status).toBe(404)
  })

  for (const m of MODES) {
    it(`${m}：改自己的 Email 可以`, () => {
      const r = updateEmail(USERS, String(MY_ID), 'new@example.test', m)
      expect(r.status).toBe(200)
      expect(r.takeover).toBe(false)
    })
  }

  it('格式錯誤：400', () => {
    expect(updateEmail(USERS, 'x', 'a@b.test', 'vulnerable').status).toBe(400)
    expect(updateEmail(USERS, '3', 'not-an-email', 'vulnerable').status).toBe(400)
  })
})
