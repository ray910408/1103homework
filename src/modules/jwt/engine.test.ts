import { describe, expect, it } from 'vitest'
import {
  b64urlDecode, b64urlEncode, buildToken, GUEST_HEADER, GUEST_PAYLOAD, GUEST_TOKEN, sign, verify, type Mode, type VerifyResult,
} from './engine.ts'

const MODES: Mode[] = ['decodeOnly', 'trustAlg', 'patched']
const sigOf = (t: string) => t.split('.')[2]
const json = (o: object) => JSON.stringify(o, null, 2)
const failText = (r: VerifyResult) => r.steps.find((s) => s.status === 'fail')

/** 攻擊者改 payload：role → admin，簽章照抄原本的 */
const tampered = buildToken(json(GUEST_HEADER), json({ ...GUEST_PAYLOAD, role: 'admin' }), sigOf(GUEST_TOKEN))
/** alg: none + 刪掉簽章 */
const algNone = buildToken(json({ alg: 'none', typ: 'JWT' }), json({ ...GUEST_PAYLOAD, role: 'admin' }), '')

describe('base64url', () => {
  it('UTF-8 來回不變、不含 + / =', () => {
    const text = '{"name":"小明 ✓","x":"??>>"}'
    const enc = b64urlEncode(text)
    expect(enc).not.toMatch(/[+/=]/)
    expect(b64urlDecode(enc)).toBe(text)
  })
  it('非法字元回傳 undefined', () => {
    expect(b64urlDecode('ab$c')).toBeUndefined()
  })
})

describe('原本的 guest token', () => {
  it('GUEST_TOKEN 真的是用密鑰簽的', async () => {
    expect(await sign(GUEST_HEADER, GUEST_PAYLOAD)).toBe(GUEST_TOKEN)
  })
  it('編輯器把縮排過的 JSON 壓回原樣，簽章仍然一致', () => {
    expect(buildToken(json(GUEST_HEADER), json(GUEST_PAYLOAD), sigOf(GUEST_TOKEN))).toBe(GUEST_TOKEN)
  })
  for (const m of MODES) {
    it(`${m}：接受，身分是 user，不是 admin`, async () => {
      const r = await verify(GUEST_TOKEN, m)
      expect(r.accepted).toBe(true)
      expect(r.admin).toBe(false)
      expect(r.role).toBe('user')
    })
  }
})

describe('改 payload（role → admin，簽章不動）', () => {
  it('漏洞 A（只 decode）：變成 admin', async () => {
    const r = await verify(tampered, 'decodeOnly')
    expect(r.admin).toBe(true)
    expect(r.sigMatch).toBe(false)
  })
  it('漏洞 B（信任 alg）：簽章不符被擋', async () => {
    const r = await verify(tampered, 'trustAlg')
    expect(r.accepted).toBe(false)
    expect(r.steps.find((s) => s.status === 'fail')?.id).toBe('compare')
  })
  it('修補版：簽章不符被擋', async () => {
    const r = await verify(tampered, 'patched')
    expect(r.accepted).toBe(false)
    expect(r.steps.find((s) => s.status === 'fail')?.id).toBe('compare')
  })
})

describe('alg: none', () => {
  it('漏洞 A：變成 admin', async () => {
    expect((await verify(algNone, 'decodeOnly')).admin).toBe(true)
  })
  it('漏洞 B：跳過驗證，變成 admin', async () => {
    const r = await verify(algNone, 'trustAlg')
    expect(r.admin).toBe(true)
    expect(r.steps.find((s) => s.id === 'compare')?.status).toBe('unsafe')
  })
  it('漏洞 B：none 走 decode，連 exp 都不看（沒有 exp 也接受）', async () => {
    const r = await verify(buildToken('{"alg":"none"}', '{"sub":"guest","role":"admin"}', ''), 'trustAlg')
    expect(r.admin).toBe(true)
    expect(r.steps.find((s) => s.id === 'exp')?.status).toBe('unsafe')
  })
  it('修補版：在 alg 這步就拒絕', async () => {
    const r = await verify(algNone, 'patched')
    expect(r.accepted).toBe(false)
    expect(r.steps.find((s) => s.status === 'fail')?.id).toBe('alg')
  })
})

describe('修補版的 verify 真的有在驗', () => {
  it('用正確密鑰簽的 admin token：接受', async () => {
    const r = await verify(await sign(GUEST_HEADER, { sub: 'boss', role: 'admin', exp: 4102444800 }), 'patched')
    expect(r.admin).toBe(true)
  })
  it('用錯的密鑰簽：拒絕', async () => {
    const r = await verify(await sign(GUEST_HEADER, { ...GUEST_PAYLOAD, role: 'admin' }, 'wrong-key'), 'patched')
    expect(r.accepted).toBe(false)
    expect(failText(r)?.id).toBe('compare')
  })
  it('exp 邊界：now >= exp 就算過期（RFC 7519）', async () => {
    const t = await sign(GUEST_HEADER, { ...GUEST_PAYLOAD, exp: 1000 })
    expect((await verify(t, 'patched', 999)).accepted).toBe(true)
    const r = await verify(t, 'patched', 1000)
    expect(r.accepted).toBe(false)
    expect(failText(r)).toMatchObject({ id: 'exp', text: 'token 已經過期' })
  })
  it('沒有 exp / exp 是字串：拒絕，訊息不同', async () => {
    const { exp: _, ...noExp } = GUEST_PAYLOAD
    expect(failText(await verify(await sign(GUEST_HEADER, noExp), 'patched'))?.text).toBe('token 沒有 exp（到期時間）')
    const strExp = await sign(GUEST_HEADER, { ...GUEST_PAYLOAD, exp: '4102444800' })
    expect(failText(await verify(strExp, 'patched'))?.text).toBe('exp 必須是數字')
  })
  it('role / alg 只認字串：陣列不算', async () => {
    const roleArr = buildToken(json(GUEST_HEADER), '{"sub":"guest","role":["admin"],"exp":4102444800}', '')
    expect((await verify(roleArr, 'decodeOnly')).admin).toBe(false)
    const algArr = buildToken('{"alg":["none"]}', '{"sub":"guest","role":"admin","exp":4102444800}', '')
    expect((await verify(algArr, 'trustAlg')).accepted).toBe(false)
  })
  it('格式壞掉：在 decode 這步就拒絕', async () => {
    for (const bad of ['abc', 'a.b.c', `${b64urlEncode('[1]')}.${b64urlEncode('{}')}.x`]) {
      const r = await verify(bad, 'patched')
      expect(r.accepted).toBe(false)
      expect(r.steps[0]).toMatchObject({ id: 'decode', status: 'fail' })
    }
  })
})

describe('挑戰解答', () => {
  it('挑戰 1：漏洞 A，只改 role', async () => {
    const t = buildToken(json(GUEST_HEADER), '{"sub":"guest","role":"admin","exp":4102444800}', sigOf(GUEST_TOKEN))
    expect((await verify(t, 'decodeOnly')).admin).toBe(true)
  })
  it('挑戰 2：漏洞 B，alg none + 清空簽章', async () => {
    const t = buildToken('{"alg":"none","typ":"JWT"}', '{"sub":"guest","role":"admin","exp":4102444800}', '')
    expect((await verify(t, 'trustAlg')).admin).toBe(true)
  })
})
