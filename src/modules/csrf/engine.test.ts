import { describe, expect, it } from 'vitest'
import {
  aliceRequest, ATTACKER, attackerHtml, attackRequest, cookieDecision, PATCHED, simulate, START_BALANCE, VULNERABLE,
  type BankConfig, type RequestKind, type SameSite,
} from './engine.ts'

const KINDS: RequestKind[] = ['form-post', 'img-get', 'link-navigation']
const atk = (kind: RequestKind, amount = '10000') => attackRequest({ kind, to: ATTACKER, amount })

describe('cookieDecision：SameSite × 請求方式', () => {
  const crossSite: Record<SameSite, Record<RequestKind, boolean>> = {
    None: { 'form-post': true, 'img-get': true, 'link-navigation': true },
    Lax: { 'form-post': false, 'img-get': false, 'link-navigation': true },
    Strict: { 'form-post': false, 'img-get': false, 'link-navigation': false },
  }
  for (const ss of ['None', 'Lax', 'Strict'] as SameSite[]) {
    for (const k of KINDS) {
      it(`跨站 ${k}、SameSite=${ss} → ${crossSite[ss][k] ? '帶' : '不帶'} cookie`, () => {
        expect(cookieDecision(ss, atk(k)).sent).toBe(crossSite[ss][k])
      })
      it(`同站 ${k}、SameSite=${ss} → 一定帶 cookie`, () => {
        expect(cookieDecision(ss, { ...atk(k), initiator: 'bank.demo' }).sent).toBe(true)
      })
    }
  }
})

describe('simulate', () => {
  it('漏洞版：隱藏表單自動送出 → 轉帳成功，cookie 是瀏覽器自動帶的', () => {
    const t = simulate(atk('form-post'), VULNERABLE)
    expect(t.transferred).toBe(true)
    expect(t.balanceAfter).toBe(START_BALANCE - 10000)
    expect(t.headers.find((h) => h.name === 'Cookie')?.auto).toBe(true)
    expect(t.headers.find((h) => h.name === 'Origin')?.value).toBe('https://evil.test')
  })

  it('漏洞版：<img> 與連結是 GET，被 405 擋下（但 cookie 其實有帶）', () => {
    for (const k of ['img-get', 'link-navigation'] as const) {
      const t = simulate(atk(k), VULNERABLE)
      expect(t.transferred).toBe(false)
      expect(t.blockedBy).toBe('method')
      expect(t.cookie.sent).toBe(true)
    }
  })

  it('修補版：三種攻擊全部失敗', () => {
    for (const k of KINDS) expect(simulate(atk(k), PATCHED).transferred).toBe(false)
  })

  it('只開 CSRF token：cookie 有帶，但沒有 token → 403', () => {
    const t = simulate(atk('form-post'), { ...VULNERABLE, checkToken: true })
    expect(t.cookie.sent).toBe(true)
    expect(t.status).toBe(403)
    expect(t.blockedBy).toBe('token')
  })

  it('只開 SameSite=Lax：跨站表單 POST 沒帶 cookie → 401', () => {
    const t = simulate(atk('form-post'), { ...VULNERABLE, sameSite: 'Lax' })
    expect(t.status).toBe(401)
    expect(t.blockedBy).toBe('samesite')
  })

  it('Lax + 接受 GET + 沒 token：擋得住 <img>，擋不住頂層導覽 GET', () => {
    const cfg: BankConfig = { sameSite: 'Lax', checkToken: false, acceptGet: true }
    expect(simulate(atk('img-get'), cfg).transferred).toBe(false)
    expect(simulate(atk('link-navigation'), cfg).transferred).toBe(true)
  })

  it('Strict + 接受 GET：連頂層導覽也擋得住', () => {
    expect(simulate(atk('link-navigation'), { sameSite: 'Strict', checkToken: false, acceptGet: true }).transferred).toBe(false)
  })

  it('Alice 自己在 bank.demo 轉帳：修補版仍然成功', () => {
    const t = simulate(aliceRequest('bob', '1000'), PATCHED)
    expect(t.transferred).toBe(true)
    expect(t.balanceAfter).toBe(START_BALANCE - 1000)
  })

  it('金額不合法或超過餘額 → 400', () => {
    for (const amount of ['abc', '-5', '0', '1.5', String(START_BALANCE + 1)]) {
      expect(simulate(atk('form-post', amount), VULNERABLE).status).toBe(400)
    }
  })
})

describe('attackerHtml', () => {
  it('表單版：POST 到 bank.demo/transfer，並自動送出', () => {
    const html = attackerHtml({ kind: 'form-post', to: ATTACKER, amount: '10000' }).map((l) => l.text).join('\n')
    expect(html).toContain('action="https://bank.demo/transfer" method="POST"')
    expect(html).toContain('.submit()')
  })

  it('<img> 與連結版：GET 網址帶著參數', () => {
    expect(attackerHtml({ kind: 'img-get', to: ATTACKER, amount: '10000' })[1].text).toContain('transfer?to=attacker&amount=10000')
    expect(attackerHtml({ kind: 'link-navigation', to: ATTACKER, amount: '1' })[1].text).toContain('<a href=')
  })

  it('值裡的引號會被跳脫', () => {
    expect(attackerHtml({ kind: 'form-post', to: '"><x', amount: '1' })[2].text).toContain('value="&quot;>&lt;x"')
    expect(attackerHtml({ kind: 'img-get', to: '"<', amount: '1' })[1].text).toContain('to=%22%3C')
  })
})
