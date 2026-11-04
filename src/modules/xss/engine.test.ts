import { describe, expect, it } from 'vitest'
import { domTree, escapeHtml, features, isAttempt, pageParts, toSegments, victimDoc, willExecute, type DomNode, type XssKind } from './engine.ts'

const SCRIPT = "<script>alert('XSS')</script>"
const IMG = "<img src=x onerror=alert('XSS')>"
const html = (kind: XssKind, input: string, escape: boolean) => pageParts(kind, [input], escape).map((p) => p.text).join('')
const off = { escape: false, strictCsp: false }

describe('escapeHtml', () => {
  it('五個特殊字元都要 escape', () => {
    expect(escapeHtml(`<a href="x">'&`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;')
  })
})

describe('漏洞版 vs 修補版', () => {
  for (const kind of ['reflected', 'stored', 'dom'] as const) {
    it(`${kind}：漏洞版保留原始標籤，修補版只剩 escape 後的文字`, () => {
      expect(html(kind, IMG, false)).toContain(IMG)
      const patched = html(kind, IMG, true)
      expect(patched).not.toContain('<img')
      expect(patched).toContain('&lt;img')
    })
  }

  it('經典 payload：漏洞版會執行，修補版不會', () => {
    expect(willExecute('reflected', SCRIPT, off)).toBe(true)
    expect(willExecute('stored', IMG, off)).toBe(true)
    expect(willExecute('dom', IMG, off)).toBe(true)
    for (const kind of ['reflected', 'stored', 'dom'] as const) {
      expect(willExecute(kind, SCRIPT, { escape: true, strictCsp: false })).toBe(false)
      expect(willExecute(kind, IMG, { escape: true, strictCsp: false })).toBe(false)
      expect(willExecute(kind, IMG, { escape: false, strictCsp: true })).toBe(false)
    }
  })

  it('DOM 型：innerHTML 插入的 <script> 不會執行', () => {
    expect(willExecute('dom', SCRIPT, off)).toBe(false)
    const find = (n: DomNode): DomNode | undefined => n.tag === 'script' ? n : n.children.map(find).find(Boolean)
    expect(find(domTree(pageParts('dom', [SCRIPT], false), 'dom'))?.inert).toBe(true)
    expect(find(domTree(pageParts('reflected', [SCRIPT], false), 'reflected'))?.inert).toBeUndefined()
  })
})

describe('toSegments', () => {
  it('一般文字：輸入只是 data', () => {
    const segs = toSegments(pageParts('reflected', ['貓咪'], false))
    expect(segs.filter((s) => s.kind === 'data').map((s) => s.text)).toEqual(['貓咪'])
    expect(segs.some((s) => s.kind === 'injected')).toBe(false)
  })

  it('漏洞版：標籤與 script 內容是 injected', () => {
    const segs = toSegments(pageParts('reflected', [SCRIPT], false))
    expect(segs.filter((s) => s.kind === 'injected').map((s) => s.text).join('')).toBe(SCRIPT)
  })

  it('修補版：escape 後全部變回 data', () => {
    const segs = toSegments(pageParts('reflected', [SCRIPT], true))
    expect(segs.some((s) => s.kind === 'injected')).toBe(false)
    expect(segs.find((s) => s.kind === 'data')?.text).toBe(escapeHtml(SCRIPT))
  })
})

describe('domTree', () => {
  it('從輸入長出來的 img 節點被標記，事件處理器在屬性裡', () => {
    const p = domTree(pageParts('reflected', [IMG], false), 'reflected').children[0]
    const img = p.children[1].children[0]
    expect(img).toMatchObject({ tag: 'img', injected: true })
    expect(img.attrs).toContain('onerror')
  })
})

describe('features / isAttempt', () => {
  it('抓得到 script、事件處理器、javascript: 網址', () => {
    expect(features(SCRIPT).scriptTag).toBe(true)
    expect(features(IMG).handlers).toEqual(['onerror'])
    expect(features('<a href="javascript:alert(1)">x</a>').jsUrl).toBe(true)
    expect(isAttempt('大家好')).toBe(false)
  })
})

describe('victimDoc 安全網', () => {
  it('永遠帶著擋對外連線的 CSP', () => {
    const doc = victimDoc('reflected', [IMG], { ...off, viewer: '你' })
    expect(doc).toContain("default-src 'none'")
    expect(doc).toContain(IMG)
  })

  it('strictCsp：改用 nonce，不允許 unsafe-inline', () => {
    const doc = victimDoc('reflected', [IMG], { escape: false, strictCsp: true, viewer: '你' })
    expect(doc).toContain("'nonce-")
    expect(doc).not.toContain("'unsafe-inline'; style")
  })

  it('meta / base 標籤在執行前被拆掉，不會讓 iframe 跳走', () => {
    const doc = victimDoc('reflected', ['<meta http-equiv="refresh" content="0;url=https://example.com">'], { ...off, viewer: '你' })
    expect(doc).toContain('<meta-blocked')
  })

  it('DOM 型：輸入不會提早結束 <script>', () => {
    const doc = victimDoc('dom', ['</script><b>x</b>'], { ...off, viewer: '你' })
    expect(doc).not.toContain('</script><b>')
  })
})

describe('假 cookie', () => {
  it('prelude 用 defineProperty 換掉 document.cookie，不會丟 SecurityError', () => {
    const doc = victimDoc('stored', ['hi'], { escape: false, strictCsp: false, viewer: 'admin', cookie: 'session=FLAG{x}' })
    expect(doc).toContain("Object.defineProperty(document, 'cookie'")
    expect(doc).toContain('"session=FLAG{x}"')
  })
  it('假 cookie 裡的 < 會被轉義，不會提早結束 <script>', () => {
    const doc = victimDoc('stored', ['hi'], { escape: false, strictCsp: false, viewer: 'x', cookie: '</script><b>' })
    expect(doc).not.toContain('</script><b>')
  })
})

