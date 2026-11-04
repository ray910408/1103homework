import { describe, expect, it } from 'vitest'
import { FLAG_ADMIN, FLAG_METADATA, privateRange, serverFetch, type Mode } from './engine.ts'

const MODES: Mode[] = ['vulnerable', 'blacklist', 'patched']
const CREDS = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role'

describe('serverFetch：正常圖片', () => {
  for (const m of MODES) {
    it(`${m}：抓得到 cdn 的貓圖`, () => {
      const r = serverFetch('https://cdn.example.com/cat.png', m)
      expect(r.outcome).toBe('ok')
      expect(r.response?.type).toBe('image')
      expect(r.internal).toBe(false)
      expect(r.leaked).toBe(false)
    })
  }
})

describe('serverFetch：直接打內網（黑名單擋得住的）', () => {
  const cases: [string, string, string][] = [
    ['雲端金鑰', CREDS, FLAG_METADATA],
    ['localhost 管理後台', 'http://localhost:8080/admin', FLAG_ADMIN],
    ['127.0.0.1 管理後台', 'http://127.0.0.1:8080/admin', FLAG_ADMIN],
  ]
  for (const [name, url, flag] of cases) {
    it(`${name}：漏洞版外洩，黑名單與修補版擋下`, () => {
      const v = serverFetch(url, 'vulnerable')
      expect(v.leaked).toBe(true)
      expect(v.response?.body).toContain(flag)
      expect(serverFetch(url, 'blacklist').outcome).toBe('blocked')
      expect(serverFetch(url, 'patched').outcome).toBe('blocked')
    })
  }
})

describe('serverFetch：繞過黑名單', () => {
  const bypasses = [
    'http://2130706433:8080/admin',
    'http://127.1:8080/admin',
    'http://0x7f.1:8080/admin',
    'http://0x7f000001:8080/admin',
    'http://[::1]:8080/admin',
    'http://0:8080/admin',
    'http://rebind.attacker.test:8080/admin',
  ]
  for (const url of bypasses) {
    it(`${url}：漏洞版與黑名單版都外洩，修補版擋下`, () => {
      expect(serverFetch(url, 'vulnerable').response?.body).toContain(FLAG_ADMIN)
      const b = serverFetch(url, 'blacklist')
      expect(b.outcome).toBe('ok')
      expect(b.response?.body).toContain(FLAG_ADMIN)
      const p = serverFetch(url, 'patched')
      expect(p.outcome).toBe('blocked')
      expect(p.response).toBeUndefined()
    })
  }

  it('2130706433 被正規化成 127.0.0.1', () => {
    const r = serverFetch('http://2130706433:8080/admin', 'blacklist')
    expect(r.rawHost).toBe('2130706433:8080')
    expect(r.parsedHost).toBe('127.0.0.1:8080')
    expect(r.hops[0].node).toBe('admin')
  })

  it('302 轉址：漏洞版與黑名單版跟著轉進 metadata，修補版在第二跳擋下', () => {
    for (const m of ['vulnerable', 'blacklist'] as const) {
      const r = serverFetch('http://redirect.attacker.test/r', m)
      expect(r.hops.map((h) => h.node)).toEqual(['attacker', 'metadata'])
      expect(r.response?.body).toContain(FLAG_METADATA)
    }
    const p = serverFetch('http://redirect.attacker.test/r', 'patched')
    expect(p.outcome).toBe('blocked')
    expect(p.hops.map((h) => h.status)).toEqual(['redirect', 'blocked'])
  })

  it('開放轉址 ?url= 也能轉到管理後台', () => {
    const r = serverFetch('http://redirect.attacker.test/r?url=http://127.0.0.1:8080/admin', 'blacklist')
    // 黑名單比對原始字串，裡面有 127.0.0.1 所以擋下
    expect(r.outcome).toBe('blocked')
    expect(serverFetch('http://redirect.attacker.test/r?url=http://2130706433:8080/admin', 'blacklist').response?.body).toContain(FLAG_ADMIN)
  })

  it('file:///etc/passwd：漏洞版與黑名單版讀到檔案，修補版擋協定', () => {
    expect(serverFetch('file:///etc/passwd', 'vulnerable').response?.body).toContain('root:x:0:0')
    expect(serverFetch('file:///etc/passwd', 'blacklist').leaked).toBe(true)
    expect(serverFetch('file:///etc/passwd', 'patched').outcome).toBe('blocked')
  })
})

describe('serverFetch：其他', () => {
  it('Redis：連進內網但不算機密外洩', () => {
    const r = serverFetch('http://10.0.0.5:6379/', 'vulnerable')
    expect(r.internal).toBe(true)
    expect(r.leaked).toBe(false)
  })

  it('格式錯誤 / 查無主機 → error', () => {
    expect(serverFetch('not a url', 'vulnerable').outcome).toBe('error')
    expect(serverFetch('http://nope.example/', 'vulnerable').outcome).toBe('error')
  })

  it('privateRange', () => {
    expect(privateRange('127.0.0.1')).toMatch(/loopback/)
    expect(privateRange('::1')).toMatch(/loopback/)
    expect(privateRange('::ffff:7f00:1')).toMatch(/loopback/)
    expect(privateRange('172.20.1.1')).toMatch(/private/)
    expect(privateRange('172.32.0.1')).toBeUndefined()
    expect(privateRange('169.254.169.254')).toMatch(/link-local/)
    expect(privateRange('93.184.216.34')).toBeUndefined()
  })
})
