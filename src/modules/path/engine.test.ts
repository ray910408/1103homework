import { describe, expect, it } from 'vitest'
import { BASE, FLAG_CONFIG, NODES, download, walk } from './engine.ts'

describe('正常下載', () => {
  it.each(['vulnerable', 'filter', 'patched'] as const)('%s：report.pdf 正常下載', (mode) => {
    const r = download('report.pdf', mode)
    expect(r.outcome).toBe('ok')
    expect(r.full).toBe(`${BASE}/report.pdf`)
    expect(r.leaked).toBe(false)
  })

  it('修補版：先正規化再檢查，繞一圈還在 BASE 裡的路徑照樣能下載', () => {
    expect(download('./x/../manual.txt', 'patched').outcome).toBe('ok')
  })

  it('檔名結尾多一個 /：join 保留它 → 讀檔失敗；resolve 會去掉它 → 正常', () => {
    expect(download('report.pdf/', 'vulnerable').outcome).toBe('notdir')
    expect(download('report.pdf/', 'filter').outcome).toBe('notdir')
    expect(download('report.pdf/', 'patched').outcome).toBe('ok')
  })

  it('空輸入', () => {
    expect(download('', 'vulnerable').outcome).toBe('empty')
  })
})

describe('經典 payload：../../../etc/passwd', () => {
  const payload = '../../../etc/passwd'

  it('漏洞版：讀到 /etc/passwd', () => {
    const r = download(payload, 'vulnerable')
    expect(r.full).toBe('/etc/passwd')
    expect(r.leaked).toBe(true)
    expect(r.body).toContain('root:x:0:0')
  })

  it('修補版：擋下', () => {
    const r = download(payload, 'patched')
    expect(r.outcome).toBe('blocked')
    expect(r.body).toBeUndefined()
  })

  it('過濾版：../ 被刪光，只剩 etc/passwd → 找不到', () => {
    const r = download(payload, 'filter')
    expect(r.filtered).toBe('etc/passwd')
    expect(r.outcome).toBe('notfound')
    expect(r.leaked).toBe(false)
  })

  it('多打幾個 ../ 也沒差：到根目錄就停住', () => {
    expect(download('../../../../../../etc/passwd', 'vulnerable').full).toBe('/etc/passwd')
  })
})

describe('挑戰 1：../app/config.js', () => {
  it('漏洞版：拿到 FLAG', () => {
    expect(download('../app/config.js', 'vulnerable').body).toContain(FLAG_CONFIG)
  })
  it('修補版：擋下', () => {
    expect(download('../app/config.js', 'patched').outcome).toBe('blocked')
  })
  it('過濾版：直接打 ../ 沒用', () => {
    expect(download('../app/config.js', 'filter').leaked).toBe(false)
  })
})

describe('挑戰 2：繞過只刪一輪的過濾', () => {
  it.each(['....//app/config.js', '..././app/config.js'])('過濾版：%s 拿到 FLAG', (p) => {
    const r = download(p, 'filter')
    expect(r.filtered).toBe('../app/config.js')
    expect(r.body).toContain(FLAG_CONFIG)
  })
  it.each(['....//app/config.js', '..././app/config.js'])('修補版：%s 讀不到（.... 只是普通資料夾名稱）', (p) => {
    const r = download(p, 'patched')
    expect(r.leaked).toBe(false)
    expect(r.body).toBeUndefined()
  })
})

describe('絕對路徑', () => {
  it('path.join 規則：/etc/passwd 被接在 BASE 後面 → 找不到', () => {
    const r = download('/etc/passwd', 'vulnerable')
    expect(r.full).toBe(`${BASE}/etc/passwd`)
    expect(r.outcome).toBe('notfound')
  })
  it('path.resolve 規則：/etc/passwd 直接跳到根目錄，修補版檢查的是解析後的路徑 → 擋下', () => {
    const r = download('/etc/passwd', 'patched')
    expect(r.full).toBe('/etc/passwd')
    expect(r.outcome).toBe('blocked')
  })
})

describe('修補版的前綴比對要加結尾的 /', () => {
  it('隔壁的 files-backup 不算在 BASE 裡', () => {
    expect(download('../files-backup/x', 'patched').outcome).toBe('blocked')
  })
  it('BASE 資料夾本身也不給讀', () => {
    expect(download('.', 'patched').outcome).toBe('blocked')
  })
})

describe('walk / 目錄樹', () => {
  it('一步一步走', () => {
    expect(walk('../app', false).map((s) => [s.kind, s.path])).toEqual([
      ['start', BASE], ['up', '/var/www'], ['down', '/var/www/app'],
    ])
  })
  it('資料夾不是檔案', () => {
    const r = download('../', 'vulnerable')
    expect(r.outcome).toBe('isdir')
    expect(r.escaped).toBe(true)
  })
  it('NODES 依目錄樹順序排列', () => {
    expect(NODES[0]).toBe('/')
    expect(NODES.indexOf(BASE)).toBeLessThan(NODES.indexOf(`${BASE}/report.pdf`))
    expect(NODES.indexOf('/var/www')).toBeLessThan(NODES.indexOf('/var/www/app/config.js'))
  })
})
