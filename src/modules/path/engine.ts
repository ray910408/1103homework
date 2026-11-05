// Path Traversal 模擬引擎：純 TS，不依賴 React / DOM。
// 檔案系統是記憶體裡的假資料；路徑解析自己寫（POSIX 規則），不用 Node 的 path。

export type Mode = 'vulnerable' | 'filter' | 'patched'

/** 允許下載的資料夾 */
export const BASE = '/var/www/files'

export const FLAG_CONFIG = 'FLAG{d0t_d0t_sl4sh_3sc4p3d}'

export const FILES: Record<string, string> = {
  '/var/www/files/report.pdf': '%PDF-1.4（假的 PDF）\nDemo 公司 2026 年度報告：本季營收創新高（示意內容）',
  '/var/www/files/manual.txt': 'Demo 文件中心 使用手冊\n在網址的 file= 後面填檔名，就能下載這個資料夾裡的檔案。',
  '/var/www/app/config.js': `// 網站設定檔：不該被任何人下載！\nmodule.exports = {\n  db: { user: 'docs', password: 'demo-secret-key' },\n  sessionSecret: '${FLAG_CONFIG}',\n}`,
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ndemo:x:1000:1000:Demo User（假資料）:/home/demo:/bin/bash',
  '/etc/hostname': 'docs-demo',
}

export const dirname = (p: string) => p.slice(0, p.lastIndexOf('/')) || '/'

/** 所有資料夾（由檔案路徑往上推） */
export const DIRS: ReadonlySet<string> = new Set(Object.keys(FILES).flatMap((f) => {
  const out: string[] = []
  for (let p = dirname(f); ; p = dirname(p)) {
    out.push(p)
    if (p === '/') break
  }
  return out
}))

/** 整棵樹。字典序排好剛好是「資料夾 → 它裡面的東西」的順序，可以直接畫成目錄樹 */
export const NODES: readonly string[] = [...DIRS, ...Object.keys(FILES)].sort()

/** 在 BASE 裡面（含 BASE 本身） */
export const inBase = (p: string) => p === BASE || p.startsWith(BASE + '/')

export interface Step {
  /** 這一步吃掉的路徑片段（起點是空字串） */
  seg: string
  kind: 'start' | 'root' | 'up' | 'down'
  /** 走完這一步的位置 */
  path: string
}

/**
 * 從 BASE 出發，照著 input 一段一段走（就是路徑正規化）。
 * absolute = true 時，/ 開頭的輸入會直接跳到根目錄（path.resolve 的規則）；
 * false 時當成接在 BASE 後面（path.join 的規則）。
 */
export function walk(input: string, absolute: boolean): Step[] {
  let parts = BASE.split('/').filter(Boolean)
  const steps: Step[] = [{ seg: '', kind: 'start', path: BASE }]
  if (absolute && input.startsWith('/')) {
    parts = []
    steps.push({ seg: '/', kind: 'root', path: '/' })
  }
  for (const seg of input.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') parts.pop() // 到了根目錄還 pop，就停在原地
    else parts.push(seg)
    steps.push({ seg, kind: seg === '..' ? 'up' : 'down', path: '/' + parts.join('/') })
  }
  return steps
}

export interface ReadResult {
  input: string
  /** 過濾版處理過的檔名（其他版本 = input） */
  filtered: string
  steps: Step[]
  /** 系統解析後實際讀取的路徑 */
  full: string
  /** full 不在 BASE 裡面 */
  escaped: boolean
  outcome: 'ok' | 'blocked' | 'notfound' | 'isdir' | 'notdir' | 'empty'
  body?: string
  /** 讀到了 BASE 外面的檔案 */
  leaked: boolean
}

/** 模擬 GET /download?file=... */
export function download(file: string, mode: Mode): ReadResult {
  const filtered = mode === 'filter' ? file.replaceAll('../', '') : file
  const steps = walk(filtered, mode === 'patched')
  const full = steps[steps.length - 1].path
  const r = { input: file, filtered, steps, full, escaped: !inBase(full), leaked: false }

  if (!file) return { ...r, outcome: 'empty' }
  if (mode === 'patched' && !full.startsWith(BASE + '/')) return { ...r, outcome: 'blocked' }
  if (DIRS.has(full)) return { ...r, outcome: 'isdir' }
  const body = FILES[full]
  if (body === undefined) return { ...r, outcome: 'notfound' }
  // path.join 會保留結尾的 /：readFileSync('report.pdf/') 會失敗（ENOTDIR）；path.resolve 會把它去掉
  if (mode !== 'patched' && filtered.endsWith('/')) return { ...r, outcome: 'notdir' }
  return { ...r, outcome: 'ok', body, leaked: r.escaped }
}
