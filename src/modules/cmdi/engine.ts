// Command Injection 模擬引擎：純 TS，不依賴 React / DOM。
// 自寫一個最小的 shell：只認 ; && || | & 換行、$( ) 與反引號、引號與 \ 跳脫。
// 檔案系統與指令（ping / ls / cat / whoami / id / echo）全是記憶體裡的假資料。

export type Mode = 'vulnerable' | 'filter' | 'patched'

/** 伺服器程式寫死的前半段，使用者輸入接在後面 */
export const PREFIX = 'ping -c 1 '

export const FLAG = 'FLAG{0n3_l1n3_m4ny_pr0c3ss3s}'

/** 伺服器的工作目錄（相對路徑從這裡算） */
export const CWD = '/var/www/html'

export const USER = 'www-data'

export const FILES: Record<string, string> = {
  '/var/www/html/index.php': '<h1>Demo 網路診斷工具</h1>\n<form action="ping.php">...</form>',
  '/var/www/html/ping.php': '<?php\n// 把使用者輸入直接接在指令後面（漏洞！）\necho shell_exec("ping -c 1 " . $_GET["host"]);',
  '/var/www/flag.txt': FLAG,
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ndemo:x:1000:1000:Demo User（假資料）:/home/demo:/bin/bash',
  '/etc/hostname': 'nettools-demo',
}

const dirname = (p: string) => p.slice(0, p.lastIndexOf('/')) || '/'

const DIRS: ReadonlySet<string> = new Set(Object.keys(FILES).flatMap((f) => {
  const out: string[] = []
  for (let p = dirname(f); ; p = dirname(p)) {
    out.push(p)
    if (p === '/') break
  }
  return out
}))

/** 相對路徑接在 CWD 後面，再把 . 和 .. 算掉 */
function resolve(p: string): string {
  const parts: string[] = []
  for (const seg of (p.startsWith('/') ? p : `${CWD}/${p}`).split('/')) {
    if (seg === '..') parts.pop()
    else if (seg && seg !== '.') parts.push(seg)
  }
  return '/' + parts.join('/')
}

// ---------- 指令 ----------

interface Out { stdout: string; stderr: string; status: number }

const HOSTS: Record<string, string> = { localhost: '127.0.0.1', 'nettools.test': '10.0.0.5' }

const isIPv4 = (h: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) && h.split('.').every((n) => Number(n) <= 255)

function ping(args: string[]): Out {
  const rest = [...args]
  let host: string | undefined
  while (rest.length) {
    const a = rest.shift()!
    if (a === '-c') rest.shift()
    else if (!a.startsWith('-')) { host = a; break }
  }
  if (host === undefined) return { stdout: '', stderr: 'ping: usage error: Destination address required', status: 2 }
  const ip = isIPv4(host) ? host : Object.hasOwn(HOSTS, host) ? HOSTS[host] : undefined
  if (!ip) return { stdout: '', stderr: `ping: ${host}: Name or service not known`, status: 2 }
  return {
    stdout: `PING ${host} (${ip}) 56(84) bytes of data.\n64 bytes from ${ip}: icmp_seq=1 ttl=64 time=0.8 ms\n\n--- ${host} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss`,
    stderr: '',
    status: 0,
  }
}

function ls(args: string[]): Out {
  const paths = args.filter((a) => !a.startsWith('-'))
  const out: string[] = []
  const err: string[] = []
  for (const p of paths.length ? paths : ['.']) {
    const full = resolve(p)
    if (FILES[full] !== undefined) out.push(p)
    else if (DIRS.has(full)) {
      const kids = [...DIRS, ...Object.keys(FILES)].filter((x) => x !== '/' && dirname(x) === full)
      out.push(kids.map((x) => x.slice(x.lastIndexOf('/') + 1)).sort().join('\n'))
    } else err.push(`ls: cannot access '${p}': No such file or directory`)
  }
  return { stdout: out.join('\n'), stderr: err.join('\n'), status: err.length ? 2 : 0 }
}

function cat(args: string[], stdin: string): Out {
  const paths = args.filter((a) => !a.startsWith('-'))
  if (!paths.length) return { stdout: stdin, stderr: '', status: 0 }
  const out: string[] = []
  const err: string[] = []
  for (const p of paths) {
    const full = resolve(p)
    if (FILES[full] !== undefined) out.push(FILES[full])
    else err.push(`cat: ${p}: ${DIRS.has(full) ? 'Is a directory' : 'No such file or directory'}`)
  }
  return { stdout: out.join('\n'), stderr: err.join('\n'), status: err.length ? 1 : 0 }
}

const COMMANDS: Record<string, (args: string[], stdin: string) => Out> = {
  ping,
  ls,
  cat,
  whoami: () => ({ stdout: USER, stderr: '', status: 0 }),
  id: () => ({ stdout: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)', stderr: '', status: 0 }),
  echo: (args) => ({ stdout: args.join(' '), stderr: '', status: 0 }),
}

// ---------- 掃描：引號、$( )、反引號 ----------

const isSubStart = (s: string, i: number) => s[i] === '`' || (s[i] === '$' && s[i + 1] === '(')

/** s[i] 是 $( 或 ` 的開頭，回傳它的結尾（不含）；沒收尾回傳 -1 */
function subEnd(s: string, i: number): number {
  if (s[i] === '`') {
    for (let j = i + 1; j < s.length; j++) {
      if (s[j] === '\\') j++
      else if (s[j] === '`') return j + 1
    }
    return -1
  }
  for (let j = i + 2; j < s.length;) {
    if (s[j] === ')') return j + 1
    const e = skip(s, j)
    if (e < 0) return -1
    j = e
  }
  return -1
}

/**
 * 從 s[j] 跳過一個「不能從中間拆開」的單位：引號字串、$( )、反引號、\x，其他就是一個字元。
 * 回傳下一個位置；引號或括號沒關回傳 -1。碰到 $( ) / 反引號會呼叫 onSub(開頭, 結尾)。
 */
function skip(s: string, j: number, onSub?: (a: number, b: number) => void): number {
  const c = s[j]
  if (c === '\\') return Math.min(j + 2, s.length)
  if (c === "'") {
    const k = s.indexOf("'", j + 1)
    return k < 0 ? -1 : k + 1
  }
  if (c === '"') {
    for (let k = j + 1; k < s.length;) {
      if (s[k] === '"') return k + 1
      if (s[k] === '\\') k += 2
      else if (isSubStart(s, k)) {
        const e = subEnd(s, k)
        if (e < 0) return -1
        onSub?.(k, e)
        k = e
      } else k++
    }
    return -1
  }
  if (isSubStart(s, j)) {
    const e = subEnd(s, j)
    if (e >= 0) onSub?.(j, e)
    return e
  }
  return j + 1
}

// ---------- 拆成好幾個指令 ----------

/** 換行（\n）跟 ; 一樣；& 是丟到背景執行，這裡當成跟 ; 一樣 */
export type Op = ';' | '&&' | '||' | '|' | '&' | '\n'
const OPS: Op[] = ['&&', '||', ';', '|', '&', '\n'] // 兩個字的要先比

interface Piece { text: string; op: Op | null }

interface Split {
  pieces: Piece[]
  /** 運算子與 $( ) 在整行裡的位置，用來上色 */
  marks: [number, number][]
  /** 每一段指令的開頭位置 */
  starts: number[]
  error?: string
}

function split(line: string): Split {
  const r: Split = { pieces: [], marks: [], starts: [0] }
  let start = 0
  let op: Op | null = null
  for (let j = 0; j < line.length;) {
    const hit = OPS.find((o) => line.startsWith(o, j))
    if (hit) {
      r.pieces.push({ text: line.slice(start, j), op })
      r.marks.push([j, j + hit.length])
      op = hit
      j += hit.length
      start = j
      r.starts.push(j)
      continue
    }
    const e = skip(line, j, (a, b) => r.marks.push([a, b]))
    if (e < 0) return { ...r, error: 'Syntax error: Unterminated quoted string' }
    j = e
  }
  r.pieces.push({ text: line.slice(start), op })

  // 兩個運算子中間沒有指令 → 語法錯誤；最後一段空白只有在 ; & 換行後面（或整行是空的，例如 $()）才合法
  const last = r.pieces.length - 1
  for (let i = 0; i <= last; i++) {
    const p = r.pieces[i]
    if (p.text.trim()) continue
    if (i === last && (p.op === null || p.op === ';' || p.op === '&' || p.op === '\n')) {
      r.pieces.pop()
      break
    }
    return { ...r, error: i === last ? 'Syntax error: end of file unexpected' : `Syntax error: "${r.pieces[i + 1].op}" unexpected` }
  }
  return r
}

// ---------- 執行 ----------

export interface Proc {
  argv: string[]
  /** 接在哪個運算子後面（第一個是 null） */
  op: Op | null
  /** 不是伺服器原本要跑的 ping，而是你塞進去的指令 */
  injected: boolean
  /** && / || 的條件不成立就不會執行 */
  ran: boolean
  status: number
  stdout: string
  stderr: string
  /** stdout 被 | 接給下一個指令，沒有直接回傳 */
  piped: boolean
  /** $( ) / 反引號：組參數之前先執行的指令 */
  subs: Proc[]
}

interface Ctx { output: string[] }

/** 把一段指令文字展開成 argv：去掉引號、跑 $( )、依空白切開 */
function expand(text: string, ctx: Ctx, subs: Proc[]): string[] {
  const words: string[] = []
  let cur: string | null = null
  const add = (t: string) => { cur = (cur ?? '') + t }
  const runSub = (a: number, b: number) => {
    const inner = text[a] === '`' ? text.slice(a + 1, b - 1) : text.slice(a + 2, b - 1)
    const r = runLine(inner, false, ctx)
    subs.push(...r.procs)
    return r.stdout.replace(/\n+$/, '')
  }

  for (let j = 0; j < text.length;) {
    const c = text[j]
    if (c === ' ' || c === '\t') {
      if (cur !== null) words.push(cur)
      cur = null
      j++
    } else if (c === '\\') {
      add(text[j + 1] ?? '')
      j += 2
    } else if (c === "'") {
      const k = text.indexOf("'", j + 1)
      add(text.slice(j + 1, k))
      j = k + 1
    } else if (c === '"') {
      let buf = ''
      let k = j + 1
      while (text[k] !== '"') {
        if (text[k] === '\\' && '"\\$`'.includes(text[k + 1])) {
          buf += text[k + 1]
          k += 2
        } else if (isSubStart(text, k)) {
          const e = subEnd(text, k)
          buf += runSub(k, e) // 雙引號裡的 $( ) 結果不會被空白切開
          k = e
        } else buf += text[k++]
      }
      add(buf)
      j = k + 1
    } else if (isSubStart(text, j)) {
      const e = subEnd(text, j)
      const parts = runSub(j, e).split(/\s+/).filter(Boolean)
      parts.forEach((p, i) => {
        if (i > 0) { words.push(cur!); cur = null }
        add(p)
      })
      j = e
    } else {
      add(c)
      j++
    }
  }
  if (cur !== null) words.push(cur)
  return words
}

function exec(argv: string[], stdin: string): Out {
  if (!argv.length) return { stdout: '', stderr: '', status: 0 }
  if (!Object.hasOwn(COMMANDS, argv[0])) return { stdout: '', stderr: `sh: 1: ${argv[0]}: not found`, status: 127 }
  return COMMANDS[argv[0]](argv.slice(1), stdin)
}

interface LineResult { procs: Proc[]; stdout: string; error?: string }

/**
 * 模擬 sh -c "line"。
 * top = 最外層：第一段是伺服器原本的 ping，其他段都算注入；stdout 依執行順序直接寫進回應。
 * 不是最外層（$( ) 裡面）：每一段都算注入；stdout 收起來回傳，等著塞回參數。stderr 一律寫進回應。
 */
function runLine(line: string, top: boolean, ctx: Ctx): LineResult {
  const sp = split(line)
  if (sp.error) {
    ctx.output.push(`sh: 1: ${sp.error}`)
    return { procs: [], stdout: '', error: sp.error }
  }
  const procs: Proc[] = []
  const captured: string[] = []
  let status = 0
  let stdin = ''
  sp.pieces.forEach((p, i) => {
    const run = p.op === '&&' ? status === 0 : p.op === '||' ? status !== 0 : true
    const proc: Proc = { argv: [], op: p.op, injected: !(top && i === 0), ran: run, status: 0, stdout: '', stderr: '', piped: false, subs: [] }
    procs.push(proc)
    if (!run) {
      proc.argv = p.text.trim().split(/\s+/) // 沒執行就不展開，只拿來顯示
      return
    }
    proc.argv = expand(p.text, ctx, proc.subs)
    const r = exec(proc.argv, p.op === '|' ? stdin : '')
    Object.assign(proc, r)
    proc.piped = sp.pieces[i + 1]?.op === '|'
    stdin = proc.piped ? r.stdout : ''
    if (r.stdout && !proc.piped) (top ? ctx.output : captured).push(r.stdout)
    if (r.stderr) ctx.output.push(r.stderr)
    status = r.status
  })
  return { procs, stdout: captured.join('\n') }
}

// ---------- 對外 API ----------

export type SegKind = 'code' | 'data' | 'injected'
export interface Seg { text: string; kind: SegKind }

export interface RunResult {
  input: string
  outcome: 'ok' | 'blocked' | 'syntax' | 'empty'
  /** 被擋下的原因 */
  reason?: string
  /** 伺服器交給 shell 的整行 */
  line: string
  /** 修補版：不經過 shell，直接把這個陣列交給作業系統 */
  argv?: string[]
  /** 整行依角色分段：程式 / 你的資料 / 變成指令的部分 */
  segments: Seg[]
  /** 最外層的指令（$( ) 裡的在 subs） */
  procs: Proc[]
  /** 回應給瀏覽器的內容（stdout + stderr，依執行順序） */
  output: string
  /** 除了 ping 以外，還有其他指令被執行 */
  injected: boolean
  /** 注入的指令的輸出，回到了攻擊者手上 */
  leaked: boolean
}

/** 過濾版擋的字元（黑名單） */
export const BLACKLIST = /[;&|]/

/** 修補版的格式檢查：只能是英數字、點、減號，而且不能用 - 開頭（避免被當成 ping 的選項） */
export const HOST_FORMAT = /^[a-z0-9][a-z0-9.-]*$/i

/** 整行依角色上色：運算子、$( ) 和第 2 段以後的指令 = injected */
function segments(line: string, sp: Split): Seg[] {
  const kinds = [...line].map((_, i) => (i < PREFIX.length ? 'code' : 'data') as SegKind)
  for (const [a, b] of sp.marks) for (let i = a; i < b; i++) kinds[i] = 'injected'
  for (let i = sp.starts[1] ?? line.length; i < line.length; i++) kinds[i] = 'injected'
  const out: Seg[] = []
  kinds.forEach((k, i) => {
    const last = out[out.length - 1]
    if (last?.kind === k) last.text += line[i]
    else out.push({ text: line[i], kind: k })
  })
  return out
}

/** 不經過 shell，直接執行 argv（execFile 的概念）：; | $( ) 都只是普通字元 */
export function runArgv(argv: string[]): Proc {
  const r = exec(argv, '')
  return { argv, op: null, injected: false, ran: true, piped: false, subs: [], ...r }
}

const allProcs = (ps: Proc[]): Proc[] => ps.flatMap((p) => [...allProcs(p.subs), p])

/** 模擬 GET /ping?host=... */
export function runPing(host: string, mode: Mode): RunResult {
  const line = PREFIX + host
  const sp = split(line)
  const base: RunResult = { input: host, outcome: 'ok', line, segments: segments(line, sp), procs: [], output: '', injected: false, leaked: false }

  if (!host.trim()) return { ...base, outcome: 'empty' }

  if (mode === 'patched') {
    const argv = ['ping', '-c', '1', host]
    if (!HOST_FORMAT.test(host)) return { ...base, argv, outcome: 'blocked', reason: '格式不符：只接受英數字、點和減號' }
    const p = runArgv(argv)
    return { ...base, argv, procs: [p], output: [p.stdout, p.stderr].filter(Boolean).join('\n') }
  }

  if (mode === 'filter') {
    const bad = host.match(BLACKLIST)
    if (bad) return { ...base, outcome: 'blocked', reason: `含有禁止的字元 ${bad[0]}` }
  }

  const ctx: Ctx = { output: [] }
  const r = runLine(line, true, ctx)
  const output = ctx.output.filter(Boolean).join('\n')
  const all = allProcs(r.procs)
  const injected = all.some((p) => p.injected && p.ran)
  const leaked = all.some((p) => p.injected && p.ran && p.stdout.trim() && output.includes(p.stdout.trim().split('\n')[0]))
  return { ...base, outcome: r.error ? 'syntax' : 'ok', procs: r.procs, output, injected, leaked }
}
