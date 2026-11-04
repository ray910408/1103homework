// XSS 模擬引擎：純 TS，不依賴 React / DOM，方便測試。
import type { SegKind, Segment } from '../../components/ui.tsx'

export type XssKind = 'reflected' | 'stored' | 'dom'

/** 一段 HTML，標記是不是來自使用者輸入 */
export interface Part { text: string; input: boolean }

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

/** 論壇上原本就有的留言（假資料） */
export const EXISTING_COMMENTS = [
  { author: '小明', text: '這個論壇好讚！' },
  { author: '阿華', text: '有人知道社團怎麼報名嗎？' },
]

/**
 * 受害者頁面裡「會被輸入影響」的那段 HTML。
 * reflected / stored：伺服器回傳的 HTML；dom：前端 JS 用 innerHTML 寫進去之後的結果。
 * escape = 修補版（輸出前 escape；DOM 型改用 textContent，效果等同）。
 */
export function pageParts(kind: XssKind, inputs: string[], escape: boolean): Part[] {
  const code = (text: string): Part => ({ text, input: false })
  const user = (text: string): Part => ({ text: escape ? escapeHtml(text) : text, input: true })
  if (kind === 'reflected') return [code('<p>你搜尋的是：<b>'), user(inputs[0] ?? ''), code('</b></p>\n<p>找不到相關文章。</p>')]
  if (kind === 'dom') return [code('<p id="out">歡迎，'), user(inputs[0] ?? ''), code('</p>')]
  return [
    ...EXISTING_COMMENTS.map((c) => code(`<div class="c"><b>${c.author}</b>：${c.text}</div>\n`)),
    ...inputs.flatMap((t) => [code('<div class="c"><b>你</b>：'), user(t), code('</div>\n')]),
  ]
}

// ---------- 受害者頁面（放進 sandbox iframe 的 srcdoc） ----------

const NONCE = 'demo-nonce'

/**
 * 安全網：default-src 'none' 擋掉 iframe 裡所有對外連線（圖片、fetch、iframe…）。
 * 一般模式允許 inline script，才能示範 XSS；strictCsp = 示範用 nonce 的 CSP 修補。
 */
function cspMeta(strictCsp: boolean): string {
  const script = strictCsp ? `'nonce-${NONCE}'` : "'unsafe-inline'"
  return `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src ${script}; style-src 'unsafe-inline'; img-src data:">`
}

/**
 * 把 alert 和錯誤轉給父頁顯示；擋掉會讓 iframe 離開本頁的連結與導覽。
 * sandbox 沒有 allow-same-origin，讀真的 document.cookie 會丟 SecurityError，所以換成假 cookie。
 */
const prelude = (cookie: string) => `<script nonce="${NONCE}">(function () {
  Object.defineProperty(document, 'cookie', { get: function () { return ${JSON.stringify(cookie).replace(/</g, '\\u003c')} }, set: function () {}, configurable: true });
  function send(type, msg) { parent.postMessage({ type: type, msg: String(msg).slice(0, 200) }, '*') }
  window.alert = function (m) { send('alert', m) };
  window.addEventListener('error', function (e) { send('error', e.message) });
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (a && !/^\\s*javascript:/i.test(a.getAttribute('href') || '')) e.preventDefault();
  }, true);
  if (window.navigation) window.navigation.addEventListener('navigate', function (e) { if (e.cancelable) e.preventDefault() });
})();</script>`

const STYLE = '<style>body{font:14px/1.6 system-ui,sans-serif;margin:10px;color:#1f2328}.bar{color:#59636e;font-size:12px;margin-bottom:6px}.c{border-bottom:1px solid #d0d7de;padding:4px 0}</style>'

/** <meta refresh> / <base> 會讓 iframe 跳去別的網址：執行前先拆掉（畫面上的 HTML 仍照原樣顯示） */
function defuse(s: string): string {
  return s.replace(/<(\/?)(meta|base)\b/gi, '<$1$2-blocked')
}

export function victimDoc(kind: XssKind, inputs: string[], opts: { escape: boolean; strictCsp: boolean; viewer: string; cookie?: string }): string {
  const head = cspMeta(opts.strictCsp) + prelude(opts.cookie ?? '') + STYLE
  const bar = `<div class="bar">forum.demo｜目前登入：${escapeHtml(opts.viewer)}</div>`
  if (kind === 'dom') {
    // 輸入用 JSON 字串帶進去，把 < 轉成 <，避免提早結束 <script>
    const value = JSON.stringify(defuse(inputs[0] ?? '')).replace(/</g, '\\u003c')
    const prop = opts.escape ? 'textContent' : 'innerHTML'
    return `${head}${bar}<p id="out"></p><script nonce="${NONCE}">document.getElementById('out').${prop} = '歡迎，' + ${value};</script>`
  }
  const body = pageParts(kind, inputs.map(defuse), opts.escape).map((p) => p.text).join('')
  return head + bar + body
}

// ---------- 分析：輸入變成了什麼 ----------

export function features(input: string) {
  return {
    tags: [...input.matchAll(/<([a-zA-Z][\w-]*)/g)].map((m) => m[1].toLowerCase()),
    scriptTag: /<script\b/i.test(input),
    handlers: [...input.matchAll(/\bon([a-z]+)\s*=/gi)].map((m) => `on${m[1].toLowerCase()}`),
    jsUrl: /javascript\s*:/i.test(input),
  }
}

/** 是不是像攻擊（有標籤或 javascript: 網址） */
export function isAttempt(input: string): boolean {
  const f = features(input)
  return f.tags.length > 0 || f.jsUrl
}

/** 預測腳本會不會「不用點擊就自動執行」（javascript: 連結要點才會跑，不算） */
export function willExecute(kind: XssKind, input: string, opts: { escape: boolean; strictCsp: boolean }): boolean {
  if (opts.escape || opts.strictCsp) return false
  const f = features(input)
  // innerHTML 插入的 <script> 不會執行（HTML 規範），只有事件處理器有用
  return kind === 'dom' ? f.handlers.length > 0 : f.scriptTag || f.handlers.length > 0
}

interface Tok { type: 'tag' | 'text' | 'raw'; start: number; end: number }

const TAG_START = /[A-Za-z/!]/

// ponytail: 極簡 tokenizer，屬性值裡的 > 會切錯；教學夠用，要精準再換真正的 HTML parser
function tokenize(s: string): Tok[] {
  const out: Tok[] = []
  let i = 0
  while (i < s.length) {
    if (s[i] === '<' && TAG_START.test(s[i + 1] ?? '')) {
      const close = s.indexOf('>', i)
      const end = close === -1 ? s.length : close + 1
      out.push({ type: 'tag', start: i, end })
      i = end
      if (/^<script\b/i.test(s.slice(out[out.length - 1].start, end))) {
        const c = s.slice(end).search(/<\/script/i)
        const rawEnd = c === -1 ? s.length : end + c
        if (rawEnd > end) out.push({ type: 'raw', start: end, end: rawEnd })
        i = rawEnd
      }
    } else {
      let j = i + 1
      while (j < s.length && !(s[j] === '<' && TAG_START.test(s[j + 1] ?? ''))) j++
      out.push({ type: 'text', start: i, end: j })
      i = j
    }
  }
  return out
}

function flatten(parts: Part[]) {
  const html = parts.map((p) => p.text).join('')
  const fromInput: boolean[] = []
  for (const p of parts) for (let k = 0; k < p.text.length; k++) fromInput.push(p.input)
  return { html, fromInput }
}

/** 上色：範本 = code；輸入只是文字 = data；輸入變成標籤 / script 內容 = injected */
export function toSegments(parts: Part[]): Segment[] {
  const { html, fromInput } = flatten(parts)
  const segments: Segment[] = []
  for (const t of tokenize(html)) {
    for (let i = t.start; i < t.end; i++) {
      const kind: SegKind = !fromInput[i] ? 'code' : t.type === 'text' ? 'data' : 'injected'
      const last = segments[segments.length - 1]
      if (last && last.kind === kind) last.text += html[i]
      else segments.push({ text: html[i], kind })
    }
  }
  return segments
}

export interface DomNode {
  tag?: string
  text?: string
  attrs: string[]
  /** 這個節點是從你的輸入長出來的 */
  injected: boolean
  /** innerHTML 插入的 <script>：存在，但不會執行 */
  inert?: boolean
  children: DomNode[]
}

const VOID = new Set(['img', 'br', 'hr', 'input', 'meta', 'link', 'source', 'area', 'base', 'col', 'embed', 'wbr'])

/** 簡化 DOM 樹（只為了畫圖） */
export function domTree(parts: Part[], kind: XssKind): DomNode {
  const { html, fromInput } = flatten(parts)
  const root: DomNode = { tag: 'body', attrs: [], injected: false, children: [] }
  const stack: DomNode[] = [root]
  for (const t of tokenize(html)) {
    const raw = html.slice(t.start, t.end)
    const injected = fromInput.slice(t.start, t.end).some(Boolean)
    const parent = stack[stack.length - 1]
    if (t.type !== 'tag') {
      if (raw.trim()) parent.children.push({ text: raw.trim(), attrs: [], injected, children: [] })
      continue
    }
    const close = raw.match(/^<\/([a-zA-Z][\w-]*)/)
    if (close) {
      const name = close[1].toLowerCase()
      const at = stack.map((n) => n.tag).lastIndexOf(name)
      if (at > 0) stack.length = at
      continue
    }
    const open = raw.match(/^<([a-zA-Z][\w-]*)/)
    if (!open) continue // <!-- --> 或 <!doctype>
    const tag = open[1].toLowerCase()
    const attrs = [...raw.slice(open[0].length).matchAll(/([^\s=/>"']+)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?/g)].map((m) => m[1])
    const node: DomNode = { tag, attrs, injected, children: [] }
    if (kind === 'dom' && tag === 'script' && injected) node.inert = true
    parent.children.push(node)
    if (!VOID.has(tag) && !raw.endsWith('/>')) stack.push(node)
  }
  return root
}
