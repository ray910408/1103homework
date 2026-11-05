import { useId, useMemo, useState, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, Term, TextField,
} from '../../components/ui.tsx'
import {
  FLAG_ADMIN, FLAG_METADATA, INTERNAL, privateRange, serverFetch, type FetchResult, type Mode, type NodeId,
} from './engine.ts'
import s from './ssrf.module.css'

const NODE_LABEL: Record<NodeId, string> = {
  web: '圖床伺服器自己的硬碟',
  cdn: 'cdn.example.com',
  attacker: 'attacker.test（攻擊者的伺服器）',
  metadata: '雲端 metadata（169.254.169.254）',
  admin: '本機管理後台（127.0.0.1:8080）',
  redis: '內部 Redis（10.0.0.5:6379）',
}

const MODE_LABEL: Record<Mode, string> = { vulnerable: '漏洞版', blacklist: '黑名單版', patched: '修補版' }

// ---------- 拓撲圖 ----------

interface Box { x: number; y: number; w: number; h: number; title: string; sub: string }

const BOXES: Record<NodeId | 'user', Box> = {
  user: { x: 15, y: 40, w: 180, h: 70, title: '🧑 你（攻擊者）', sub: '在網頁貼上網址' },
  cdn: { x: 15, y: 140, w: 180, h: 70, title: '🖼️ cdn.example.com', sub: '正常的圖片網站' },
  attacker: { x: 15, y: 240, w: 180, h: 70, title: '😈 attacker.test', sub: '攻擊者自己的網域' },
  web: { x: 280, y: 130, w: 190, h: 84, title: '🖥️ 圖床伺服器', sub: '幫你抓網址' },
  metadata: { x: 525, y: 45, w: 265, h: 72, title: '☁️ 雲端 metadata', sub: '169.254.169.254（有雲端金鑰）' },
  admin: { x: 525, y: 135, w: 265, h: 72, title: '🔧 管理後台', sub: '127.0.0.1:8080（只給本機用）' },
  redis: { x: 525, y: 225, w: 265, h: 72, title: '🗄️ Redis', sub: '10.0.0.5:6379' },
}

/** 伺服器 → 節點 的線段座標 */
function edge(node: Exclude<NodeId, 'web'>) {
  const b = BOXES[node]
  return INTERNAL.has(node)
    ? { x1: 470, y1: 172, x2: b.x - 4, y2: b.y + b.h / 2 }
    : { x1: 280, y1: 172, x2: b.x + b.w + 4, y2: b.y + b.h / 2 }
}

function Topology({ r }: { r?: FetchResult }) {
  // 每個節點這次的狀態：被連到（reached）或 只在半路被擋（blocked）
  const reached = new Set<NodeId>()
  for (const h of r?.hops ?? []) if (h.node && (h.status === 'ok' || h.status === 'redirect')) reached.add(h.node)
  const last = r?.hops.at(-1)?.node

  const boxClass = (id: NodeId | 'user') => {
    if (id === 'user') return 'box'
    if (id === 'web') return reached.has('web') ? (r?.leaked ? 'box-leak' : 'box-attack') : 'box-code'
    if (!reached.has(id)) return 'box'
    if (id === last && r?.leaked) return 'box-leak'
    return INTERNAL.has(id) || id === 'attacker' ? 'box-attack' : 'box-code'
  }

  return (
    <svg className="diagram" viewBox="0 0 820 340" role="img"
      aria-label={r ? `這次請求的路徑：${r.hops.map((h) => (h.node ? NODE_LABEL[h.node] : h.host)).join(' → ') || '沒有送出'}` : '網路拓撲：攻擊者在外網，防火牆後面是圖床伺服器與內網服務'}>
      <text className={s.zoneLabel} x="105" y="25" textAnchor="middle">🌐 外網</text>
      <rect className={s.zone} x="258" y="32" width="552" height="285" rx="14" />
      <text className={s.zoneLabel} x="534" y="25" textAnchor="middle">🏢 公司內網（防火牆裡面）</text>
      <rect className={s.firewall} x="228" y="32" width="14" height="285" rx="3" />
      <text className={s.zoneLabel} x="235" y="335" textAnchor="middle">🧱 防火牆</text>

      {(Object.keys(BOXES) as (NodeId | 'user')[]).map((id) => {
        const b = BOXES[id]
        return (
          <g key={id}>
            <rect className={boxClass(id)} x={b.x} y={b.y} width={b.w} height={b.h} rx="12" />
            <text className="d-title" x={b.x + b.w / 2} y={b.y + b.h / 2 - 4} textAnchor="middle">{b.title}</text>
            <text className="d-sub" x={b.x + b.w / 2} y={b.y + b.h / 2 + 18} textAnchor="middle">{b.sub}</text>
          </g>
        )
      })}

      {/* 你 → 圖床：網站本來就對外開放 */}
      <line className="arrow-attack dash" x1="195" y1="80" x2="276" y2="152" />

      {!r && (
        <>
          {/* 直接連內網：被防火牆擋下 */}
          <line className="arrow-safe" x1="195" y1="55" x2="222" y2="55" />
          <text className={s.blockX} x="235" y="63" textAnchor="middle">✖</text>
          <text className="d-sub" x="105" y="130" textAnchor="middle">✖ 直接連內網會被防火牆擋</text>
          {(['metadata', 'admin', 'redis'] as const).map((n) => {
            const e = edge(n)
            return <line key={n} className="arrow-code dash" {...e} />
          })}
          <text className={s.note} x="375" y="240" textAnchor="middle">伺服器在牆裡面，</text>
          <text className={s.note} x="375" y="258" textAnchor="middle">連得到內網每一台機器</text>
        </>
      )}

      {r?.hops.map((h, i) => {
        if (!h.node) return null
        if (h.node === 'web') {
          return <text key={i} className={s.note} x="375" y="238" textAnchor="middle">📂 讀自己的檔案</text>
        }
        const e = edge(h.node)
        const mx = (e.x1 + e.x2) / 2
        const my = (e.y1 + e.y2) / 2
        if (h.status === 'blocked') {
          return (
            <g key={i}>
              <line className="arrow-safe" x1={e.x1} y1={e.y1} x2={mx} y2={my} />
              <text className={s.blockX} x={mx + (e.x2 > e.x1 ? 12 : -12)} y={my + 8} textAnchor="middle">✖</text>
            </g>
          )
        }
        if (h.status === 'error') return null
        const internal = INTERNAL.has(h.node)
        const lx = e.x1 + (e.x2 - e.x1) * 0.35
        const ly = e.y1 + (e.y2 - e.y1) * 0.35
        return (
          <g key={i}>
            <line className={`${internal ? 'arrow-attack' : 'arrow-code'} dash`} {...e} />
            <circle className={s.hopDot} cx={lx} cy={ly} r="9" />
            <text className={s.hopNo} x={lx} y={ly + 4} textAnchor="middle">{i + 1}</text>
          </g>
        )
      })}
    </svg>
  )
}

// ---------- 結果 ----------

function ResultLine({ r }: { r: FetchResult }) {
  const last = r.hops.filter((h) => h.status === 'ok' || h.status === 'redirect').at(-1)?.node
  const where = last ? NODE_LABEL[last] : ''
  if (r.outcome === 'blocked') return <ResultBox tone="ok">🛡️ 擋下了：{r.reason}</ResultBox>
  if (r.leaked) return <ResultBox tone="leak">🔓 資料外洩！伺服器把「{where}」的機密內容抓回來給你了</ResultBox>
  if (r.internal) return <ResultBox tone="attack">🚨 伺服器替你連進了內網：{where}</ResultBox>
  if (r.outcome === 'error') return <ResultBox tone="fail">❌ 匯入失敗：{r.reason}</ResultBox>
  if (r.response?.type === 'image') return <ResultBox tone="ok">✅ 匯入成功：cat.png 已存到你的相簿</ResultBox>
  return <ResultBox tone="fail">⚠️ 抓到了，但不是圖片（HTTP {r.response?.status}）</ResultBox>
}

/** 伺服器抓回來、回給你的內容 */
function Fetched({ r }: { r: FetchResult }) {
  if (!r.response) return null
  if (r.response.type === 'image') {
    return <div className={s.image}><span className={s.cat} aria-hidden="true">🐱</span><span>cat.png（假圖片）</span></div>
  }
  return <pre className={`${s.fetched} ${r.leaked ? s.fetchedLeak : ''}`} aria-label="伺服器抓回來的內容">{r.response.body}</pre>
}

/** 你打的字串 vs 伺服器實際連線的目標 */
function Target({ r }: { r: FetchResult }) {
  const conn = r.hops.filter((h) => h.ip).map((h) => `${h.ip}:${h.port}`).join(' → ')
  return (
    <p className={s.target}>
      你打的主機：<b>{r.rawHost || '—'}</b>　實際連線：<b>{conn || (r.hops[0]?.node === 'web' ? '伺服器自己的硬碟' : '—')}</b>
    </p>
  )
}

function insights(r: FetchResult) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  const nodes = r.hops.map((h) => h.node)
  const first = r.hops[0]

  if (r.userinfo) out.push({ tone: 'attack', text: <><code>@</code> 前面的「{r.userinfo}」只是帳號欄位，真正的主機是 <code>@</code> 後面那段。</> })
  if (r.rawHost && r.parsedHost && r.rawHost.toLowerCase() !== r.parsedHost) {
    out.push({ tone: 'attack', text: <>你打的是 <code>{r.rawHost}</code>，URL 解析器把它正規化成 <code>{r.parsedHost}</code>。只比對字串的檢查看到前者，伺服器真正連的是後者。</> })
  }
  if (first?.ip && first.host !== first.ip && privateRange(first.ip)) {
    out.push({ tone: 'attack', text: <>網域 <code>{first.host}</code> 看起來在外面，但 DNS 把它指向 <code>{first.ip}</code>（內網）。網域是攻擊者自己的，想指去哪就指去哪。</> })
  }
  const redirectAt = r.hops.findIndex((h) => h.status === 'redirect')
  const after = r.hops[redirectAt + 1]?.node
  if (redirectAt >= 0 && after) {
    out.push({ tone: 'attack', text: <>你給的網址在外網，但它回了 <code>302</code> 轉址，把伺服器導向「{NODE_LABEL[after]}」。</> })
  }
  if (nodes.includes('web')) out.push({ tone: 'attack', text: <><code>file://</code> 不是上網，是叫伺服器讀它自己硬碟上的檔案。</> })
  if (r.internal) out.push({ tone: 'attack', text: '防火牆擋得住外面的你，擋不住牆裡面的伺服器。伺服器替你連進了內網，這就是 SSRF。' })
  if (r.leaked && nodes.includes('metadata')) {
    out.push({ tone: 'leak', text: '雲端 metadata 會把這台主機的臨時金鑰交給任何連得到它的程式。拿到金鑰，就能用這台伺服器的身分操作整個雲端帳號。' })
  }
  if (r.leaked && nodes.includes('admin')) {
    out.push({ tone: 'leak', text: '管理後台以為「從本機來的請求一定是自己人」，所以沒有登入檢查。' })
  }
  if (r.outcome === 'blocked') out.push({ tone: 'safe', text: <>伺服器在送出請求前就擋下了：{r.reason}。</> })
  if (r.outcome === 'ok' && !r.internal && r.response?.type === 'image') {
    out.push({ tone: 'safe', text: '正常情況：伺服器到外網抓圖片，這正是這個功能原本的用途。' })
  }
  return out
}

// ---------- 第 3 段：三種寫法 ----------

const CODE: Record<Mode, ReactNode> = {
  vulnerable: (
    <>
      <span className="tok-cm">{'// 使用者給什麼網址，就抓什麼\n'}</span>
      {'const res = await fetch('}<span className="tok-var">userUrl</span>{')\n'}
      <span className="tok-cm">{'// fetch 預設還會自動跟隨轉址\n'}</span>
      {'return res.body'}
    </>
  ),
  blacklist: (
    <>
      {'const banned = ['}<span className="tok-str">'localhost'</span>{', '}<span className="tok-str">'127.0.0.1'</span>{',\n  '}
      <span className="tok-str">'169.254.169.254'</span>{']\n'}
      <span className="tok-cm">{'// ⚠️ 比對的是「字串」，不是實際連線目標\n'}</span>
      {'if (banned.some((b) => '}<span className="tok-var">userUrl</span>{'.includes(b)))\n  throw '}<span className="tok-str">'禁止'</span>{'\n'}
      {'const res = await fetch('}<span className="tok-var">userUrl</span>{')'}
    </>
  ),
  patched: (
    <>
      {'const url = new URL('}<span className="tok-var">userUrl</span>{')\n'}
      {'if (!['}<span className="tok-str">'http:'</span>{', '}<span className="tok-str">'https:'</span>{'].includes(url.protocol))\n  throw '}<span className="tok-str">'禁止'</span>{'\n'}
      <span className="tok-cm">{'// 先解析成 IP，檢查「真正要連的 IP」\n'}</span>
      {'const ip = await dns.lookup(url.hostname)\n'}
      {'if ('}<span className="tok-safe">isPrivate(ip)</span>{') throw '}<span className="tok-str">'禁止'</span>{'\n'}
      {'const res = await fetch(url, { '}<span className="tok-safe">redirect: 'manual'</span>{' })\n'}
      <span className="tok-cm">{'// 有轉址？對新網址重做一次上面的檢查'}</span>
    </>
  ),
}

const MODE_HEAD: Record<Mode, ReactNode> = {
  vulnerable: <h3 className="head-vuln">❌ 漏洞版：照單全收</h3>,
  blacklist: <h3 className="head-vuln">⚠️ 黑名單版：只比對字串</h3>,
  patched: <h3 className="head-safe">✅ 修補版：檢查實際連線的 IP</h3>,
}

function ModeCard({ mode, url }: { mode: Mode; url: string }) {
  const r = useMemo(() => serverFetch(url, mode), [url, mode])
  return (
    <div className="card">
      {MODE_HEAD[mode]}
      <pre className="code-block">{CODE[mode]}</pre>
      <Target r={r} />
      <ResultLine r={r} />
    </div>
  )
}

// ---------- 挑戰 ----------

interface ChallengeDef {
  title: string
  mode: Mode
  goal: ReactNode
  check: (r: FetchResult) => boolean
  hints: ReactNode[]
  why: ReactNode
}

const CHALLENGES: ChallengeDef[] = [
  {
    title: '挑戰 1：偷出雲端金鑰',
    mode: 'vulnerable',
    goal: <>漏洞版。讓伺服器把雲端 metadata 裡的 SecretAccessKey（格式是 <code>{'FLAG{...}'}</code>）抓回來給你。</>,
    check: (r) => !!r.response?.body.includes(FLAG_METADATA),
    hints: [
      <>雲端主機上有個特殊的內網位址 <code>169.254.169.254</code>，叫 metadata 服務，裡面放著這台主機的臨時金鑰。</>,
      <>先抓 <code>http://169.254.169.254/latest/meta-data/</code> 看有哪些路徑，再一層一層往 <code>iam/security-credentials/</code> 找下去。</>,
      <>解答：<code>http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role</code></>,
    ],
    why: '伺服器在防火牆裡面，它替你連到只有內網才碰得到的 metadata 服務，把整台主機的雲端金鑰交到你手上。2019 年美國 Capital One 的資料外洩事件，就是用 SSRF 偷 metadata 金鑰開始的。',
  },
  {
    title: '挑戰 2：繞過黑名單，打開管理後台',
    mode: 'blacklist',
    goal: <>黑名單版（擋 <code>localhost</code>、<code>127.0.0.1</code>、<code>169.254.169.254</code>）。讓伺服器打開 <code>127.0.0.1:8080/admin</code>，拿到裡面的 <code>{'FLAG{...}'}</code>。</>,
    check: (r) => !!r.response?.body.includes(FLAG_ADMIN),
    hints: [
      '黑名單只比對你打的「字串」。同一個 IP，其實有很多種寫法。',
      <>IP 其實就是一個 32 位元的數字：<code>127.0.0.1</code> = 127×256³ + 1。URL 解析器也看得懂 <code>127.1</code>、<code>0x7f.1</code> 這種縮寫。</>,
      <>解答：<code>http://2130706433:8080/admin</code>（或 <code>http://127.1:8080/admin</code>、<code>http://[::1]:8080/admin</code>、<code>http://rebind.attacker.test:8080/admin</code>）</>,
    ],
    why: <>黑名單比對的是字串，你打的字串裡沒有 <code>127.0.0.1</code>；但 URL 解析器把它正規化成 <code>127.0.0.1</code>，伺服器實際連進了本機的管理後台。防禦要檢查「解析後真正要連的 IP」，而不是字串。</>,
  },
]

function Challenge({ def }: { def: ChallengeDef }) {
  const [url, setUrl] = useState('')
  const r = useMemo(() => (url.trim() ? serverFetch(url, def.mode) : undefined), [url, def.mode])
  const id = useId()
  return (
    <ChallengeCard title={def.title} goal={def.goal} solved={!!r && def.check(r)} hints={def.hints} why={def.why}>
      <TextField id={id} label={`圖片網址（${MODE_LABEL[def.mode]}）`} value={url} onChange={setUrl} placeholder="http://..." />
      {r && (
        <>
          <Target r={r} />
          <ResultLine r={r} />
          <Fetched r={r} />
        </>
      )}
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS = [
  { label: '正常圖片', url: 'https://cdn.example.com/cat.png' },
  { label: '雲端 metadata', url: 'http://169.254.169.254/latest/meta-data/' },
  { label: 'localhost 後台', url: 'http://localhost:8080/admin' },
  { label: '2130706433', url: 'http://2130706433:8080/admin' },
  { label: '302 轉址', url: 'http://redirect.attacker.test/r' },
  { label: 'file://', url: 'file:///etc/passwd' },
]

export default function SsrfPage() {
  const [url, setUrl] = useState('https://cdn.example.com/cat.png')
  const r = useMemo(() => serverFetch(url, 'vulnerable'), [url])

  return (
    <>
      <h1>SSRF（伺服器端請求偽造）</h1>
      <OwaspLine category="A01 Broken Access Control（存取控制失效）" cwe="CWE-918" />

      <Section no={1} title="情境：一個會「幫你抓網址」的圖床">
        <p>
          這是假的「Demo 圖床」。它有個方便的功能：貼上圖片網址，<strong>伺服器</strong>就幫你下載回來。
          問題在於：「去抓網址」這個動作是伺服器做的，而伺服器站在公司的
          <Term tip="擋在公司網路門口的守衛：外面的人連不進內網，但牆裡面的機器可以互相連線，也可以往外連。">防火牆</Term>
          裡面。
        </p>
        <Topology />
        <p>
          攻擊者的目標：自己連不進內網，就騙伺服器替他連。這種手法叫
          <Term tip="Server-Side Request Forgery：偽造一個「由伺服器發出」的請求，讓伺服器替你連到你自己連不到的地方。">SSRF</Term>
          。內網裡最值錢的通常是雲端主機的
          <Term tip="雲端主機上的特殊服務，位址固定是 169.254.169.254，會回答「我是誰、我的臨時金鑰是什麼」。只有主機自己連得到。">metadata 服務</Term>
          ，裡面放著能操作整個雲端帳號的金鑰。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：叫伺服器替你連內網" lead="每打一個字，右邊就重新模擬一次（漏洞版）。先按「正常圖片」看正常長怎樣，再試其他按鈕。">
        <div className="grid-2">
          <FakeSite url="https://imghost.demo/import">
            <h3>🖼️ Demo 圖床｜用網址匯入圖片</h3>
            <p className="hint">貼上圖片網址，伺服器會幫你下載、存到相簿，並顯示抓到的內容。</p>
            <TextField id="ssrf-url" label="圖片網址" value={url} onChange={setUrl} />
            <ResultLine r={r} />
            <Fetched r={r} />
            <Presets items={PRESETS} onPick={(x) => setUrl(x.url)} />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>🖥️ 伺服器內部：這次請求走了哪裡</h3>
              <Topology r={r} />
              <p className="caption">紅線 = 連進內網；藍線 = 正常往外連；綠色 ✖ = 被擋下。圓圈數字是連線順序。</p>
            </div>
            <div>
              <h3>📍 你打的字串 vs 實際連線目標</h3>
              <table className="data-table">
                <tbody>
                  <tr><th>你打的主機</th><td>{r.rawHost || '—'}</td></tr>
                  <tr><th>URL 解析後</th><td>{r.parsedHost || '—'}</td></tr>
                  <tr className={r.internal ? 'hit' : undefined}>
                    <th>實際連線</th>
                    <td>{r.hops.map((h) => (h.ip ? `${h.ip}:${h.port}` : h.node === 'web' ? '自己的硬碟' : h.host)).join(' → ') || '—'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div>
              <h3>🧾 伺服器做了什麼</h3>
              <ol className={s.trace}>
                {r.steps.map((st, i) => <li key={i} className={s[st.tone]}>{st.text}</li>)}
              </ol>
            </div>
            <Insights items={insights(r)} />
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：同一個網址，三種寫法" lead="下面沿用第 2 段的網址。中間的黑名單版「看起來修了」，試試 2130706433 或 302 轉址，看它怎麼被繞過。">
        <div className="grid-3">
          <ModeCard mode="vulnerable" url={url} />
          <ModeCard mode="blacklist" url={url} />
          <ModeCard mode="patched" url={url} />
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼黑名單擋不住、修補版擋得住？</strong>
            黑名單比對的是你打的「字串」，但同一個目標有無數種寫法（<code>2130706433</code>、<code>127.1</code>、
            <code>[::1]</code>、指向內網的網域、轉址）。修補版不看字串，而是先把網址解析成
            <strong>真正要連線的 IP</strong>，再檢查它是不是內網位址，而且每次轉址都重新檢查一次。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>
              <Term tip="白名單：只列出「允許」的東西，其他一律拒絕。跟黑名單（只列出禁止的）相反，安全得多。">allowlist</Term>
              ：只允許 <code>cdn.example.com</code> 這類指定的圖片網域，比檢查內網 IP 更好
            </li>
            <li>連線時要用「檢查過的那個 IP」，不要再查一次 DNS（防 DNS rebinding：攻擊者讓 DNS 第一次回外網 IP、第二次回 127.0.0.1）</li>
            <li>雲端主機開啟 IMDSv2（要先拿 token 才能讀 metadata），並在網路層擋掉伺服器到 <code>169.254.169.254</code> 的流量</li>
            <li>不要把抓回來的原始內容直接回給使用者，只回「是不是圖片」</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="卡住就按提示，提示會一個一個給。">
        {CHALLENGES.map((c) => <Challenge key={c.title} def={c} />)}
      </Section>
    </>
  )
}
