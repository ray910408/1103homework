import { useId, useMemo, useState, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, SegmentLegend, SegmentView, Term, TextField,
  type Segment,
} from '../../components/ui.tsx'
import { BASE, DIRS, FLAG_CONFIG, NODES, dirname, download, inBase, type Mode, type ReadResult } from './engine.ts'
import s from './path.module.css'

const MODE_LABEL: Record<Mode, string> = { vulnerable: '漏洞版', filter: '過濾版', patched: '修補版' }

const fileName = (p: string) => p.slice(p.lastIndexOf('/') + 1)

// ---------- 目錄樹 ----------

const X0 = 40, DX = 28, Y0 = 30, ROW = 28, BW = 112
const depth = (p: string) => (p === '/' ? 0 : p.split('/').length - 1)
const POS = new Map(NODES.map((p, i) => [p, { x: X0 + depth(p) * DX, y: Y0 + i * ROW }]))
const LAST_Y = Y0 + (NODES.length - 1) * ROW
/** BASE 那一框：NODES 是目錄樹順序，BASE 底下的東西一定連在一起 */
const ZONE = { x: X0 + depth(BASE) * DX - 10, y: Y0 + NODES.indexOf(BASE) * ROW - 17, h: (NODES.filter(inBase).length - 1) * ROW + 34 }

function Tree({ r }: { r?: ReadResult }) {
  const steps = r?.steps ?? []

  // 每一步停在哪個節點（圓圈數字）；同一個節點走過兩次就往右排
  const seen = new Map<string, number>()
  const dots = steps.flatMap((st, i) => {
    const p = POS.get(st.path)
    if (!p) return []
    const k = seen.get(st.path) ?? 0
    seen.set(st.path, k + 1)
    return [{ x: p.x + BW + 14 + k * 20, y: p.y, n: i + 1 }]
  })

  const boxClass = (p: string) => {
    if (!seen.has(p)) return 'box'
    if (p === r?.full && r.leaked) return 'box-leak'
    return inBase(p) ? 'box-code' : 'box-attack'
  }

  // 往下走：沿著樹枝畫；往上（..）：沿著同一條樹枝反著畫回去
  const moves = steps.map((st, i) => {
    const a = i > 0 ? POS.get(steps[i - 1].path) : undefined
    const b = POS.get(st.path)
    if (!a || !b || a === b) return null
    if (st.kind === 'down') {
      return <path key={i} className={inBase(st.path) ? 'arrow-code' : 'arrow-attack'} d={`M${a.x + 12} ${a.y + 12}V${b.y}H${b.x - 2}`} />
    }
    if (st.kind !== 'up') return null
    return (
      <g key={i}>
        <path className="arrow-attack dash" d={`M${a.x - 2} ${a.y}H${b.x + 12}V${b.y + 14}`} />
        <text className="label-attack" x={b.x + 7} y={(a.y + b.y) / 2 + 4} textAnchor="end">..</text>
      </g>
    )
  })

  return (
    <svg className="diagram" viewBox={`0 0 520 ${LAST_Y + 75}`} role="img"
      aria-label={r ? `路徑一步步走過：${steps.map((st) => st.path).join(' → ')}` : `伺服器的資料夾結構：只有 ${BASE} 底下的檔案允許下載`}>
      <rect className={s.zone} x={ZONE.x} y={ZONE.y} width={510 - ZONE.x} height={ZONE.h} rx="10" />
      <text className={s.zoneLabel} x="500" y={ZONE.y + ZONE.h - 10} textAnchor="end">🔒 BASE：允許下載的範圍</text>

      {NODES.slice(1).map((p) => {
        const a = POS.get(dirname(p))
        const b = POS.get(p)
        return a && b && <path key={p} className={s.treeLine} d={`M${a.x + 12} ${a.y + 12}V${b.y}H${b.x}`} />
      })}

      {NODES.map((p) => {
        const b = POS.get(p)
        if (!b) return null
        return (
          <g key={p}>
            <rect className={boxClass(p)} x={b.x} y={b.y - 12} width={BW} height="24" rx="6" />
            <text className={s.name} x={b.x + 8} y={b.y + 5}>{p === '/' ? '/' : fileName(p) + (DIRS.has(p) ? '/' : '')}</text>
          </g>
        )
      })}

      {moves}

      {dots.map((d) => (
        <g key={d.n}>
          <circle className={s.hopDot} cx={d.x} cy={d.y} r="8" />
          <text className={s.hopNo} x={d.x} y={d.y + 4} textAnchor="middle">{d.n}</text>
        </g>
      ))}

      {r && r.outcome !== 'empty' && (
        <>
          <text className={s.status} x={X0} y={LAST_Y + 38}>📄 最後讀取：{r.full}{POS.has(r.full) ? '' : '（不存在）'}</text>
          <text className={r.escaped ? s.statusBad : s.statusOk} x={X0} y={LAST_Y + 62}>
            {r.escaped ? '🚨 跑出 BASE 了' : '✅ 還在 BASE 裡面'}
          </text>
        </>
      )}
    </svg>
  )
}

// ---------- 結果 ----------

function ResultLine({ r }: { r: ReadResult }) {
  if (r.outcome === 'empty') return <ResultBox tone="fail">請在 file= 後面輸入檔名</ResultBox>
  if (r.outcome === 'blocked') return <ResultBox tone="ok">🛡️ 擋下了（403）：解析後是 <code>{r.full}</code>，不在 <code>{BASE}/</code> 底下</ResultBox>
  if (r.outcome === 'ok') {
    return r.leaked
      ? <ResultBox tone="leak">🔓 資料外洩！伺服器把 <code>{r.full}</code> 的內容傳給你了</ResultBox>
      : <ResultBox tone="ok">✅ 下載成功：{fileName(r.full)}</ResultBox>
  }
  const why = r.outcome === 'isdir' ? '是資料夾，不是檔案'
    : r.outcome === 'notdir' ? '結尾多了 /，被當成資料夾讀，讀取失敗（ENOTDIR）' : '不存在（404）'
  return r.escaped
    ? <ResultBox tone="attack">🚨 跑出 BASE 了：伺服器去讀 <code>{r.full}</code>，只是它{why}</ResultBox>
    : <ResultBox tone="fail">❌ <code>{r.full}</code> {why}</ResultBox>
}

function Body({ r }: { r: ReadResult }) {
  if (!r.body) return null
  return <pre className={`${s.fetched} ${r.leaked ? s.fetchedLeak : ''}`} aria-label="下載到的檔案內容">{r.body}</pre>
}

/** 伺服器拼出來的路徑：../ 是「變成指令」的部分 */
function joined(file: string): Segment[] {
  const out: Segment[] = [{ kind: 'code', text: BASE + '/' }]
  for (const part of file.split(/(?<=\/)/)) {
    if (!part) continue
    const kind = part === '../' || part === '..' ? 'injected' : 'data'
    const last = out[out.length - 1]
    if (last.kind === kind) last.text += part
    else out.push({ kind, text: part })
  }
  return out
}

type Line = { tone: 'info' | 'attack' | 'leak' | 'safe'; text: ReactNode }

function trace(r: ReadResult): Line[] {
  if (r.outcome === 'empty') return []
  const lines = r.steps.map((st, i): Line => {
    const prev = r.steps[i - 1]
    if (st.kind === 'start') return { tone: 'info', text: <>從 BASE 資料夾 <code>{BASE}</code> 出發</> }
    if (st.kind === 'root') return { tone: 'attack', text: <><code>/</code> 開頭 → 直接跳到根目錄</> }
    const tone = inBase(st.path) ? 'info' : 'attack'
    if (st.kind === 'down') return { tone, text: <><code>{st.seg}</code> → 進到 <code>{st.path}</code></> }
    if (prev.path === '/') return { tone, text: <><code>..</code> → 已經在最上層 <code>/</code>，停在原地</> }
    return { tone, text: <><code>..</code> → 往上一層，到 <code>{st.path}</code>{inBase(prev.path) && !inBase(st.path) && '（⚠️ 離開 BASE 了）'}</> }
  })
  const tone = r.leaked ? 'leak' : r.escaped ? 'attack' : 'info'
  if (r.outcome === 'blocked') lines.push({ tone: 'safe', text: <>🛡️ <code>{r.full}</code> 不在 <code>{BASE}/</code> 底下 → 回傳 403，沒有讀檔</> })
  else if (r.outcome === 'ok') lines.push({ tone, text: <>📄 讀取 <code>{r.full}</code>，把內容回傳給你</> })
  else if (r.outcome === 'isdir') lines.push({ tone, text: <>📁 <code>{r.full}</code> 是資料夾 → 回傳錯誤</> })
  else if (r.outcome === 'notdir') lines.push({ tone, text: <>📁 結尾多了 <code>/</code>，系統把 <code>{r.full}</code> 當成資料夾 → 讀取失敗</> })
  else lines.push({ tone, text: <>❓ <code>{r.full}</code> 不存在 → 回傳 404</> })
  return lines
}

function insights(r: ReadResult) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  if (r.outcome === 'empty') return out
  if (r.escaped) {
    out.push({ tone: 'attack', text: <>伺服器只是把你的字串接在 BASE 後面。<code>..</code> 讓路徑往上爬，一路爬出了允許的範圍。網站只檢查「檔案在不在」，沒檢查「該不該給你」。</> })
  }
  if (r.steps.some((st, i) => st.kind === 'up' && r.steps[i - 1].path === '/')) {
    out.push({ tone: 'attack', text: <>到了最上層 <code>/</code>，多出來的 <code>..</code> 只會停在原地。所以攻擊者不用知道資料夾有幾層，多打幾個 <code>../</code> 就好。</> })
  }
  if (r.leaked && r.full.endsWith('config.js')) {
    out.push({ tone: 'leak', text: '設定檔裡常放資料庫密碼、金鑰。拿到它，攻擊者就能直接連進資料庫。' })
  }
  if (r.leaked && r.full === '/etc/passwd') {
    out.push({ tone: 'leak', text: <><code>/etc/passwd</code> 是 Linux 的帳號清單（現代系統的密碼其實不在這裡）。攻擊者常讀它，來證明「我能讀伺服器上任何檔案」。</> })
  }
  if (!r.escaped && r.outcome === 'ok') out.push({ tone: 'safe', text: '正常情況：檔案在 BASE 裡面，這正是下載功能原本的用途。' })
  return out
}

// ---------- 第 3 段：三種寫法 ----------

const CODE: Record<Mode, ReactNode> = {
  vulnerable: (
    <>
      <span className="tok-cm">{'// 把使用者給的檔名直接接在資料夾後面\n'}</span>
      {'const full = path.join(BASE, '}<span className="tok-var">file</span>{')\n'}
      {'res.send(fs.readFileSync(full))'}
    </>
  ),
  filter: (
    <>
      <span className="tok-cm">{'// ⚠️ 把 ../ 刪掉，但只從頭到尾掃一遍\n'}</span>
      {'const safe = '}<span className="tok-var">file</span>{'.replaceAll('}<span className="tok-str">'../'</span>{', '}<span className="tok-str">''</span>{')\n'}
      {'const full = path.join(BASE, safe)\n'}
      {'res.send(fs.readFileSync(full))'}
    </>
  ),
  patched: (
    <>
      <span className="tok-cm">{'// 先解析成最後真正要讀的路徑，再檢查它還在不在 BASE 裡\n'}</span>
      {'const full = path.resolve(BASE, '}<span className="tok-var">file</span>{')\n'}
      {'if (!'}<span className="tok-safe">{"full.startsWith(BASE + '/')"}</span>{')\n'}
      {'  return res.status(403).send('}<span className="tok-str">'禁止'</span>{')\n'}
      {'res.send(fs.readFileSync(full))'}
    </>
  ),
}

const MODE_HEAD: Record<Mode, ReactNode> = {
  vulnerable: <h3 className="head-vuln">❌ 漏洞版：直接拼接</h3>,
  filter: <h3 className="head-vuln">⚠️ 過濾版：刪掉 ../</h3>,
  patched: <h3 className="head-safe">✅ 修補版：檢查解析後的路徑</h3>,
}

function Resolved({ r, mode }: { r: ReadResult; mode: Mode }) {
  return (
    <p className={s.target}>
      {mode === 'filter' && <>過濾後的檔名：<b>{r.filtered || '（空）'}</b><br /></>}
      解析後的路徑：<b>{r.full}</b>{r.outcome === 'blocked' && '（檢查沒過，沒有讀取）'}
    </p>
  )
}

function ModeCard({ mode, file }: { mode: Mode; file: string }) {
  const r = useMemo(() => download(file, mode), [file, mode])
  return (
    <div className="card">
      {MODE_HEAD[mode]}
      <pre className="code-block">{CODE[mode]}</pre>
      <Resolved r={r} mode={mode} />
      <ResultLine r={r} />
    </div>
  )
}

// ---------- 挑戰 ----------

interface ChallengeDef {
  title: string
  mode: Mode
  goal: ReactNode
  hints: ReactNode[]
  why: ReactNode
}

const CHALLENGES: ChallengeDef[] = [
  {
    title: '挑戰 1：偷出網站設定檔',
    mode: 'vulnerable',
    goal: <>漏洞版。讀出 <code>/var/www/app/config.js</code>，拿到裡面的 <code>{'FLAG{...}'}</code>。</>,
    hints: [
      '看第 1 段的目錄樹：app/ 和 files/ 都在 www/ 底下，是「兄弟」資料夾。',
      <>從 files/ 先往上一層（<code>..</code>）回到 www/，再往下走進 app/。</>,
      <>解答：<code>../app/config.js</code></>,
    ],
    why: <>伺服器把你的輸入接成 <code>/var/www/files/../app/config.js</code>，系統解析時 <code>..</code> 抵銷掉 <code>files</code>，實際讀的是 <code>/var/www/app/config.js</code>。網站只檢查檔案在不在，沒檢查你有沒有權限拿。</>,
  },
  {
    title: '挑戰 2：繞過「刪掉 ../」的過濾',
    mode: 'filter',
    goal: <>過濾版（會把輸入裡的 <code>../</code> 全部刪掉）。一樣讀出 config.js 的 <code>{'FLAG{...}'}</code>。</>,
    hints: [
      '過濾只從頭到尾掃一遍，刪完就不再檢查。刪掉之後「剩下的字」，會不會又拼出一個 ../？',
      <>試試 <code>....//</code>：中間的 <code>../</code> 被刪掉後，剩下什麼？</>,
      <>解答：<code>....//app/config.js</code>（或 <code>..././app/config.js</code>）</>,
    ],
    why: <><code>....//</code> 中間的 <code>../</code> 被刪掉，左右剩下的 <code>..</code> 和 <code>/</code> 合起來剛好又是 <code>../</code>。「把危險字串刪掉」這種過濾很難寫對；修補版改成檢查「解析後的最終路徑」，字串怎麼變形都沒用。</>,
  },
]

function Challenge({ def }: { def: ChallengeDef }) {
  const [file, setFile] = useState('')
  const r = useMemo(() => download(file, def.mode), [file, def.mode])
  const id = useId()
  return (
    <ChallengeCard title={def.title} goal={def.goal} solved={!!r.body?.includes(FLAG_CONFIG)} hints={def.hints} why={def.why}>
      <TextField id={id} label={`file 參數（${MODE_LABEL[def.mode]}）`} value={file} onChange={setFile} placeholder="report.pdf" />
      {file && (
        <>
          <Resolved r={r} mode={def.mode} />
          <ResultLine r={r} />
          <Body r={r} />
        </>
      )}
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS = [
  { label: '正常下載 report.pdf', file: 'report.pdf' },
  { label: '往上一層 ../', file: '../' },
  { label: '../../../etc/passwd', file: '../../../etc/passwd' },
  { label: '多打幾個 ../', file: '../../../../../../etc/passwd' },
]

export default function PathPage() {
  const [file, setFile] = useState('report.pdf')
  const r = useMemo(() => download(file, 'vulnerable'), [file])

  return (
    <>
      <h1>Path Traversal（路徑穿越）</h1>
      <OwaspLine category="A01 Broken Access Control（存取控制失效）" cwe="CWE-22" />

      <Section no={1} title="情境：一個「給檔名就下載」的文件站">
        <p>
          這是假的「Demo 文件中心」。點下載連結時，網址會帶上檔名：<code>docs.test/download?file=report.pdf</code>。
          伺服器把檔名接在一個固定的資料夾（程式裡叫 <code>BASE</code>）後面，讀出檔案傳給你：
        </p>
        <SegmentView label="伺服器拼出來的路徑" segments={[{ kind: 'code', text: `${BASE}/` }, { kind: 'data', text: 'report.pdf' }]} />
        <Tree />
        <p>
          伺服器上的檔案像一棵樹，每個檔案都有一條
          <Term tip="檔案在硬碟上的「地址」，用 / 隔開每一層資料夾。例如 /var/www/files/report.pdf = 最上層 / → var → www → files → report.pdf。">路徑（path）</Term>
          。綠框是允許下載的範圍；旁邊的 <code>app/config.js</code> 是網站自己的設定檔，裡面有資料庫密碼。
          攻擊者的目標：用檔名欄位「爬出」綠框，讀到不該給人看的檔案。這種手法叫
          <Term tip="Path Traversal（又叫 Directory Traversal）：在檔名裡塞進 ../ 這類路徑符號，讓伺服器讀到指定資料夾以外的檔案。">Path Traversal（路徑穿越）</Term>
          。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：讓檔名爬出資料夾" lead={<>
        每打一個字，右邊就重新模擬一次（漏洞版）。關鍵符號是
        <Term tip="在路徑裡代表「上一層資料夾」。/var/www/files/.. 就等於 /var/www。">..</Term>
        。先按「正常下載」看正常長怎樣，再試其他按鈕。
      </>}>
        <div className="grid-2">
          <FakeSite url={`https://docs.test/download?file=${file}`}>
            <h3>📚 Demo 文件中心｜下載檔案</h3>
            <p className="hint">可以下載的檔案：report.pdf、manual.txt</p>
            <TextField id="path-file" label="file 參數（檔名）" value={file} onChange={setFile} />
            <ResultLine r={r} />
            <Body r={r} />
            <Presets items={PRESETS} onPick={(x) => setFile(x.file)} />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>🧩 伺服器拼出來的路徑</h3>
              <SegmentView segments={joined(file)} label="伺服器拼出來的路徑" />
              <SegmentLegend code="程式設計師寫的資料夾" injected="你的輸入，變成「往上一層」" />
              <p className={s.target}>系統解析後的路徑：<b>{r.full}</b></p>
            </div>
            <div>
              <h3>🌳 伺服器內部：路徑一步一步怎麼走</h3>
              <Tree r={r} />
              <p className="caption">藍色 = 還在 BASE 裡；紅色 = 跑出 BASE；黃色 = 外洩的檔案。圓圈數字是第幾步。</p>
            </div>
            <div>
              <h3>🧾 伺服器做了什麼</h3>
              <ol className={s.trace}>
                {trace(r).map((t, i) => <li key={i} className={s[t.tone]}>{t.text}</li>)}
              </ol>
            </div>
            <Insights items={insights(r)} />
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：同一個檔名，三種寫法" lead="下面沿用第 2 段的檔名。中間的過濾版「看起來修了」：試試 ../../../etc/passwd，看它把字串改成什麼。">
        <div className="grid-3">
          <ModeCard mode="vulnerable" file={file} />
          <ModeCard mode="filter" file={file} />
          <ModeCard mode="patched" file={file} />
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼過濾版擋不住、修補版擋得住？</strong>
            過濾版改的是「字串」：把 <code>../</code> 刪掉，但刪完剩下的字可能又拼出新的 <code>../</code>（挑戰 2）。
            修補版不管字串長怎樣，先讓系統把路徑
            <Term tip="正規化（normalize / resolve）：把 . 和 .. 算掉，得到最後真正指向的那個位置。例如 /var/www/files/../app → /var/www/app。">解析成最終位置</Term>
            ，再檢查它是不是還在 <code>{BASE}/</code> 底下。中間繞了幾圈都沒差，看的是終點。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>
              最好的做法是根本不讓使用者給路徑：改成檔案編號（<code>?id=2</code>），伺服器查表找到檔案，表裡沒有就拒絕（
              <Term tip="白名單：只列出「允許」的東西，其他一律拒絕。跟黑名單（只列出禁止的）相反，安全得多。">allowlist</Term>
              ）
            </li>
            <li>前綴比對要加結尾的 <code>/</code>：只比 <code>{BASE}</code> 的話，<code>{BASE}-backup/</code> 也會過關</li>
            <li>
              小心
              <Term tip="從最上層 / 開始寫的完整路徑，例如 /etc/passwd。跟它相對的是「相對路徑」（例如 ../app），要看從哪裡出發。">絕對路徑</Term>
              ：<code>path.resolve(BASE, '/etc/passwd')</code>、Python 的 <code>os.path.join(BASE, '/etc/passwd')</code> 都會丟掉前面的資料夾，直接變成 <code>/etc/passwd</code>。修補版檢查的是解析後的結果，所以一樣擋得住
            </li>
            <li>
              BASE 裡的
              <Term tip="符號連結（symlink）：像桌面捷徑，本身不是檔案，只是一個「指向別處」的路標。">捷徑（symlink）</Term>
              可能指向外面：真正的程式還要用 <code>fs.realpathSync(full)</code> 查出捷徑背後的真實位置，再檢查一次
            </li>
            <li>網站程式用低權限帳號執行，系統檔案本來就讀不到（最小權限）</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="卡住就按提示，提示會一個一個給。">
        {CHALLENGES.map((c) => <Challenge key={c.title} def={c} />)}
      </Section>
    </>
  )
}
