import initSqlJs, { type SqlJsStatic } from 'sql.js'
import wasmUrl from 'sql.js/dist/sql-wasm-browser.wasm?url'
import { useEffect, useId, useMemo, useState, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, SegmentLegend, SegmentView, Term, TextField,
} from '../../components/ui.tsx'
import { analyze, login, SEED, type Analysis, type LoginResult } from './engine.ts'
import s from './sqli.module.css'

let sqlPromise: Promise<SqlJsStatic> | undefined

function useSqlJs() {
  const [SQL, setSQL] = useState<SqlJsStatic>()
  const [err, setErr] = useState<string>()
  useEffect(() => {
    (sqlPromise ??= initSqlJs({ locateFile: () => wasmUrl })).then((m) => setSQL(() => m), (e) => setErr(String(e)))
  }, [])
  return { SQL, err }
}

const ADMIN_PW = SEED[0].password
const PASSWORDS = new Set(SEED.map((u) => u.password))

// ---------- 小元件 ----------

function SqlView({ analysis }: { analysis: Analysis }) {
  return <SegmentView segments={analysis.segments} label="實際送進資料庫的 SQL" />
}

function LoginFields({ id, u, p, setU, setP }: {
  id: string; u: string; p: string; setU: (v: string) => void; setP: (v: string) => void
}) {
  return (
    <>
      <TextField id={`${id}-u`} label="帳號" value={u} onChange={setU} />
      <TextField id={`${id}-p`} label="密碼（教學用，顯示明碼）" value={p} onChange={setP} />
    </>
  )
}

const isAttack = (a: Analysis) => a.segments.some((seg) => seg.kind === 'injected')

/** attack = 這次輸入是注入攻擊：成功要顯示紅色、被擋下要顯示綠色 */
function ResultLine({ r, attack }: { r?: LoginResult; attack: boolean }) {
  if (!r) return <ResultBox tone="fail">資料庫載入中…</ResultBox>
  if (r.error) return <ResultBox tone="attack">💥 伺服器錯誤：{r.error}</ResultBox>
  if (!r.user) {
    return attack
      ? <ResultBox tone="ok">🛡️ 攻擊被擋下：帳號或密碼錯誤</ResultBox>
      : <ResultBox tone="fail">❌ 帳號或密碼錯誤</ResultBox>
  }
  const welcome = <>歡迎，{r.user.username}（身分：{r.user.role}）</>
  if (PASSWORDS.has(r.user.username) || PASSWORDS.has(r.user.role)) return <ResultBox tone="leak">🔓 資料外洩！{welcome}</ResultBox>
  if (attack) return <ResultBox tone="attack">🚨 攻擊成功，沒用密碼就登入了：{welcome}</ResultBox>
  return <ResultBox tone="ok">✅ 登入成功：{welcome}</ResultBox>
}

function insights(a: Analysis, r: LoginResult | undefined, empty: boolean) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  const w = new Set(a.injectedWords)

  if (r?.error) out.push({ tone: 'attack', text: 'SQL 語法壞掉了。攻擊者一看到錯誤訊息，就知道輸入被直接拼進 SQL：這裡有注入點。' })
  if (isAttack(a)) out.push({ tone: 'attack', text: '你的輸入跳出了字串引號，變成 SQL 指令的一部分。' })
  else if (!empty) out.push({ tone: 'safe', text: '你的輸入都待在引號裡，只被當成要比對的資料。這是正常情況。' })
  if (w.has('--')) {
    out.push({ tone: 'attack', text: <>
      <code>--</code> 是 SQL 的註解符號，後面的 <code>{a.commentedCode || '（空）'}</code> 都不會執行
      {a.commentedCode.includes('password') && '：密碼檢查消失了'}。
    </> })
  }
  if (w.has('OR')) out.push({ tone: 'attack', text: <><code>OR</code> 接上一個永遠成立的條件，WHERE 就變成「每一列都符合」。</> })
  if (w.has('UNION')) out.push({ tone: 'leak', text: <><code>UNION SELECT</code> 把另一個查詢的結果接在後面，網頁會把它當成登入結果顯示出來。</> })
  if (w.has(';')) out.push({ tone: 'attack', text: <><code>;</code> 結束了上一條 SQL，後面可以接任何新指令（例如 <code>DROP TABLE</code> 刪表）。本頁每次查詢都重建資料庫，所以不會真的壞掉。</> })
  return out
}

function UsersTable({ r }: { r?: LoginResult }) {
  const hit = new Set(r?.rows.map((row) => String(row[0])))
  return (
    <div>
      <h3>🗄️ 資料庫裡的 users 表（上帝視角，攻擊者看不到）</h3>
      <table className="data-table">
        <thead><tr><th>id</th><th>username</th><th>password</th><th>role</th></tr></thead>
        <tbody>
          {SEED.map((u) => (
            <tr key={u.id} className={hit.has(String(u.id)) ? 'hit' : undefined}>
              <td>{u.id}</td><td>{u.username}</td><td>{'●'.repeat(8)}</td><td>{u.role}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="caption">淺紅色的列 = 這次查詢有比對到。</p>
    </div>
  )
}

function ReturnedRows({ r }: { r?: LoginResult }) {
  if (!r || r.error) return null
  return (
    <div>
      <h3>📦 資料庫回傳給伺服器的結果（{r.rows.length} 列）</h3>
      {r.rows.length > 0 && (
        <table className="data-table">
          <thead><tr><th>id</th><th>username</th><th>role</th></tr></thead>
          <tbody>
            {r.rows.map((row, i) => (
              <tr key={i}>
                {row.map((v, j) => (
                  <td key={j} className={PASSWORDS.has(String(v)) ? 'leak-cell' : undefined}>{String(v)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="caption">伺服器只看第一列：有資料就當作「登入成功」，並把那一列的 username 印在歡迎訊息裡。</p>
    </div>
  )
}

function FlowDiagram() {
  return (
    <svg className="diagram" viewBox="0 0 820 170" role="img" aria-label="流程：你輸入帳號密碼，伺服器把輸入黏進 SQL 字串，資料庫照著字串執行">
      <rect className="box" x="10" y="30" width="190" height="100" rx="12" />
      <text className="d-title" x="105" y="70" textAnchor="middle">🧑 你（瀏覽器）</text>
      <text className="d-sub" x="105" y="95" textAnchor="middle">在登入框輸入帳號密碼</text>

      <line className="arrow-attack dash" x1="205" y1="80" x2="305" y2="80" />
      <text className="label-attack" x="255" y="68" textAnchor="middle">alice / ●●●</text>

      <rect className="box-code" x="315" y="30" width="200" height="100" rx="12" />
      <text className="d-title" x="415" y="65" textAnchor="middle">🖥️ 網站伺服器</text>
      <text className="d-sub" x="415" y="90" textAnchor="middle">把輸入「黏」進</text>
      <text className="d-sub" x="415" y="108" textAnchor="middle">SQL 字串裡</text>

      <line className="arrow-code dash" x1="520" y1="80" x2="620" y2="80" />
      <text className="label-code" x="570" y="68" textAnchor="middle">SQL 查詢</text>

      <rect className="box" x="630" y="30" width="180" height="100" rx="12" />
      <text className="d-title" x="720" y="70" textAnchor="middle">🗄️ 資料庫</text>
      <text className="d-sub" x="720" y="95" textAnchor="middle">照著整串文字執行</text>

      <text className="d-sub" x="410" y="160" textAnchor="middle">問題：資料庫只收到一整串文字，分不出哪段是程式、哪段是你打的。</text>
    </svg>
  )
}

// ---------- 挑戰 ----------

interface ChallengeDef {
  title: string
  goal: ReactNode
  check: (r: LoginResult) => boolean
  hints: ReactNode[]
  why: ReactNode
}

const CHALLENGES: ChallengeDef[] = [
  {
    title: '挑戰 1：不知道密碼，登入 bob 的帳號',
    goal: '讓網站顯示「歡迎，bob」。你不知道 bob 的密碼。',
    check: (r) => r.user?.username === 'bob',
    hints: [
      '密碼檢查寫在 SQL 的後半段。如果能讓後半段不執行呢？',
      <>SQL 的 <code>--</code> 代表註解，它後面的東西都會被忽略。</>,
      <>解答：帳號輸入 <code>bob' --</code>，密碼隨便打。</>,
    ],
    why: <>你打的 <code>'</code> 把字串關掉，<code>--</code> 把後面的密碼檢查變成註解。資料庫實際執行的只剩 <code>WHERE username = 'bob'</code>。</>,
  },
  {
    title: '挑戰 2：偷出 admin 的密碼',
    goal: <>讓 admin 的密碼（格式是 <code>{'FLAG{...}'}</code>）出現在歡迎訊息裡。</>,
    check: (r) => !!r.user && (r.user.username.includes(ADMIN_PW) || r.user.role.includes(ADMIN_PW)),
    hints: [
      '網站會把查詢結果第 2 欄（username）印在「歡迎，＿＿」裡。如果第 2 欄裝的是密碼呢？',
      <><code>UNION SELECT</code> 可以把另一個查詢的結果接在後面，但欄位數要一樣（這裡是 3 欄：id, username, role）。</>,
      <>解答：帳號輸入 <code>' UNION SELECT 1, password, role FROM users WHERE username = 'admin' --</code></>,
    ],
    why: <>原本的查詢什麼都沒找到，<code>UNION</code> 接上的查詢把「admin 的密碼」放在 username 欄位，網站就把它當成你的名字印出來了。真實世界的攻擊者就是這樣一欄一欄把整個資料庫撈走。</>,
  },
]

function Challenge({ def, SQL }: { def: ChallengeDef; SQL?: SqlJsStatic }) {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const r = useMemo(() => SQL && login(SQL, u, p, 'vulnerable'), [SQL, u, p])
  const a = useMemo(() => analyze(u, p), [u, p])
  const id = useId()

  return (
    <ChallengeCard title={def.title} goal={def.goal} solved={!!r && def.check(r)} hints={def.hints} why={def.why}>
      <div className="challenge-inputs">
        <LoginFields id={id} u={u} p={p} setU={setU} setP={setP} />
      </div>
      <SqlView analysis={a} />
      <ResultLine r={r} attack={isAttack(a)} />
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS = [
  { label: '正常登入 alice', u: 'alice', p: 'alice123' },
  { label: '密碼打錯', u: 'alice', p: 'abc' },
  { label: "只打一個 '", u: "'", p: '' },
  { label: "' OR '1'='1' --", u: "' OR '1'='1' --", p: '' },
  { label: "'; DROP TABLE users; --", u: "'; DROP TABLE users; --", p: '' },
]

export default function SqliPage() {
  const { SQL, err } = useSqlJs()
  const [u, setU] = useState('alice')
  const [p, setP] = useState('alice123')

  const analysis = useMemo(() => analyze(u, p), [u, p])
  const vuln = useMemo(() => SQL && login(SQL, u, p, 'vulnerable'), [SQL, u, p])
  const patched = useMemo(() => SQL && login(SQL, u, p, 'patched'), [SQL, u, p])
  const attacking = isAttack(analysis)

  return (
    <>
      <h1>SQL Injection（SQL 注入）</h1>
      <OwaspLine category="A05 Injection（注入）" cwe="CWE-89" />
      {err && <ResultBox tone="attack">資料庫引擎載入失敗：{err}</ResultBox>}

      <Section no={1} title="情境：一個會「黏字串」的登入頁">
        <p>
          這是假的「Demo 銀行」會員登入頁。伺服器收到你的帳號密碼後，把它們直接黏進一句
          <Term tip="Structured Query Language，跟資料庫溝通的語言。例如：把帳號是 alice 的那一列找出來。">SQL</Term>
          查詢，再交給資料庫執行：
        </p>
        <SegmentView label="SQL 範本" segments={[
          { kind: 'code', text: "SELECT id, username, role FROM users WHERE username = '" },
          { kind: 'data', text: '你的帳號' },
          { kind: 'code', text: "' AND password = '" },
          { kind: 'data', text: '你的密碼' },
          { kind: 'code', text: "'" },
        ]} />
        <FlowDiagram />
        <p>
          攻擊者的目標：不知道密碼也能登入，甚至把整個資料庫的資料偷出來。這種把惡意內容塞進「資料」欄位、
          讓它被當成「指令」執行的手法，就叫
          <Term tip="Injection：程式以為收到的是資料，結果裡面藏了指令，被當成程式碼執行。">注入（Injection）</Term>。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：看你的輸入變成了什麼" lead="每打一個字，右邊就重新查詢一次。先按「正常登入」看正常長怎樣，再試其他按鈕，或自己打。">
        <div className="grid-2">
          <FakeSite url="https://bank.demo/login">
            <h3>🏦 Demo 銀行｜會員登入</h3>
            <p className="hint">你知道一組帳號：alice / alice123</p>
            <LoginFields id="play" u={u} p={p} setU={setU} setP={setP} />
            <ResultLine r={vuln} attack={attacking} />
            <Presets items={PRESETS} onPick={(x) => { setU(x.u); setP(x.p) }} />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>🖥️ 伺服器實際送進資料庫的 SQL</h3>
              <SqlView analysis={analysis} />
              <SegmentLegend code="程式設計師寫的 SQL" comment="被註解掉，不會執行" />
            </div>
            <Insights items={insights(analysis, vuln, !u && !p)} />
            <ReturnedRows r={vuln} />
            <UsersTable r={vuln} />
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：同一個輸入，兩種寫法" lead="下面沿用第 2 段你輸入的帳號密碼。換個攻擊字串，再回來看兩邊的差別。">
        <div className="grid-2">
          <div className="card">
            <h3 className="head-vuln">❌ 漏洞版：字串拼接</h3>
            <pre className="code-block">
              <span className="tok-cm">{'// 把輸入直接黏進 SQL 字串\n'}</span>
              {'const sql =\n  '}
              <span className="tok-str">"SELECT id, username, role FROM users "</span>{' +\n  '}
              <span className="tok-str">"WHERE username = '"</span>{' + '}<span className="tok-var">username</span>{' +\n  '}
              <span className="tok-str">"' AND password = '"</span>{' + '}<span className="tok-var">password</span>{' + '}<span className="tok-str">"'"</span>
              {'\ndb.exec(sql)'}
            </pre>
            <ResultLine r={vuln} attack={attacking} />
          </div>

          <div className="card">
            <h3 className="head-safe">✅ 修補版：參數化查詢</h3>
            <pre className="code-block">
              <span className="tok-cm">{'// SQL 結構先固定，輸入之後才填進 ? 的格子\n'}</span>
              {'const stmt = db.prepare(\n  '}
              <span className="tok-str">"SELECT id, username, role FROM users WHERE username = ? AND password = ?"</span>
              {'\n)\nstmt.bind(['}<span className="tok-var">username</span>{', '}<span className="tok-var">password</span>{'])'}
            </pre>
            <div className={s.params} aria-label="填進格子的參數">
              <div className={s.param}><b>? #1 ←</b><span>{u || '（空）'}</span></div>
              <div className={s.param}><b>? #2 ←</b><span>{p || '（空）'}</span></div>
            </div>
            <ResultLine r={patched} attack={attacking} />
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼修補版擋得住？</strong>
            <Term tip="Parameterized Query / Prepared Statement：先把 SQL 結構送給資料庫編譯好，使用者輸入之後才當作純資料填進去。">參數化查詢</Term>
            先把 SQL 的「結構」交給資料庫，之後才把你的輸入放進 <code>?</code> 的格子。不管你打了多少引號或
            <code>--</code>，都只會被當成「要比對的字串」，永遠不可能變成指令。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>不要把資料庫錯誤訊息直接顯示給使用者（第 2 段的 💥 就洩漏了 SQL 結構）</li>
            <li>網站用的資料庫帳號只給最小權限，例如不給 <code>DROP TABLE</code> 權限</li>
            <li>密碼用雜湊（hash）儲存，就算被撈出來也不是明文</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="以下都是漏洞版。卡住就按提示，提示會一個一個給。">
        {CHALLENGES.map((c) => <Challenge key={c.title} def={c} SQL={SQL} />)}
      </Section>
    </>
  )
}
