import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, Term, TextField,
} from '../../components/ui.tsx'
import {
  PATCHED, VULNERABLE, WORDLIST, createServer, defenseHolds, estimateMs, fmtClock, fmtDuration, runAttack,
  type Attempt, type AttackResult, type Reply,
} from './engine.ts'
import s from './brute.module.css'

type Item = { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }

/** 有耐心的攻擊者試完 10,000 組要多久（模擬時鐘，載入時算一次） */
const EST = { vulnerable: estimateMs(VULNERABLE), patched: estimateMs(PATCHED) }

const prefersReduced = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches

// ---------- 手動登入 ----------

function LoginLine({ r }: { r: Reply }) {
  if (r.kind === 'ok') {
    return r.user.secret
      ? <ResultBox tone="leak">🔓 登入成功：{r.user.username} 的管理後台。機密資料：{r.user.secret}</ResultBox>
      : <ResultBox tone="ok">✅ 登入成功：歡迎，{r.user.username}</ResultBox>
  }
  return <ResultBox tone="fail">❌ 帳號或密碼錯誤（想再試幾次都可以，伺服器不限次數）</ResultBox>
}

const PRESETS = [
  { label: '正常登入 alice', u: 'alice', p: 'Purple-Tiger-42' },
  { label: 'admin / 123456', u: 'admin', p: '123456' },
  { label: 'admin / password', u: 'admin', p: 'password' },
]

/** 漏洞版伺服器的登入表單；presets = 顯示快速填入按鈕 */
function LoginBox({ id, presets, onLogin }: { id: string; presets?: boolean; onLogin?: (r: Reply) => void }) {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [r, setR] = useState<Reply>()
  const submit = (u: string, p: string) => {
    const reply = createServer(VULNERABLE)(u, p, 0)
    setR(reply)
    onLogin?.(reply)
  }
  return (
    <form onSubmit={(e) => { e.preventDefault(); submit(u, p) }}>
      <TextField id={`${id}-u`} label="帳號" value={u} onChange={setU} />
      <TextField id={`${id}-p`} label="密碼（教學用，顯示明碼）" value={p} onChange={setP} />
      <button type="submit" className="primary" style={{ marginTop: '.75rem' }}>登入</button>
      {r && <LoginLine r={r} />}
      {presets && <Presets items={PRESETS} onPick={(x) => { setU(x.u); setP(x.p); submit(x.u, x.p) }} />}
    </form>
  )
}

// ---------- 攻擊腳本的嘗試紀錄 ----------

function replyText(a: Attempt) {
  const r = a.reply
  if (r.kind === 'ok') return '✔ 登入成功！'
  if (r.kind === 'locked') return a.correct ? '🔒 鎖定中，被拒絕（這組其實是對的！）' : '🔒 鎖定中，連密碼都沒檢查就拒絕'
  return r.lockedUntil ? `✖ 錯誤 → 🔒 帳號鎖定到 ${fmtClock(r.lockedUntil)}` : '✖ 帳號或密碼錯誤'
}

function rowClass(a: Attempt) {
  const r = a.reply
  if (r.kind === 'ok') return 'hit'
  if (r.kind === 'locked') return s.locked
  return r.lockedUntil ? s.lockNow : s.fail
}

function AttackLine({ r }: { r: AttackResult }) {
  const last = r.attempts.at(-1)
  if (r.cracked && last?.reply.kind === 'ok') {
    const secret = last.reply.user.secret
    return (
      <ResultBox tone={secret ? 'leak' : 'attack'}>
        {secret ? '🔓' : '🚨'} 第 {last.no} 次猜中 {r.username} 的密碼 <code>{last.password}</code>（花了 {fmtDuration(r.elapsedMs)}）
        {secret && <>，後台機密：{secret}</>}
      </ResultBox>
    )
  }
  if (r.lockedAt) {
    return <ResultBox tone="ok">🛡️ 攻擊失敗：第 {r.lockedAt} 次失敗後帳號就鎖定了{r.blockedCorrect && '，連正確密碼送來也被拒絕'}</ResultBox>
  }
  return <ResultBox tone="fail">❌ 字典試完了也沒猜中：{r.username} 的密碼不在常見密碼清單裡</ResultBox>
}

/** 一列一列重播嘗試紀錄；animate = false 或使用者偏好減少動態時，一次全部顯示 */
function Replay({ r, animate = false, after }: { r: AttackResult; animate?: boolean; after?: ReactNode }) {
  const total = r.attempts.length
  const [shown, setShown] = useState(() => (animate && !prefersReduced() ? 0 : total))
  const box = useRef<HTMLDivElement>(null)
  const visible = animate ? shown : total

  useEffect(() => {
    if (!animate) return
    const el = box.current
    if (el) el.scrollTop = el.scrollHeight
    if (shown >= total) return
    const id = setTimeout(() => { setShown((n) => n + 1) }, 150)
    return () => { clearTimeout(id) }
  }, [animate, shown, total])

  const rows = r.attempts.slice(0, visible)
  return (
    <div>
      <div className={s.stats}>
        <span>嘗試次數：<b>{visible}</b> / {total}</span>
        <span>模擬經過時間：<b>{fmtDuration(rows.at(-1)?.t ?? 0)}</b></span>
      </div>
      <div ref={box} className={s.timeline} tabIndex={0} role="region" aria-label={`${r.username} 的嘗試紀錄（可捲動）`}>
        <table className="data-table" aria-label={`攻擊腳本對 ${r.username} 的嘗試紀錄`}>
          <thead><tr><th>#</th><th>時間</th><th>試的密碼</th><th>伺服器回應</th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.no} className={rowClass(a)}>
                <td>{a.no}</td><td>{fmtClock(a.t)}</td><td>{a.password}</td><td>{replyText(a)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {visible >= total && <><AttackLine r={r} />{after}</>}
    </div>
  )
}

function attackInsights(r: AttackResult): Item[] {
  const out: Item[] = [{
    tone: 'attack',
    text: `伺服器從頭到尾沒擋：腳本 ${fmtDuration(r.elapsedMs)} 內送了 ${r.attempts.length} 次登入，每次都老實回答「錯」或「對」。`,
  }]
  if (r.cracked) {
    out.push({ tone: 'leak', text: <>{r.username} 的密碼 <code>{r.attempts.at(-1)?.password}</code> 就在常見密碼清單裡。攻擊者不用試遍所有組合，拿現成的清單就夠了。</> })
  } else {
    out.push({ tone: 'safe', text: `${r.username} 的密碼不在字典裡，字典攻擊就沒用。強密碼是對付暴力破解的另一半防線。` })
  }
  return out
}

function patchInsights(r: AttackResult): Item[] {
  const out: Item[] = []
  const correct = r.attempts.find((a) => a.correct)
  if (r.lockedAt) {
    out.push({ tone: 'safe', text: <>
      修補版在第 {r.lockedAt} 次失敗後鎖住 {r.username}，之後的猜測連密碼都不檢查
      {r.blockedCorrect && correct && <>，所以第 {correct.no} 次送出的正確密碼 <code>{correct.password}</code> 也被拒絕</>}。
    </> })
  }
  out.push({ tone: 'attack', text: '代價：任何人都能故意打錯 5 次，把真正的使用者鎖在門外。鎖定只是把攻擊拖慢，還要搭配 MFA 和強密碼政策，才是完整的修法。' })
  return out
}

function FlowDiagram() {
  const tries: [string, boolean][] = [['123456', false], ['password', false], ['sunshine', true]]
  return (
    <svg className="diagram" viewBox="0 0 820 190" role="img" aria-label="流程：攻擊腳本拿常見密碼清單一組一組送去登入，伺服器不限次數，猜中後就進到管理後台">
      <rect className="box-attack" x="10" y="35" width="190" height="110" rx="12" />
      <text className="d-title" x="105" y="75" textAnchor="middle">😈 攻擊腳本</text>
      <text className="d-sub" x="105" y="100" textAnchor="middle">拿常見密碼清單</text>
      <text className="d-sub" x="105" y="118" textAnchor="middle">一組一組自動送</text>

      {tries.map(([pw, ok], i) => {
        const y = 62 + i * 30
        return (
          <g key={pw}>
            <line className="arrow-attack" x1="205" y1={y} x2="305" y2={y} />
            <text className="label-attack" x="255" y={y - 6} textAnchor="middle">{pw} {ok ? '✔' : '✖'}</text>
          </g>
        )
      })}

      <rect className="box-code" x="315" y="35" width="200" height="110" rx="12" />
      <text className="d-title" x="415" y="75" textAnchor="middle">🖥️ login.test</text>
      <text className="d-sub" x="415" y="100" textAnchor="middle">每次都老實回答對或錯</text>
      <text className="d-sub" x="415" y="118" textAnchor="middle">不管你試了幾次</text>

      <line className="arrow-leak dash" x1="520" y1="90" x2="620" y2="90" />
      <text className="label-attack" x="570" y="78" textAnchor="middle">✔ 猜中</text>

      <rect className="box-leak" x="630" y="35" width="180" height="110" rx="12" />
      <text className="d-title" x="720" y="80" textAnchor="middle">🔧 管理後台</text>
      <text className="d-sub" x="720" y="105" textAnchor="middle">機密資料任你看</text>

      <text className="d-sub" x="410" y="178" textAnchor="middle">問題：伺服器不在乎你試了幾次。密碼只要夠常見，腳本幾秒內就猜得到。</text>
    </svg>
  )
}

// ---------- 挑戰 ----------

function CrackChallenge() {
  const [solved, setSolved] = useState(false)
  const id = useId()
  return (
    <ChallengeCard
      title="挑戰 1：登進 admin 的管理後台"
      goal={<>漏洞版。你不知道 admin 的密碼，登入它，拿到後台裡的 <code>{'FLAG{...}'}</code>。</>}
      solved={solved}
      hints={[
        'admin 很懶，用的是一個超常見的密碼。',
        '用第 2 段的攻擊腳本對 admin 跑一次，看第幾次猜中。',
        <>解答：帳號 <code>admin</code>，密碼 <code>sunshine</code>。</>,
      ]}
      why="伺服器不限次數，而 admin 的密碼就在常見密碼清單裡。真實的密碼字典有上百萬組，在不限次數的伺服器上，攻擊者開很多條連線一起試，很快就跑完。"
    >
      <LoginBox id={id} onLogin={(r) => setSolved(r.kind === 'ok' && r.user.username === 'admin')} />
    </ChallengeCard>
  )
}

const toInt = (v: string, lo: number, hi: number) => Math.min(hi, Math.max(lo, Math.round(Number(v)) || lo))

function DefenseChallenge() {
  const [n, setN] = useState('5')
  const [m, setM] = useState('15')
  const id = useId()
  const rule = { maxFails: toInt(n, 1, 20), lockMinutes: toInt(m, 0, 120) }
  const d = defenseHolds(rule)
  return (
    <ChallengeCard
      title="挑戰 2：換你當防守方，調整鎖定規則"
      goal={<>
        這支攻擊腳本更有耐心：<strong>被鎖就等解鎖再繼續猜，最多跑 1 小時</strong>。
        調整規則，讓它 1 小時內猜不到 admin 的密碼，而真正的使用者 alice（打錯 2 次、第 3 次打對）還登得進去。
      </>}
      solved={d.ok}
      hints={[
        'admin 的密碼是字典第 15 組，所以攻擊腳本會先失敗 14 次；alice 會先失敗 2 次。',
        '失敗上限要大於 2，alice 才不會被鎖。14 次失敗會觸發「14 ÷ 上限（取整數）」次鎖定，這些鎖定加起來至少要 60 分鐘。',
        '解答：失敗 5 次鎖 30 分鐘（鎖 2 次 × 30 = 60 分鐘），或失敗 3 次鎖 15 分鐘（鎖 4 次 × 15 = 60 分鐘）。',
      ]}
      why="失敗上限決定「多容易被鎖」：要比正常人打錯的次數多，又要少到讓腳本頻頻撞牆；鎖定時間決定每撞一次要等多久。但弱密碼只是被拖慢：攻擊者願意等一天，sunshine 還是會被猜中。所以還需要 MFA 和強密碼政策。"
    >
      <div className="challenge-inputs">
        <div>
          <label htmlFor={`${id}-n`}>連續失敗幾次就鎖定（1–20）</label>
          <input id={`${id}-n`} className={s.control} type="number" min={1} max={20} value={n} onChange={(e) => setN(e.target.value)} />
        </div>
        <div>
          <label htmlFor={`${id}-m`}>鎖定幾分鐘（0–120）</label>
          <input id={`${id}-m`} className={s.control} type="number" min={0} max={120} value={m} onChange={(e) => setM(e.target.value)} />
        </div>
      </div>
      <p className="caption">
        <strong>目前規則：連續失敗 {rule.maxFails} 次鎖 {rule.lockMinutes} 分鐘</strong>{rule.lockMinutes === 0 && '（等於不鎖）'}。
        預設值就是第 3 段的修補版（失敗 5 次鎖 15 分鐘）。
      </p>
      {d.attack.cracked
        ? <ResultBox tone="attack">😈 攻擊腳本：等了 {fmtDuration(d.attack.elapsedMs)} 就猜中 admin 的密碼</ResultBox>
        : <ResultBox tone="ok">😈 攻擊腳本：跑滿 1 小時只試到第 {d.attack.attempts.length} 組，沒猜中</ResultBox>}
      {d.alice.ok
        ? <ResultBox tone="ok">🙋 alice：打錯 2 次、第 3 次打對，順利登入</ResultBox>
        : <ResultBox tone="fail">🙋 alice：第 {rule.maxFails} 次打錯就被鎖，第 3 次打對也進不去</ResultBox>}
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

export default function BrutePage() {
  const [target, setTarget] = useState('admin')
  const [run, setRun] = useState(0)
  const vuln = useMemo(() => runAttack(target, WORDLIST, VULNERABLE), [target])
  const patched = useMemo(() => runAttack(target, WORDLIST, PATCHED), [target])

  return (
    <>
      <h1>Brute Force（暴力破解）</h1>
      <OwaspLine category="A07 Authentication Failures（身分驗證失效）" cwe="CWE-307" />

      <Section no={1} title="情境：一個可以無限次重試的登入頁">
        <p>
          這是假網站 login.test 的管理後台登入頁。密碼打錯，伺服器就回一句「帳號或密碼錯誤」，然後讓你再試，
          要試幾次都可以。
        </p>
        <FlowDiagram />
        <p>
          攻擊者的目標：不知道 admin 的密碼，就讓程式一組一組猜，直到猜中為止。這叫
          <Term tip="Brute Force：不靠程式漏洞，只靠「一直猜」。程式每秒能試好幾組，而人想的密碼又常常很好猜。">暴力破解（Brute Force）</Term>
          。如果拿來猜的是「最多人用的密碼」清單，就叫
          <Term tip="Dictionary Attack：不亂猜，而是照著「最多人用的密碼」或「外洩過的密碼」清單一組一組試，命中率高得多。">字典攻擊</Term>
          ：很多人的密碼就是 123456，根本不用試遍所有組合。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：讓腳本替你一直猜" lead="左邊可以自己手動猜；右邊是攻擊者的自動腳本。選好目標帳號，按「開始攻擊」，看伺服器怎麼回應每一次嘗試。">
        <div className="grid-2">
          <FakeSite url="https://login.test/admin">
            <h3>🔧 login.test｜管理後台登入</h3>
            <p className="hint">你知道一組帳號：alice / Purple-Tiger-42。admin 的密碼你不知道。</p>
            <LoginBox id="brute-play" presets />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>😈 攻擊腳本（在攻擊者自己的電腦上跑）</h3>
              <label htmlFor="brute-target">目標帳號</label>
              <select id="brute-target" className={s.control} value={target}
                onChange={(e) => { setTarget(e.target.value); setRun(0) }}>
                <option value="admin">admin（管理員）</option>
                <option value="alice">alice（一般使用者）</option>
              </select>
              <p className="caption">字典：{WORDLIST.length} 組最常見的密碼，照順序試</p>
              <div className={s.words}>{WORDLIST.map((w) => <code key={w}>{w}</code>)}</div>
              <button type="button" className="primary" onClick={() => setRun(run + 1)}>
                {run ? '↻ 再跑一次' : '▶ 開始攻擊'}
              </button>
            </div>
            {run > 0 && <Replay key={run} r={vuln} animate after={<Insights items={attackInsights(vuln)} />} />}
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：同一份字典，兩種伺服器" lead={<>
        下面用第 2 段選的目標（{target}），同一份字典分別打兩台伺服器。修補版多了
        <Term tip="Account Lockout：同一個帳號連續失敗太多次，就暫時不接受登入，連正確密碼也一樣。">帳號鎖定</Term>
        ：連續失敗 5 次，鎖 15 分鐘。
      </>}>
        <div className="grid-2">
          <div className="card">
            <h3 className="head-vuln">❌ 漏洞版：不限次數</h3>
            <pre className="code-block">
              <span className="tok-cm">{'// 對就放行，錯就回錯誤；可以無限次重試\n'}</span>
              {'if (checkPassword('}<span className="tok-var">username</span>{', '}<span className="tok-var">password</span>{'))\n  return ok()\n'}
              {'return fail('}<span className="tok-str">'帳號或密碼錯誤'</span>{')'}
            </pre>
            <Replay r={vuln} />
          </div>

          <div className="card">
            <h3 className="head-safe">✅ 修補版：失敗 5 次就鎖 15 分鐘</h3>
            <pre className="code-block">
              {'const a = attempts['}<span className="tok-var">username</span>{']\n'}
              <span className="tok-cm">{'// 鎖定中：連密碼都不檢查\n'}</span>
              {'if ('}<span className="tok-safe">now &lt; a.lockedUntil</span>{') return fail('}<span className="tok-str">'帳號已鎖定'</span>{')\n'}
              {'if (checkPassword('}<span className="tok-var">username</span>{', '}<span className="tok-var">password</span>{')) {\n  a.fails = 0; return ok()\n}\n'}
              {'if ('}<span className="tok-safe">++a.fails &gt;= 5</span>{') {\n  '}
              <span className="tok-safe">a.lockedUntil = now + 15 * MINUTE</span>{'\n  a.fails = 0\n}\n'}
              {'return fail('}<span className="tok-str">'帳號或密碼錯誤'</span>{')'}
            </pre>
            <Replay r={patched} />
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <h3 style={{ marginTop: 0 }}>⏱️ 如果字典有 10,000 組密碼，要試多久？</h3>
          <table className="data-table">
            <thead><tr><th>伺服器</th><th>規則</th><th>試完 10,000 組</th></tr></thead>
            <tbody>
              <tr className="hit"><td>❌ 漏洞版</td><td>不限次數</td><td>{fmtDuration(EST.vulnerable)}</td></tr>
              <tr><td>✅ 修補版</td><td>失敗 5 次鎖 15 分鐘</td><td>{fmtDuration(EST.patched)}</td></tr>
            </tbody>
          </table>
          <p className="caption">假設腳本每 0.2 秒送一次、被鎖就乖乖等解鎖再繼續。真實攻擊者會同時開很多條連線，不限次數的伺服器只會被試得更快。</p>
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼修補版擋得住？</strong>
            暴力破解靠的是「試很多次」。帳號鎖定把每個帳號能被猜的速度壓到每 15 分鐘 5 次：腳本衝得再快，
            第 6 次以後的猜測伺服器連看都不看。
            注意：這支腳本被鎖了還是照送；換成「被鎖就等解鎖再繼續」的腳本，同樣的規則大約 30 分鐘就會猜中 admin（見挑戰 2）。
          </p>
          <Insights items={patchInsights(patched)} />
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>
              <Term tip="Multi-Factor Authentication：除了密碼，還要第二個證明，例如手機 App 上的 6 位數驗證碼。密碼被猜中也登不進去。">MFA（多因素驗證）</Term>
              ：密碼被猜中也登不進去
            </li>
            <li>強密碼政策：註冊時就拒絕出現在常見 / 外洩密碼清單裡的密碼（CWE-521）</li>
            <li>
              依來源 IP 的
              <Term tip="Rate Limiting：限制同一個來源在一段時間內能送幾次請求，例如每分鐘最多 10 次登入。">速率限制</Term>
              ，加上漸進延遲（失敗越多次，回應越慢）：不必鎖帳號也能拖慢腳本
            </li>
            <li>記錄並告警大量失敗的登入（OWASP A09 Security Logging and Alerting Failures）</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：攻守各一題" lead="卡住就按提示，提示會一個一個給。">
        <CrackChallenge />
        <DefenseChallenge />
      </Section>
    </>
  )
}
