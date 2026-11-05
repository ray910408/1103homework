import { useId, useState, type FormEvent, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, SegmentView, Term, TextField,
} from '../../components/ui.tsx'
import {
  FLAG_ORDER, getOrder, ME, MY_ID, USERS, updateEmail, type EmailResult, type Mode, type OrderResult,
} from './engine.ts'
import s from './idor.module.css'

// ---------- 小元件 ----------

/** 訂單編號輸入框 + ◀ ▶ 換上一號 / 下一號 */
function IdField({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const step = (d: number) => {
    if (!/^\d+$/.test(value.trim())) return onChange('1002')
    const n = Number(value) + d
    if (n >= 0 && Number.isSafeInteger(n)) onChange(String(n))
  }
  return (
    <div className={s.stepper}>
      <button type="button" onClick={() => step(-1)} aria-label="上一號訂單">◀</button>
      <TextField id={id} label="網址最後的訂單編號（改改看）" value={value} onChange={onChange} />
      <button type="button" onClick={() => step(1)} aria-label="下一號訂單">▶</button>
    </div>
  )
}

function ResultLine({ r }: { r: OrderResult }) {
  if (r.blocked) return <ResultBox tone="ok">🛡️ 擋下了：回 404 找不到訂單（不是你的，就當作不存在）</ResultBox>
  if (r.status === 404) return <ResultBox tone="fail">❌ 404：沒有 #{r.id} 這張訂單</ResultBox>
  if (r.leaked) return <ResultBox tone="leak">🔓 資料外洩！你看到了 {r.target?.owner} 的訂單：姓名、電話、地址全都有</ResultBox>
  return <ResultBox tone="ok">✅ 這是你自己的訂單</ResultBox>
}

/** 網站把訂單畫出來的樣子；別人的個資標成黃色 */
function OrderView({ r }: { r: OrderResult }) {
  const o = r.order
  if (!o) return null
  const cell = (v: string) => <td className={r.leaked ? 'leak-cell' : undefined}>{v}</td>
  return (
    <table className={`data-table ${s.order}`} aria-label={`訂單 #${o.id}`}>
      <tbody>
        <tr><th>訂單</th><td>#{o.id}</td></tr>
        <tr><th>商品</th><td>{o.item}（NT${o.total}）</td></tr>
        <tr><th>收件人</th>{cell(o.name)}</tr>
        <tr><th>電話</th>{cell(o.phone)}</tr>
        <tr><th>地址</th>{cell(o.address)}</tr>
        {o.note && <tr><th>備註</th>{cell(o.note)}</tr>}
      </tbody>
    </table>
  )
}

/** 圖解：「你是誰」和「你要什麼」兩個輸入，伺服器有沒有拿來比對 */
/** 只畫漏洞版（修補版的差別在第 3 段用程式碼對照） */
function Flow({ r }: { r: OrderResult }) {
  const t = r.target
  const id = r.id.length > 8 ? r.id.slice(0, 7) + '…' : r.id // 圖裡空間有限
  const check: { cls: string; text: string } = !t
    ? { cls: 'd-sub', text: `查無 #${id} → 404` }
    : { cls: r.leaked ? s.tAttack : 'd-sub', text: '⚠️ 沒檢查訂單是誰的' }
  const back = r.leaked ? { cls: 'arrow-leak', label: s.tLeak, text: `📦 回傳 ${t?.owner} 的訂單` }
    : r.mine ? { cls: 'arrow-code', label: 'label-code', text: '📦 回傳你的訂單' }
      : { cls: 'arrow-code', label: 'label-code', text: `❌ ${r.status}` }

  return (
    <svg className="diagram" viewBox="0 0 820 250" role="img"
      aria-label={`你帶著 session（你是 ${ME}）要求訂單 #${r.id}；伺服器：${check.text}；結果：${back.text}`}>
      <rect className="box" x="15" y="55" width="170" height="110" rx="12" />
      <text className="d-title" x="100" y="103" textAnchor="middle">🧑 你（瀏覽器）</text>
      <text className="d-sub" x="100" y="127" textAnchor="middle">登入身分：{ME}</text>

      <line className="arrow-code dash" x1="188" y1="85" x2="326" y2="85" />
      <text className="label-code" x="257" y="74" textAnchor="middle">🍪 你是誰：{ME}</text>
      <line className="arrow-attack dash" x1="188" y1="140" x2="326" y2="140" />
      <text className="label-attack" x="257" y="161" textAnchor="middle">🔢 你要什麼：#{id || '？'}</text>

      <rect className={r.leaked ? 'box-attack' : 'box-code'} x="330" y="35" width="220" height="150" rx="12" />
      <text className="d-title" x="440" y="70" textAnchor="middle">🖥️ shop.test 伺服器</text>
      <text className="d-sub" x="440" y="105" textAnchor="middle">✔ 有登入嗎？有（{ME}）</text>
      <text className={check.cls} x="440" y="135" textAnchor="middle">{check.text}</text>

      <line className="arrow-code" x1="552" y1="110" x2="646" y2="110" />
      <text className="label-code" x="599" y="100" textAnchor="middle">id={id}</text>
      <rect className={r.leaked ? 'box-leak' : 'box'} x="650" y="55" width="155" height="110" rx="12" />
      <text className="d-title" x="727" y="103" textAnchor="middle">🗄️ orders 表</text>
      <text className="d-sub" x="727" y="127" textAnchor="middle">{t ? `#${t.id} 的主人：${t.owner}` : `沒有 #${id}`}</text>

      <path className={`${back.cls} dash`} d="M440 187 V225 H100 V169" />
      <text className={back.label} x="270" y="217" textAnchor="middle">{back.text}</text>
    </svg>
  )
}

function insights(r: OrderResult) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  if (r.leaked) {
    out.push({ tone: 'attack', text: <>伺服器從 cookie 知道你是 {ME}，也查得到 #{r.id} 是 {r.target?.owner} 的，但它<strong>沒有把這兩件事拿來比對</strong>。</> })
    out.push({ tone: 'leak', text: '換一個號碼就是下一個人。寫個迴圈從 1 試到 99999，整個訂單資料庫的姓名、電話、地址就被搬走了。' })
  }
  if (r.mine) out.push({ tone: 'safe', text: '這張本來就是你的訂單，正常情況。不過伺服器其實沒檢查，只是剛好而已。' })
  if (r.status === 404 && !r.blocked) out.push({ tone: 'attack', text: '這個號碼沒有訂單。攻擊者會繼續換號碼，有回應的就是有資料。' })
  return out
}

// ---------- 第 3 段：兩種寫法 ----------

const CODE: Record<Mode, ReactNode> = {
  vulnerable: (
    <>
      <span className="tok-cm">{'// requireLogin 只確認「有登入」\n'}</span>
      {"app.get('/orders/:id', requireLogin, (req, res) => {\n  const order = db.get(\n    "}
      <span className="tok-str">'SELECT * FROM orders WHERE id = ?'</span>{',\n    '}
      <span className="tok-var">req.params.id</span>{')\n'}
      {'  if (!order) return res.sendStatus(404)\n'}
      {"  res.render('order', order)\n})"}
    </>
  ),
  patched: (
    <>
      <span className="tok-cm">{'// 多一個條件：訂單的主人必須是登入的人\n'}</span>
      {"app.get('/orders/:id', requireLogin, (req, res) => {\n  const order = db.get(\n    "}
      <span className="tok-str">'SELECT * FROM orders WHERE id = ?<span className="tok-safe"> AND owner = ?</span>'</span>{',\n    '}
      <span className="tok-var">req.params.id</span>{', '}<span className="tok-safe">req.session.user</span>{')\n'}
      <span className="tok-cm">{'  // 不是你的 → 跟不存在一樣回 404\n'}</span>
      {'  if (!order) return res.sendStatus(404)\n'}
      {"  res.render('order', order)\n})"}
    </>
  ),
}

const HEAD: Record<Mode, ReactNode> = {
  vulnerable: <h3 className="head-vuln">❌ 漏洞版：只檢查有沒有登入</h3>,
  patched: <h3 className="head-safe">✅ 修補版：再檢查訂單是不是你的</h3>,
}

function ModeCard({ mode, id }: { mode: Mode; id: string }) {
  const r = getOrder(id, mode)
  return (
    <div className="card">
      {HEAD[mode]}
      <pre className="code-block">{CODE[mode]}</pre>
      <p className={s.compare}>訂單 #{r.id || '？'} 的主人：<b>{r.target?.owner ?? '—'}</b>　登入的人：<b>{ME}</b></p>
      <ResultLine r={r} />
    </div>
  )
}

// ---------- 挑戰 ----------

function FindFlag() {
  const [id, setId] = useState('1002')
  const fid = useId()
  const r = getOrder(id, 'vulnerable')
  return (
    <ChallengeCard
      title="挑戰 1：找出管理員的測試訂單"
      goal={<>漏洞版。某張訂單的備註欄裡藏著 <code>{'FLAG{...}'}</code>，把它找出來。</>}
      solved={!!r.order?.note.includes(FLAG_ORDER)}
      hints={[
        '訂單編號是連號的：你的是 1002，前後的號碼通常也有人用。',
        '往小的方向找：網站剛開張時，管理員通常會先下一張「測試訂單」。',
        <>解答：把編號改成 <code>1000</code>。</>,
      ]}
      why={<>伺服器只確認你有登入，任何編號的訂單都交出來。像這樣一個號碼一個號碼試，叫
        <Term tip="Enumeration：把可能的值（編號、帳號）一個一個試過，看哪些有回應。">列舉（enumeration）</Term>
        ；寫個迴圈從 1 試到 99999，整個訂單資料庫就被搬走了。</>}
    >
      <IdField id={fid} value={id} onChange={setId} />
      <ResultLine r={r} />
      <OrderView r={r} />
    </ChallengeCard>
  )
}

function EmailLine({ r }: { r: EmailResult }) {
  if (r.status === 400) return <ResultBox tone="fail">❌ 400：編號或 Email 格式不對</ResultBox>
  if (r.status === 403) return <ResultBox tone="ok">🛡️ 403：你只能改自己的 Email</ResultBox>
  if (r.status === 404) return <ResultBox tone="fail">❌ 404：沒有這個使用者</ResultBox>
  if (r.takeover) return <ResultBox tone="attack">🚨 攻擊成功：{r.target?.username} 的 Email 被你改掉了</ResultBox>
  return <ResultBox tone="ok">✅ 你的 Email 已更新</ResultBox>
}

const ATTACKER_EMAIL = 'attacker@evil.test'

function TakeOver() {
  const [users, setUsers] = useState(USERS)
  const [uid, setUid] = useState(String(MY_ID))
  const [email, setEmail] = useState(ATTACKER_EMAIL)
  const [res, setRes] = useState<EmailResult>()
  const fid = useId()

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const r = updateEmail(users, uid, email, 'vulnerable')
    setRes(r)
    setUsers(r.users)
  }

  return (
    <ChallengeCard
      title="挑戰 2：改掉 bob 的 Email，接管他的帳號"
      goal={<>漏洞版。這是 alice 的「帳號設定」，按儲存會送出下面的請求。把 bob 的 Email 改成你的信箱 <code>attacker@evil.test</code>。</>}
      solved={users.find((u) => u.username === 'bob')?.email === ATTACKER_EMAIL}
      hints={[
        <>請求網址裡的 <code>{MY_ID}</code> 是什麼？伺服器靠它決定「要改誰的 Email」。</>,
        '看下面的會員表：bob 是幾號？',
        <>解答：使用者編號改成 <code>3</code>，按「儲存」。</>,
      ]}
      why={<>伺服器只看網址裡的編號決定改誰，沒比對「登入的人是不是 3 號」。bob 的 Email 變成你的之後，你去按「忘記密碼」，
        重設信就寄到你的信箱，整個帳號就是你的了（帳號接管）。修補版多一行
        <code>if (Number(req.params.id) !== req.session.userId) return res.sendStatus(403)</code>：編號不是登入的人，就不准改。</>}
    >
      <form onSubmit={submit}>
        <div className="challenge-inputs">
          <TextField id={`${fid}-id`} label="使用者編號（藏在請求網址裡）" value={uid} onChange={setUid} />
          <TextField id={`${fid}-email`} label="新 Email" value={email} onChange={setEmail} />
        </div>
        <SegmentView label="送出的請求" segments={[
          { kind: 'code', text: 'PUT /api/users/' },
          { kind: 'data', text: uid },
          { kind: 'code', text: '/email\n{ "email": "' },
          { kind: 'data', text: email },
          { kind: 'code', text: '" }' },
        ]} />
        <button type="submit" className={`primary ${s.submit}`}>儲存</button>
      </form>
      {res && <EmailLine r={res} />}
      <h4 className={s.godHead}>🗄️ 會員表（上帝視角，攻擊者看不到）</h4>
      <table className="data-table">
        <thead><tr><th>id</th><th>username</th><th>email</th></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} className={res?.takeover && res.target?.id === u.id ? 'hit' : undefined}>
              <td>{u.id}</td><td>{u.username}{u.id === MY_ID && '（你）'}</td><td>{u.email}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS = [
  { label: '我的訂單 1002', id: '1002' },
  { label: '上一號 1001', id: '1001' },
  { label: '下一號 1003', id: '1003' },
  { label: '不存在的 9999', id: '9999' },
]

export default function IdorPage() {
  const [id, setId] = useState('1002')
  const r = getOrder(id, 'vulnerable')
  const mine = getOrder('1002', 'vulnerable')

  return (
    <>
      <h1>IDOR（不安全的直接物件參考）</h1>
      <OwaspLine category="A01 Broken Access Control（存取控制失效）" cwe="CWE-639" />

      <Section no={1} title="情境：網址裡的訂單編號">
        <p>
          你在假的「Demo 商店」登入成 alice，打開「我的訂單」，網址最後面是訂單編號 <code>1002</code>。
          伺服器靠瀏覽器自動帶上的
          <Term tip="登入後伺服器發給瀏覽器的一張「號碼牌」，之後每個請求都會自動帶上，伺服器靠它認出你是誰。">session cookie</Term>
          知道你是 alice。
        </p>
        <FakeSite url="https://shop.test/orders/1002">
          <h3>🛒 Demo 商店｜我的訂單</h3>
          <OrderView r={mine} />
        </FakeSite>
        <Flow r={mine} />
        <p>
          伺服器每次收到請求，手上有兩個資訊：「你是誰」（cookie）和「你要什麼」（網址裡的編號）。
          攻擊者的目標：把 1002 改成別的號碼，看伺服器會不會把別人的訂單交出來。這種漏洞叫
          <Term tip="Insecure Direct Object Reference：網址或參數直接用資料的編號（例如訂單 1002），伺服器卻沒檢查你有沒有權限看這筆資料。">IDOR</Term>
          ，屬於
          <Term tip="Access Control：決定「誰可以看、可以改哪些資料」的規則。它失效是 OWASP Top 10:2025 的第一名。">存取控制（Access Control）</Term>
          失效。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：改網址裡的號碼" lead="改編號或按 ◀ ▶，右邊即時畫出伺服器的判斷（漏洞版）。">
        <div className="grid-2">
          <FakeSite url={`https://shop.test/orders/${id.trim()}`}>
            <h3>🛒 Demo 商店｜訂單明細</h3>
            <p className="hint">你登入的身分：alice</p>
            <IdField id="idor-id" value={id} onChange={setId} />
            <ResultLine r={r} />
            <OrderView r={r} />
            <Presets items={PRESETS} onPick={(x) => setId(x.id)} />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>🖥️ 伺服器內部：它比對了什麼</h3>
              <Flow r={r} />
              <p className="caption">藍線 = 伺服器自己認得的身分；紅線 = 你可以亂改的編號；黃線 = 外洩的資料。</p>
            </div>
            <Insights items={insights(r)} />
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：同一個號碼，兩種寫法" lead="下面沿用第 2 段的訂單編號。換成別人的號碼，再回來看兩邊的差別。">
        <div className="grid-2">
          <ModeCard mode="vulnerable" id={id} />
          <ModeCard mode="patched" id={id} />
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼修補版擋得住？</strong>
            伺服器每次都要問兩個問題：「你是誰」（
            <Term tip="Authentication：確認你是誰，例如登入、看 session cookie。">認證</Term>
            ）和「你可以碰這筆資料嗎」（
            <Term tip="Authorization：確認你有沒有權限做這件事，例如這張訂單是不是你的。">授權</Term>
            ）。漏洞版只問了第一個；修補版把「主人 = 登入的人」直接寫進查詢條件。
          </p>
          <p>
            注意：漏洞版已經用了參數化查詢，沒有 SQL Injection，還是被打穿。IDOR 的問題不在字串，而在「少了一個檢查」。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>
              把編號換成亂碼（
              <Term tip="Universally Unique Identifier：一長串隨機產生的編號，很難用猜的。">UUID</Term>
              ）不是修補：編號還是會從分享連結、記錄檔外流，伺服器一樣要檢查主人
            </li>
            <li>「我是誰」一律從 session 拿，不要相信前端送來的 userId</li>
            <li>權限檢查集中寫在一個地方（例如資料存取層），不要靠每支 API 自己記得加</li>
            <li>自動化測試：用 A 的帳號去讀、改 B 的資料，預期要失敗</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="卡住就按提示，提示會一個一個給。">
        <FindFlag />
        <TakeOver />
      </Section>
    </>
  )
}
