import { useId, useMemo, useState, type ReactNode } from 'react'
import { ChallengeCard, FakeSite, Insights, Presets, ResultBox, Section, Term, TextField } from '../../components/ui.tsx'
import {
  aliceRequest, ATTACKER, attackerHtml, attackRequest, CSRF_TOKEN, SESSION, setCookie, simulate, START_BALANCE, VULNERABLE,
  type Attack, type BankConfig, type RequestKind, type Trace,
} from './engine.ts'
import s from './csrf.module.css'

const money = (n: number) => `NT$${n.toLocaleString('zh-TW')}`

const KINDS: { kind: RequestKind; label: string; desc: string }[] = [
  { kind: 'form-post', label: '隱藏表單自動送出（POST）', desc: '頁面一打開，JavaScript 就自動送出看不見的表單' },
  { kind: 'img-get', label: '<img> 圖片（GET）', desc: '一張 0×0 的圖片，瀏覽器載入它時就會送出 GET 請求' },
  { kind: 'link-navigation', label: '誘騙點連結（GET 導覽）', desc: '「點我領獎」連結，點下去整個分頁跳到銀行' },
]

// ---------- 小元件 ----------

/** 攻擊者網頁的設定：攻擊方式 + 收款人 + 金額 */
function AttackEditor({ attack, onChange }: { attack: Attack; onChange: (a: Attack) => void }) {
  const id = useId()
  return (
    <>
      <fieldset className={s.kinds}>
        <legend>攻擊方式</legend>
        {KINDS.map((k) => (
          <label key={k.kind} className={s.kind}>
            <input type="radio" name={`${id}-kind`} checked={attack.kind === k.kind} onChange={() => onChange({ ...attack, kind: k.kind })} />
            <span><strong>{k.label}</strong><small>{k.desc}</small></span>
          </label>
        ))}
      </fieldset>
      <div className="challenge-inputs">
        <TextField id={`${id}-to`} label="收款人" value={attack.to} onChange={(to) => onChange({ ...attack, to })} />
        <TextField id={`${id}-amt`} label="金額" value={attack.amount} onChange={(amount) => onChange({ ...attack, amount })} />
      </div>
    </>
  )
}

/** 攻擊者網頁的 HTML：只當文字顯示，不會 render */
function HtmlView({ attack }: { attack: Attack }) {
  return (
    <pre className="code-block" aria-label="攻擊者網頁的 HTML 原始碼">
      <span className="tok-cm">{'<!-- evil.test/free-iphone 的原始碼（紅字 = 讓瀏覽器對 bank.demo 送請求的部分） -->\n'}</span>
      {attackerHtml(attack).map((l, i) => <span key={i} className={l.danger ? 'tok-var' : undefined}>{l.text + '\n'}</span>)}
    </pre>
  )
}

/** 瀏覽器實際送出的 HTTP request，Cookie 那行標紅 */
function RequestView({ t }: { t: Trace }) {
  return (
    <>
      <pre className={`code-block ${s.http}`} aria-label="瀏覽器送出的 HTTP request">
        <span className="tok-str">{t.startLine}</span>{'\n'}
        {t.headers.map((h) => (
          <span key={h.name} className={h.auto ? s.autoCookie : undefined}>
            {h.name}: {h.value}{h.auto && <em className={s.autoNote}>{'   ← 瀏覽器自動帶上的！'}</em>}{'\n'}
          </span>
        ))}
        {!t.cookie.sent && <span className={s.noCookie}>{'（沒有 Cookie：瀏覽器這次沒帶）\n'}</span>}
        {t.body && <>{'\n'}<span className="tok-var">{t.body}</span></>}
      </pre>
      <p className={s.reason}>🍪 {t.cookie.reason}</p>
    </>
  )
}

function Checks({ t }: { t: Trace }) {
  return (
    <ol className={s.checks} aria-label="銀行的判斷">
      {t.checks.map((c, i) => <li key={i} className={c.ok ? undefined : s.block}>{c.ok ? '✅' : '⛔'} {c.text}</li>)}
    </ol>
  )
}

const BLOCK_TEXT = { method: '轉帳 API 只接受 POST', samesite: '瀏覽器沒帶 cookie，銀行不知道你是誰', token: 'CSRF token 不對', input: '收款人或金額不合法' }

function Outcome({ t }: { t: Trace }) {
  if (t.transferred) {
    return t.initiator === 'evil.test'
      ? <ResultBox tone="attack">🚨 攻擊成功：Alice 在不知情的情況下轉了 {money(t.amount)} 給 {t.to}（餘額 {money(START_BALANCE)} → {money(t.balanceAfter)}）</ResultBox>
      : <ResultBox tone="ok">✅ Alice 自己轉帳成功：{money(t.amount)} 給 {t.to}</ResultBox>
  }
  const why = BLOCK_TEXT[t.blockedBy ?? 'input']
  return t.blockedBy === 'samesite' || t.blockedBy === 'token'
    ? <ResultBox tone="ok">🛡️ 攻擊被擋下（{t.status}）：{why}。Alice 的錢沒少。</ResultBox>
    : <ResultBox tone="fail">❌ 銀行拒絕（{t.status}）：{why}</ResultBox>
}

function insights(t: Trace, kind: RequestKind) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  if (kind === 'form-post') out.push({ tone: 'attack', text: '表單是隱藏的，頁面一打開就被 JavaScript 自動送出。Alice 連按鈕都不用按。' })
  if (kind === 'img-get') out.push({ tone: 'attack', text: <><code>{'<img>'}</code> 寬高是 0，Alice 什麼都看不到，完全不會發現。</> })
  if (kind === 'link-navigation') out.push({ tone: 'attack', text: '點連結會整頁跳到 bank.demo，Alice 也許會覺得怪，但請求已經送出去了。' })
  if (t.cookie.sent) {
    out.push({ tone: 'attack', text: '請求是 evil.test 發起的，但目的地是 bank.demo，所以瀏覽器自動帶上 bank.demo 的 cookie。瀏覽器不會問「是誰叫我送的？」' })
  } else {
    out.push({ tone: 'safe', text: t.cookie.reason })
  }
  if (t.blockedBy === 'method') out.push({ tone: 'safe', text: <>這家銀行的 <code>/transfer</code> 只接受 POST，<code>{'<img>'}</code> 和連結發出的都是 GET，所以被拒絕。換成表單試試。</> })
  if (t.transferred) out.push({ tone: 'attack', text: '銀行只認 cookie：cookie 對，就當作 Alice 本人。它分不出這個請求其實是 evil.test 偷偷發起的。' })
  if (t.headers.some((h) => h.name === 'Origin' && h.value.includes('evil'))) {
    out.push({ tone: 'leak', text: <>注意 <code>Origin: https://evil.test</code>：請求是從哪個網站來的，銀行其實看得到，只是沒檢查。</> })
  }
  return out
}

function FlowDiagram() {
  return (
    <svg className="diagram" viewBox="0 0 820 205" role="img"
      aria-label="流程：Alice 打開 evil.test，evil.test 的網頁讓 Alice 的瀏覽器對 bank.demo 送出轉帳請求，瀏覽器自動帶上 cookie，銀行以為是 Alice 本人">
      <rect className="box-attack" x="10" y="40" width="200" height="110" rx="12" />
      <text className="d-title" x="110" y="82" textAnchor="middle">😈 evil.test</text>
      <text className="d-sub" x="110" y="107" textAnchor="middle">「免費抽 iPhone」</text>
      <text className="d-sub" x="110" y="125" textAnchor="middle">裡面藏著轉帳表單</text>

      <line className="arrow-code" x1="308" y1="72" x2="216" y2="72" />
      <text className="label-code" x="262" y="62" textAnchor="middle">① 打開網頁</text>
      <line className="arrow-attack" x1="212" y1="118" x2="304" y2="118" />
      <text className="label-attack" x="258" y="140" textAnchor="middle">② 回傳 HTML</text>

      <rect className="box" x="310" y="40" width="200" height="110" rx="12" />
      <text className="d-title" x="410" y="80" textAnchor="middle">👩 Alice 的瀏覽器</text>
      <text className="d-sub" x="410" y="105" textAnchor="middle">🍪 存著 bank.demo 的</text>
      <text className="d-sub" x="410" y="123" textAnchor="middle">登入 cookie</text>

      <line className="arrow-attack dash" x1="514" y1="95" x2="604" y2="95" />
      <text className="label-attack" x="560" y="82" textAnchor="middle">③ 轉帳請求</text>
      <text className="label-attack" x="560" y="118" textAnchor="middle">+ 🍪 自動附上</text>

      <rect className="box-code" x="610" y="40" width="200" height="110" rx="12" />
      <text className="d-title" x="710" y="80" textAnchor="middle">🏦 bank.demo</text>
      <text className="d-sub" x="710" y="105" textAnchor="middle">④ cookie 正確</text>
      <text className="d-sub" x="710" y="123" textAnchor="middle">→ 以為是 Alice 本人</text>

      <text className="d-sub" x="410" y="190" textAnchor="middle">問題：瀏覽器只看「請求要送去哪」就帶 cookie，不管是哪個網站叫它送的。</text>
    </svg>
  )
}

// ---------- 挑戰 ----------

interface ChallengeDef {
  title: string
  goal: ReactNode
  cfg: BankConfig
  cfgText: string
  start: RequestKind
  check: (t: Trace) => boolean
  hints: ReactNode[]
  why: ReactNode
}

const CHALLENGES: ChallengeDef[] = [
  {
    title: '挑戰 1：讓 Alice 轉 10,000 元給 attacker',
    goal: <>Alice 打開你的網頁後，她的帳戶要轉 <strong>10,000</strong> 元給 <code>attacker</code>。</>,
    cfg: VULNERABLE,
    cfgText: 'SameSite=None、沒有 CSRF token、轉帳 API 只接受 POST',
    start: 'img-get',
    check: (t) => t.transferred && t.to === ATTACKER && t.amount === 10000,
    hints: [
      <>銀行的轉帳 API 只收 POST，<code>{'<img>'}</code> 和連結只會送出 GET。</>,
      '用隱藏表單，讓 JavaScript 一打開頁面就自動送出。SameSite=None 的 cookie 會被瀏覽器自動帶上。',
      <>解答：攻擊方式選「隱藏表單自動送出（POST）」，收款人 <code>attacker</code>、金額 <code>10000</code>。</>,
    ],
    why: '你的網頁讓 Alice 的瀏覽器送出 POST /transfer，瀏覽器看到目的地是 bank.demo，就自動帶上她的 session cookie。銀行只認 cookie，於是以為是 Alice 本人要轉帳。',
  },
  {
    title: '挑戰 2：銀行開了 SameSite=Lax，還是要轉成功',
    goal: <>讓 Alice 轉帳給 <code>attacker</code>（金額不限）。這次瀏覽器不會在跨站的表單和圖片請求帶 cookie。</>,
    cfg: { sameSite: 'Lax', checkToken: false, acceptGet: true },
    cfgText: 'SameSite=Lax、沒有 CSRF token、轉帳 API 也接受 GET',
    start: 'form-post',
    check: (t) => t.transferred && t.to === ATTACKER,
    hints: [
      'SameSite=Lax 會擋跨站的 POST 表單和 <img>，但有一種跨站請求它還是會帶 cookie。',
      'Lax 允許「頂層導覽」的 GET：使用者點連結、整個分頁跳過去的時候。這家銀行剛好也接受 GET /transfer。',
      <>解答：攻擊方式選「誘騙點連結（GET 導覽）」，收款人 <code>attacker</code>、金額隨便填（例如 <code>5000</code>）。</>,
    ],
    why: 'SameSite=Lax 為了讓一般連結正常運作（例如從 Google 點進網站還是登入狀態），頂層導覽的 GET 仍會帶 cookie。銀行讓 GET 也能轉帳，就留了洞。教訓：會改變狀態的操作只能用 POST，而且要搭配 CSRF token。',
  },
]

function Challenge({ def }: { def: ChallengeDef }) {
  const [attack, setAttack] = useState<Attack>({ kind: def.start, to: '', amount: '' })
  const [t, setT] = useState<Trace | null>(null)
  return (
    <ChallengeCard title={def.title} goal={def.goal} solved={!!t && def.check(t)} hints={def.hints} why={def.why}>
      <p className="hint">銀行設定：{def.cfgText}</p>
      <AttackEditor attack={attack} onChange={(a) => { setAttack(a); setT(null) }} />
      <button type="button" className={`primary ${s.run}`} onClick={() => setT(simulate(attackRequest(attack), def.cfg))}>
        ▶ 讓 Alice 打開這個網頁
      </button>
      {t && <><Outcome t={t} /><p className={s.reason}>🍪 {t.cookie.reason}</p></>}
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS: (Attack & { label: string })[] = [
  { label: '隱藏表單偷轉 5,000', kind: 'form-post', to: ATTACKER, amount: '5000' },
  { label: '<img> 偷轉 5,000', kind: 'img-get', to: ATTACKER, amount: '5000' },
  { label: '連結偷轉 5,000', kind: 'link-navigation', to: ATTACKER, amount: '5000' },
  { label: '轉超過餘額', kind: 'form-post', to: ATTACKER, amount: '999999' },
]

const sameAttack = (a: Attack, b: Attack) => a.kind === b.kind && a.to === b.to && a.amount === b.amount

export default function CsrfPage() {
  const [attack, setAttack] = useState<Attack>({ kind: 'form-post', to: ATTACKER, amount: '5000' })
  const [ran, setRan] = useState<Attack | null>(null)
  const [useToken, setUseToken] = useState(true)
  const [useLax, setUseLax] = useState(true)

  const trace = useMemo(() => ran && simulate(attackRequest(ran), VULNERABLE), [ran])
  const patchedCfg: BankConfig = { sameSite: useLax ? 'Lax' : 'None', checkToken: useToken, acceptGet: false }
  const vulnCmp = simulate(attackRequest(attack), VULNERABLE)
  const patchedCmp = simulate(attackRequest(attack), patchedCfg)
  const alice = simulate(aliceRequest('bob', '1000'), patchedCfg)
  const balance = trace?.balanceAfter ?? START_BALANCE

  return (
    <>
      <h1>CSRF（跨站請求偽造）</h1>

      <Section no={1} title="情境：Alice 只是打開了一個抽獎網頁">
        <p>
          Alice 剛登入「Demo 銀行」<code>bank.demo</code>，銀行給了她的瀏覽器一張
          <Term tip="網站存在你瀏覽器裡的小紙條。登入後網站給你一張「我是 Alice」的 session cookie，之後每次連到這個網站，瀏覽器都會自動附上它。">Cookie</Term>
          。之後她沒登出，又被騙打開攻擊者的網站 <code>evil.test</code>（「免費抽 iPhone」）。
        </p>
        <FlowDiagram />
        <p>
          攻擊者的網頁不用偷密碼，只要「讓 Alice 的瀏覽器替他送出轉帳請求」。瀏覽器會自動帶上 bank.demo 的 cookie，
          銀行就分不出這是 Alice 自己按的，還是別的網站偷偷叫瀏覽器送的。這就叫
          <Term tip="Cross-Site Request Forgery：利用使用者已登入的身分，從別的網站偽造出使用者本人的請求。">跨站請求偽造（CSRF）</Term>。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：寫一個會偷轉帳的網頁"
        lead={<>
          左上是攻擊者 evil.test 的網頁。選攻擊方式、填收款人和金額，再按「讓 Alice 打開這個網頁」。
          銀行目前是漏洞版：cookie 的 <Term tip="Cookie 的屬性，決定別的網站發起的請求要不要帶這個 cookie。None = 都帶、Lax = 只有點連結跳過去的 GET 才帶、Strict = 都不帶。">SameSite</Term>=None、表單沒有 <Term tip="CSRF token：銀行在自己的表單裡藏一個每個 session 都不同的隨機值，送出時伺服器會檢查它對不對。">CSRF token</Term>。
        </>}>
        <div className="grid-2">
          <div className={s.stack}>
            <FakeSite url="https://evil.test/free-iphone">
              <h3>😈 攻擊者的網頁編輯器</h3>
              <AttackEditor attack={attack} onChange={setAttack} />
              <HtmlView attack={attack} />
              <Presets items={PRESETS} onPick={(x) => setAttack({ kind: x.kind, to: x.to, amount: x.amount })} />
              <button type="button" className={`primary ${s.run}`} onClick={() => setRan(attack)}>▶ 讓 Alice 打開這個網頁</button>
              {ran && !sameAttack(ran, attack) && <p className={s.stale}>攻擊網頁改過了，再按一次「讓 Alice 打開這個網頁」。</p>}
            </FakeSite>

            <FakeSite url="https://bank.demo/account">
              <h3>🏦 Demo 銀行｜Alice 的帳戶</h3>
              <p className="hint">👩 Alice 已登入（這個分頁還開著）</p>
              <div className={`${s.balance} ${balance < START_BALANCE ? s.balanceDown : ''}`} aria-live="polite">
                餘額 {money(balance)}
              </div>
              <div className={s.jar}>🍪 瀏覽器存著：{setCookie('None').replace('Set-Cookie: ', '')}</div>
            </FakeSite>
          </div>

          <div className="card panel">
            {trace ? (
              <>
                <div>
                  <h3>📨 Alice 的瀏覽器實際送出的 HTTP request</h3>
                  <RequestView t={trace} />
                </div>
                <div>
                  <h3>🏦 銀行伺服器的判斷</h3>
                  <Checks t={trace} />
                  <Outcome t={trace} />
                </div>
                <Insights items={insights(trace, ran!.kind)} />
              </>
            ) : (
              <p className="hint">按下左邊的「▶ 讓 Alice 打開這個網頁」，這裡會顯示瀏覽器送出的請求，以及銀行怎麼判斷。</p>
            )}
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：讓銀行分得出「是不是自己人送的」" lead="下面沿用第 2 段攻擊者網頁目前的設定，自動比較兩個版本（不用按執行）。">
        <div className="grid-2">
          <div className="card">
            <h3 className="head-vuln">❌ 漏洞版：只認 cookie</h3>
            <pre className="code-block">
              {setCookie('None')}{'\n\n'}
              <span className="tok-cm">{'// 伺服器：有正確的 session cookie 就轉帳\n'}</span>
              {"app.post('/transfer', (req, res) => {\n  const user = sessions["}<span className="tok-var">req.cookies.session</span>{']\n  if (!user) return res.status(401)\n  transfer(user, req.body.to, req.body.amount)\n})'}
            </pre>
            <Outcome t={vulnCmp} />
          </div>

          <div className="card">
            <h3 className="head-safe">✅ 修補版：CSRF token + SameSite</h3>
            <div className={s.toggles} role="group" aria-label="修補版的防禦開關">
              <label><input type="checkbox" checked={useToken} onChange={(e) => setUseToken(e.target.checked)} /> CSRF token</label>
              <label><input type="checkbox" checked={useLax} onChange={(e) => setUseLax(e.target.checked)} /> SameSite=Lax</label>
            </div>
            <pre className="code-block">
              <span className={useLax ? 'tok-safe' : undefined}>{setCookie(useLax ? 'Lax' : 'None')}</span>{'\n\n'}
              <span className="tok-cm">{'<!-- bank.demo 自己的轉帳表單 -->\n'}</span>
              {'<form action="/transfer" method="POST">\n  <input name="to"> <input name="amount">\n'}
              {useToken && <span className="tok-safe">{`  <input type="hidden" name="csrf_token" value="${CSRF_TOKEN}">\n`}</span>}
              {'</form>'}
              {useToken && <>
                {'\n\n'}<span className="tok-cm">{'// 伺服器多一道檢查：token 要等於這個 session 的 token\n'}</span>
                <span className="tok-safe">{'if (req.body.csrf_token !== session.csrfToken) return res.status(403)'}</span>
              </>}
            </pre>
            <Outcome t={patchedCmp} />
            <p className={s.subhead}>Alice 自己在 bank.demo 轉 1,000 元給 bob：</p>
            <Outcome t={alice} />
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼攻擊者拿不到 token？</strong>
            CSRF token 藏在 bank.demo 自己的頁面裡。cookie 是瀏覽器自動帶的，但 token 必須寫在請求內容裡。evil.test 想讀 bank.demo 的頁面，
            會被瀏覽器的
            <Term tip="Same-Origin Policy：A 網站的 JavaScript 不能讀取 B 網站的內容。evil.test 可以叫瀏覽器「送」請求到 bank.demo，但讀不到回應。">同源政策</Term>
            擋下，所以攻擊者寫不出正確的 token。
          </p>
          <p>
            <strong>SameSite 是第二道保險：</strong>
            SameSite=Lax 時，別的網站發起的 POST 表單和圖片請求都不會帶 cookie。試試把上面的開關一個一個關掉，看哪一招又會成功。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>檢查 <code>Origin</code> / <code>Referer</code> header，不是自己網站來的就拒絕</li>
            <li>會改變狀態的操作（轉帳、改密碼）只用 POST，絕不接受 GET（挑戰 2 就是這個洞）</li>
            <li>重要操作再要求輸入密碼或 OTP 驗證碼</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="每題的銀行設定不一樣。改好攻擊網頁後按執行；卡住就按提示。">
        {CHALLENGES.map((c) => <Challenge key={c.title} def={c} />)}
      </Section>

      <p className="caption">本頁的 session（{SESSION}）、token 與餘額都是假資料；攻擊者網頁的 HTML 只當文字顯示，不會真的執行。</p>
    </>
  )
}
