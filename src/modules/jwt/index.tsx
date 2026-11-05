import { useEffect, useId, useState, type ReactNode } from 'react'
import {
  ChallengeCard, OwaspLine, FakeSite, Insights, Presets, ResultBox, Section, Term, TextField,
} from '../../components/ui.tsx'
import {
  b64urlDecode, buildToken, FLAG, GUEST_HEADER, GUEST_PAYLOAD, GUEST_TOKEN, STEP_ORDER, verify,
  type Mode, type StepId, type StepStatus, type VerifyResult,
} from './engine.ts'
import s from './jwt.module.css'

const MODES: Mode[] = ['decodeOnly', 'trustAlg', 'patched']
const MODE_LABEL: Record<Mode, string> = { decodeOnly: '漏洞 A：只 decode', trustAlg: '漏洞 B：相信 token 的 alg', patched: '修補版' }

/** 編輯器的內容：解碼後的 header / payload JSON + 簽章 */
interface Draft { header: string; payload: string; sig: string }

const json = (o: object) => JSON.stringify(o, null, 2)
const ORIG = GUEST_TOKEN.split('.')
const START: Draft = { header: json(GUEST_HEADER), payload: json(GUEST_PAYLOAD), sig: ORIG[2] }
const ADMIN_PAYLOAD = json({ ...GUEST_PAYLOAD, role: 'admin' })
const toToken = (d: Draft) => buildToken(d.header, d.payload, d.sig)

interface Verified { r?: VerifyResult; err?: boolean }

/**
 * verify 是 async（Web Crypto），結果放進 state。
 * 結果跟算它的 token + mode 綁在一起：還沒算完就回傳空的（⏳），舊結果不會配到新 token。
 */
function useVerify(token: string, mode: Mode): Verified {
  const key = `${mode}|${token}`
  const [state, setState] = useState<Verified & { key: string }>()
  useEffect(() => {
    let cancelled = false
    const k = `${mode}|${token}`
    verify(token, mode)
      .then((r) => { if (!cancelled) setState({ key: k, r }) })
      // 非 https 的區網網址沒有 crypto.subtle，不要永遠卡在 ⏳
      .catch(() => { if (!cancelled) setState({ key: k, err: true }) })
    return () => { cancelled = true }
  }, [token, mode])
  return state?.key === key ? state : {}
}

// ---------- token 三段 ----------

const PART = [
  { name: '① Header', note: '用哪種演算法' },
  { name: '② Payload', note: '你是誰、什麼身分' },
  { name: '③ Signature', note: '伺服器蓋的簽章' },
]

function TokenView({ token, decoded = false }: { token: string; decoded?: boolean }) {
  const parts = token.split('.')
  return (
    <>
      <table className={`data-table ${s.token}`} aria-label="JWT 的三段">
        <thead><tr><th>段落</th><th>token 裡的樣子（base64url）</th>{decoded && <th>解碼後</th>}</tr></thead>
        <tbody>
          {PART.map((p, i) => {
            const v = parts[i] ?? ''
            const changed = v !== ORIG[i]
            return (
              <tr key={p.name}>
                <th>{p.name}<small>{p.note}</small></th>
                <td>
                  <span className={changed ? 'seg-injected' : i === 2 ? 'seg-code' : 'seg-data'}>{v || '（空）'}</span>
                  {changed && <span className={s.changed}>✏️ 被改過</span>}
                </td>
                {decoded && (
                  <td>{i < 2 ? b64urlDecode(v) : <>
                    <Term tip="HMAC-SHA256：用密鑰計算簽章的演算法，JWT 裡寫作 HS256。">HMAC-SHA256</Term>(①.②, 🔑 密鑰)
                  </>}</td>
                )}
              </tr>
            )
          })}
        </tbody>
      </table>
      <p className="caption">
        <span className="seg-data">紅框</span> 誰都讀得到、改得了的資料　<span className="seg-code">藍字</span> 伺服器用密鑰算的簽章
        <span className="seg-injected">紅底</span> 被改過的段落。實際傳送時三段用「.」接成一行。
      </p>
    </>
  )
}

function TokenEditor({ id, draft, onChange }: { id: string; draft: Draft; onChange: (d: Draft) => void }) {
  return (
    <>
      <div className="challenge-inputs">
        <div>
          <label htmlFor={`${id}-h`}>① Header（JSON）</label>
          <textarea id={`${id}-h`} className={s.area} rows={5} spellCheck={false} value={draft.header}
            onChange={(e) => onChange({ ...draft, header: e.target.value })} />
        </div>
        <div>
          <label htmlFor={`${id}-p`}>② Payload（JSON）</label>
          <textarea id={`${id}-p`} className={s.area} rows={5} spellCheck={false} value={draft.payload}
            onChange={(e) => onChange({ ...draft, payload: e.target.value })} />
        </div>
      </div>
      <TextField id={`${id}-s`} label="③ Signature（簽章）" value={draft.sig} onChange={(v) => onChange({ ...draft, sig: v })} />
    </>
  )
}

// ---------- 伺服器檢查步驟圖 ----------

const STEP_TITLE: Record<StepId, string> = {
  decode: '① 解碼', alg: '② 讀 alg', hmac: '③ 用密鑰算簽章', compare: '④ 比對簽章', exp: '⑤ 檢查 exp', role: '⑥ 讀 role',
}
const STATUS: Record<StepStatus, { box: string; icon: string; cls: string }> = {
  pass: { box: 'box-code', icon: '✔', cls: s.stPass },
  fail: { box: 'box-safe', icon: '🛡️', cls: s.stFail },
  unsafe: { box: 'box-attack', icon: '⚠️', cls: s.stUnsafe },
  idle: { box: 'box', icon: '—', cls: s.stIdle },
}

function VerifyDiagram({ r, err }: { r?: VerifyResult; err?: boolean }) {
  const steps = r?.steps ?? STEP_ORDER.map((id) => ({ id, status: 'idle' as const, text: '' }))
  const end = err ? { box: 'box', text: '⚠️ 無法驗證（瀏覽器不支援 Web Crypto）' }
    : !r ? { box: 'box', text: '⏳ 驗證中…' }
    : !r.accepted ? { box: 'box-safe', text: '🛡️ 拒絕這個 token' }
      : r.admin ? { box: 'box-leak', text: '🔓 開門：把 /admin 的 FLAG 給你' }
        : { box: 'box-code', text: '🙂 登入成功，但你不是 admin' }
  return (
    <svg className="diagram" viewBox="0 0 520 384" role="img"
      aria-label={`伺服器檢查步驟：${steps.map((st) => `${STEP_TITLE[st.id]}，${st.text || '尚未執行'}`).join('；')}。結果：${end.text}`}>
      {steps.map((st, i) => {
        const y = 8 + i * 54
        const look = STATUS[st.status]
        return (
          <g key={st.id}>
            <rect className={look.box} x="10" y={y} width="500" height="38" rx="10" />
            <text className="d-title" x="24" y={y + 24}>{STEP_TITLE[st.id]}</text>
            <text className={look.cls} x="496" y={y + 24} textAnchor="end">{look.icon} {st.text}</text>
            <line className="arrow-code" x1="260" y1={y + 38} x2="260" y2={y + 52} />
          </g>
        )
      })}
      <rect className={end.box} x="10" y="332" width="500" height="44" rx="10" />
      <text className="d-title" x="260" y="359" textAnchor="middle">{end.text}</text>
    </svg>
  )
}

function SigTable({ r, sig, mode }: { r?: VerifyResult; sig: string; mode: Mode }) {
  return (
    <>
      <table className="data-table">
        <tbody>
          <tr><th>token 帶來的簽章</th><td>{sig || '（空）'}</td></tr>
          <tr><th>伺服器用 🔑 密鑰重算</th><td>{r?.expected ? `${r.expected.slice(0, 6)}…（只露前 6 碼）` : '—'}</td></tr>
          <tr className={r && !r.sigMatch ? 'hit' : undefined}>
            <th>一致嗎？</th>
            <td>{!r ? '—' : r.sigMatch ? '✔ 一致：header 和 payload 沒被改過' : '✖ 不一致：有人改過內容，或根本沒簽'}</td>
          </tr>
        </tbody>
      </table>
      {(mode === 'decodeOnly' || (mode === 'trustAlg' && r?.alg === 'none')) && <p className="caption">⚠️ 這張表是算給你看的：這台伺服器這次其實沒做這一步。</p>}
    </>
  )
}

// ---------- 結果與說明 ----------

/** attack = token 跟伺服器原本發的不一樣：被接受要顯示紅色、被擋下要顯示綠色 */
function ResultLine({ v: { r, err }, attack }: { v: Verified; attack: boolean }) {
  if (err) return <ResultBox tone="fail">⚠️ 這個瀏覽器環境沒有 Web Crypto（請用 https 或 localhost 開啟本站），沒辦法模擬簽章驗證。</ResultBox>
  if (!r) return <ResultBox tone="fail">⏳ 伺服器驗證中…</ResultBox>
  if (!r.accepted) {
    const failed = r.steps.find((st) => st.status === 'fail')
    const why = failed?.text
    if (failed?.id === 'decode') return <ResultBox tone="fail">❌ 400 token 格式錯誤：{why}</ResultBox>
    return attack
      ? <ResultBox tone="ok">🛡️ 擋下了：{why}</ResultBox>
      : <ResultBox tone="fail">❌ 401 拒絕：{why}</ResultBox>
  }
  if (r.admin) return <ResultBox tone="leak">🔓 /admin 打開了！伺服器相信你是 admin：{FLAG}</ResultBox>
  if (attack) return <ResultBox tone="attack">🚨 伺服器接受了被改過的 token：你是 {r.sub}（role: {r.role}）</ResultBox>
  return <ResultBox tone="fail">🙂 你是 {r.sub}（role: {r.role}）：403 沒有權限打開 /admin</ResultBox>
}

function insights(token: string, r: VerifyResult | undefined, mode: Mode) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  if (!r) return out
  const parts = token.split('.')
  const failed = r.steps.find((st) => st.status === 'fail')?.id

  if (parts[1] !== ORIG[1]) out.push({ tone: 'attack', text: '你改了 payload。它只是 base64url 編碼、不是加密，不需要任何密鑰就能改。' })
  if (r.alg === 'none') {
    out.push({ tone: 'attack', text: mode === 'trustAlg' && r.accepted
      ? <>header 寫 <code>alg: none</code>（不簽章），這台伺服器讓 token 自己決定用什麼演算法，就真的跳過了驗證。等於讓拿證件的人決定要不要查證件。</>
      : <>header 寫 <code>alg: none</code>：意思是「這張 token 沒有簽章，不用驗」。</> })
  }
  if (mode === 'decodeOnly' && r.accepted && !r.sigMatch) {
    out.push({ tone: 'attack', text: <>簽章早就對不上了，但這台伺服器只 <code>decode</code>、沒有 <code>verify</code>，payload 寫什麼它都信。</> })
  }
  if (failed === 'compare') out.push({ tone: 'safe', text: '伺服器用只有自己知道的密鑰重算簽章，跟 token 帶來的不一樣，代表內容被改過 → 拒絕。沒有密鑰，攻擊者算不出正確的簽章。' })
  if (failed === 'alg' && mode === 'patched') out.push({ tone: 'safe', text: <>修補版用哪種演算法是伺服器寫死的（<code>algorithms: ['HS256']</code>）。header 的 alg 只拿來跟這份允許清單比對，不在清單裡就拒絕。</> })
  if (r.admin) out.push({ tone: 'leak', text: '/admin 只看 payload 裡的 role。伺服器一相信被改過的 role，FLAG 就外洩了。' })
  if (token === GUEST_TOKEN && r.accepted) out.push({ tone: 'safe', text: '這是伺服器原本發給你的 token：簽章一致，你是 guest，沒有 admin 權限。這是正常情況。' })
  return out
}

function FlowDiagram() {
  return (
    <svg className="diagram" viewBox="0 0 820 170" role="img" aria-label="流程：瀏覽器每次請求都帶著 token，伺服器先驗簽章，再看 payload 裡的 role 決定能不能進 /admin">
      <rect className="box" x="10" y="30" width="190" height="100" rx="12" />
      <text className="d-title" x="105" y="70" textAnchor="middle">🧑 你（瀏覽器）</text>
      <text className="d-sub" x="105" y="95" textAnchor="middle">保管 token，每次都帶上</text>

      <line className="arrow-attack dash" x1="205" y1="80" x2="305" y2="80" />
      <text className="label-attack" x="255" y="68" textAnchor="middle">token=eyJ…</text>

      <rect className="box-code" x="315" y="30" width="210" height="100" rx="12" />
      <text className="d-title" x="420" y="62" textAnchor="middle">🖥️ api.test 伺服器</text>
      <text className="d-sub" x="420" y="88" textAnchor="middle">① 用 🔑 密鑰驗簽章</text>
      <text className="d-sub" x="420" y="108" textAnchor="middle">② 讀 payload 的 role</text>

      <line className="arrow-code dash" x1="530" y1="80" x2="630" y2="80" />
      <text className="label-code" x="580" y="68" textAnchor="middle">role = admin?</text>

      <rect className="box" x="640" y="30" width="170" height="100" rx="12" />
      <text className="d-title" x="725" y="70" textAnchor="middle">🔒 /admin</text>
      <text className="d-sub" x="725" y="95" textAnchor="middle">只給 admin，有 FLAG</text>

      <text className="d-sub" x="410" y="160" textAnchor="middle">伺服器不記得你是誰，完全照 token 上寫的身分辦事：簽章檢查是唯一的防線。</text>
    </svg>
  )
}

// ---------- 第 3 段：三種寫法 ----------

const CODE: Record<Mode, ReactNode> = {
  decodeOnly: (
    <>
      <span className="tok-cm">{'// 只把 token 解碼出來，沒檢查簽章\n'}</span>
      {'const payload = jwt.decode('}<span className="tok-var">token</span>{')\n'}
      {'if (payload.role === '}<span className="tok-str">'admin'</span>{')\n  showAdmin()'}
    </>
  ),
  trustAlg: (
    <>
      {'const { alg } = readHeader('}<span className="tok-var">token</span>{')\n'}
      <span className="tok-cm">{'// ⚠️ 用什麼演算法，由 token 自己說了算\n'}</span>
      {'const payload = alg === '}<span className="tok-str">'none'</span>{'\n  ? jwt.decode('}<span className="tok-var">token</span>{')  '}
      <span className="tok-cm">{'// 不驗簽章\n'}</span>
      {'  : jwt.verify('}<span className="tok-var">token</span>{', SECRET, { algorithms: [alg] })\n'}
      {'if (payload.role === '}<span className="tok-str">'admin'</span>{')\n  showAdmin()'}
    </>
  ),
  patched: (
    <>
      {'const payload = jwt.verify('}<span className="tok-var">token</span>{', SECRET, {\n'}
      {'  '}<span className="tok-safe">algorithms: ['HS256']</span>{',  '}<span className="tok-cm">{'// 伺服器自己決定\n'}</span>
      {'})  '}<span className="tok-cm">{'// 簽章不符、過期都會丟出錯誤（本站另外要求一定要有 exp）\n'}</span>
      {'if (payload.role === '}<span className="tok-str">'admin'</span>{')\n  showAdmin()'}
    </>
  ),
}

const MODE_HEAD: Record<Mode, ReactNode> = {
  decodeOnly: <h3 className="head-vuln">❌ 漏洞 A：只 decode，不 verify</h3>,
  trustAlg: <h3 className="head-vuln">⚠️ 漏洞 B：相信 header 的 alg</h3>,
  patched: <h3 className="head-safe">✅ 修補版：伺服器指定演算法</h3>,
}

function ModeCard({ mode, token }: { mode: Mode; token: string }) {
  const v = useVerify(token, mode)
  return (
    <div className="card">
      {MODE_HEAD[mode]}
      <pre className="code-block">{CODE[mode]}</pre>
      <ResultLine v={v} attack={token !== GUEST_TOKEN} />
    </div>
  )
}

// ---------- 挑戰 ----------

interface ChallengeDef { title: string; mode: Mode; goal: ReactNode; hints: ReactNode[]; why: ReactNode }

const CHALLENGES: ChallengeDef[] = [
  {
    title: '挑戰 1：把自己升級成 admin',
    mode: 'decodeOnly',
    goal: <>漏洞 A（只 decode）。改 token，讓 /admin 顯示 <code>{'FLAG{...}'}</code>。</>,
    hints: [
      '這台伺服器只把 token 解碼，沒有檢查簽章。你改什麼，它就信什麼。',
      <>payload 裡有個 <code>role</code> 欄位，現在是 <code>"user"</code>。</>,
      <>解答：把 payload 的 <code>"role": "user"</code> 改成 <code>"role": "admin"</code>，header 和簽章都不用動。</>,
    ],
    why: <>payload 只是 base64url 編碼，誰都能改。簽章本來抓得到竄改，但這台伺服器用的是 <code>decode</code> 而不是 <code>verify</code>，根本沒看簽章。</>,
  },
  {
    title: '挑戰 2：讓伺服器自己關掉驗證',
    mode: 'trustAlg',
    goal: <>漏洞 B（相信 token 的 alg）。這台會驗簽章，只改 role 會被擋。想辦法讓 /admin 顯示 <code>{'FLAG{...}'}</code>。</>,
    hints: [
      '先只改 role 試試：結果會說「簽章不符」。所以要讓它「根本不檢查簽章」。',
      <>它用哪種演算法驗簽章，是照 header 的 <code>alg</code> 決定的。JWT 規格裡有一個「不簽章」的演算法叫 <code>none</code>。</>,
      <>解答：header 改成 <code>{'{"alg": "none", "typ": "JWT"}'}</code>，payload 的 role 改成 <code>"admin"</code>，簽章欄位清空。</>,
    ],
    why: <>伺服器讓 token 自己決定「要用什麼方式檢查我」。你說 <code>none</code>，它就跳過簽章檢查。修補版把演算法寫死在伺服器端，header 的 alg 只拿來跟允許清單比對，<code>none</code> 不在清單裡就直接拒絕。</>,
  },
]

function Challenge({ def }: { def: ChallengeDef }) {
  const [draft, setDraft] = useState(START)
  const token = toToken(draft)
  const v = useVerify(token, def.mode)
  const id = useId()
  return (
    <ChallengeCard title={def.title} goal={def.goal} solved={!!v.r?.admin} hints={def.hints} why={def.why}>
      <TokenEditor id={id} draft={draft} onChange={setDraft} />
      <ResultLine v={v} attack={token !== GUEST_TOKEN} />
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS: (Draft & { label: string })[] = [
  { label: '原本的 token（guest）', ...START },
  { label: 'role 改成 admin', ...START, payload: ADMIN_PAYLOAD },
  { label: 'alg: none + 刪掉簽章', header: json({ alg: 'none', typ: 'JWT' }), payload: ADMIN_PAYLOAD, sig: '' },
]

export default function JwtPage() {
  const [draft, setDraft] = useState(START)
  const [mode, setMode] = useState<Mode>('decodeOnly')
  const token = toToken(draft)
  const v = useVerify(token, mode)
  const { r } = v
  const attack = token !== GUEST_TOKEN

  return (
    <>
      <h1>JWT（JSON Web Token）竄改</h1>
      <OwaspLine category="A04 Cryptographic Failures（加密機制失效）" cwe="CWE-347" />

      <Section no={1} title="情境：身分寫在你手上的那張 token 裡">
        <p>
          假網站 <code>api.test</code> 用
          <Term tip="JSON Web Token：一段「a.b.c」格式的字串，裡面寫著你是誰、什麼身分，最後附上伺服器的簽章。很多網站用它記住登入狀態。">JWT</Term>
          記住你是誰。你用 guest 登入後，伺服器把「你是誰、什麼身分」寫成一張 token，用只有它知道的
          <Term tip="只有伺服器知道的一串秘密文字。有它才算得出正確的簽章。">密鑰</Term>
          蓋上
          <Term tip="Signature：把內容跟密鑰一起算出來的一串亂碼。內容改一個字，簽章就完全不同；沒有密鑰的人算不出正確的簽章。">簽章</Term>
          ，交給你的瀏覽器保管：
        </p>
        <TokenView token={GUEST_TOKEN} decoded />
        <p className="caption">
          Header 的 <Term tip="algorithm：這張 token 用哪種演算法簽章。HS256 = 用密鑰算 HMAC-SHA256。">alg</Term> 說明用哪種演算法簽章；
          Payload 的 <Term tip="expiration time：到期時間（從 1970 年起算的秒數）。過了這個時間，token 就不能用。">exp</Term> 是到期時間。
        </p>
        <Insights items={[{ tone: 'leak', text: <>
          中間那段 payload 只是
          <Term tip="一種把任何資料轉成英數字的「編碼」方式，像換一種寫法，不是加密：任何人都能轉回原文。">base64url</Term>
          編碼，不是加密：任何人都讀得到、也改得了。能防止竄改的只有最後的簽章，前提是伺服器真的有檢查它。
        </> }]} />
        <FlowDiagram />
        <p>攻擊者的目標：你是 guest（<code>role: "user"</code>），想把 role 改成 admin，騙伺服器打開 <code>/admin</code>。</p>
      </Section>

      <Section no={2} title="動手攻擊：改 token，看伺服器怎麼檢查" lead="改左邊的 header / payload / 簽章，右邊同步畫出伺服器每一步的檢查。先選要攻擊哪台伺服器，再按下面的按鈕試試。">
        <div className={s.modes} role="group" aria-label="要攻擊哪台伺服器">
          <span>攻擊哪台伺服器：</span>
          {MODES.map((m) => (
            <button key={m} type="button" aria-pressed={m === mode} onClick={() => setMode(m)}>{MODE_LABEL[m]}</button>
          ))}
        </div>
        <div className="grid-2">
          <FakeSite url="https://api.test/admin">
            <h3>🔑 api.test｜管理後台</h3>
            <p className="hint">
              token 存在瀏覽器的 cookie 裡，打開
              <Term tip="瀏覽器內建的開發者工具（按 F12）。可以看到、也可以直接改 cookie 和網路請求。">DevTools</Term>
              就能改它。下面是解碼後的內容，改完會自動重新編碼。
            </p>
            <TokenEditor id="play" draft={draft} onChange={setDraft} />
            <TokenView token={token} />
            <ResultLine v={v} attack={attack} />
            <Presets items={PRESETS} onPick={(x) => setDraft({ header: x.header, payload: x.payload, sig: x.sig })} />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>🖥️ 伺服器怎麼檢查這張 token（{MODE_LABEL[mode]}）</h3>
              <VerifyDiagram r={r} err={v.err} />
              <p className="caption">藍 ✔ = 檢查通過；紅 ⚠️ = 該檢查卻沒檢查；綠 🛡️ = 在這一步擋下；灰 = 沒執行到。</p>
            </div>
            <div>
              <h3>✍️ 簽章比對（HMAC）</h3>
              <SigTable r={r} sig={token.split('.')[2] ?? ''} mode={mode} />
            </div>
            <Insights items={insights(token, r, mode)} />
          </div>
        </div>
      </Section>

      <Section no={3} title="修補：同一張 token，三種寫法" lead="下面沿用第 2 段的 token。試試「role 改成 admin」和「alg: none」，看三台伺服器的差別。">
        <div className="grid-3">
          {MODES.map((m) => <ModeCard key={m} mode={m} token={token} />)}
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼修補版擋得住？</strong>
            它每次都用密鑰重算簽章，而且<strong>用哪種演算法是伺服器自己決定的</strong>：header 的 alg 只拿來跟允許清單比對，永遠不會決定要用哪種演算法。
            沒有密鑰的人改了 payload，就算不出對得上的簽章；寫 <code>alg: none</code> 也直接被拒絕。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>用 <code>verify</code>，不要拿 <code>decode</code> 的結果做權限判斷（decode 只是解碼）</li>
            <li>密鑰要夠長、夠隨機，放在環境變數，不要寫死在程式碼或 git 裡</li>
            <li>exp 設短一點；payload 誰都看得到，不要放密碼或個資</li>
            <li>重要操作（例如刪帳號）在伺服器端再查一次資料庫裡的權限，不要只信 token</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="每個挑戰都從原本的 guest token 開始。卡住就按提示，提示會一個一個給。">
        {CHALLENGES.map((c) => <Challenge key={c.title} def={c} />)}
      </Section>
    </>
  )
}
