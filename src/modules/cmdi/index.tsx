import { useId, useMemo, useState, type ReactNode } from 'react'
import {
  ChallengeCard, FakeSite, Insights, OwaspLine, Presets, ResultBox, Section, SegmentLegend, SegmentView, Term, TextField,
} from '../../components/ui.tsx'
import { CWD, FLAG, USER, runArgv, runPing, type Mode, type Op, type Proc, type RunResult } from './engine.ts'
import s from './cmdi.module.css'

const MODE_LABEL: Record<Mode, string> = { vulnerable: '漏洞版', filter: '過濾版', patched: '修補版' }

const OP_MEAN: Record<Op, string> = {
  ';': '不管前一個成功或失敗，接著執行',
  '\n': '換行：跟 ; 一樣，接著執行',
  '&': '前一個丟到背景，接著執行',
  '&&': '前一個成功（結束碼 0）才執行',
  '||': '前一個失敗（結束碼不是 0）才執行',
  '|': '把前一個的輸出，接給下一個當輸入',
}
const opText = (op: Op) => (op === '\n' ? '換行' : op)

/** 所有真的有跑的 process（含 $( ) 裡的） */
const ranProcs = (ps: Proc[]): Proc[] => ps.flatMap((p) => [...ranProcs(p.subs), ...(p.ran ? [p] : [])])

// ---------- process 拆解圖 ----------

interface Row { p: Proc; depth: number; op: Op | null; fromSubs: boolean }

/** $( ) 裡的指令排在它的主人上面（先執行） */
function flatten(procs: Proc[], depth = 0): Row[] {
  return procs.flatMap((p) => {
    const group: Row[] = [...flatten(p.subs, depth + 1), { p, depth, op: null, fromSubs: p.subs.length > 0 }]
    group[0] = { ...group[0], op: p.op }
    return group
  })
}

const TOP = 34, RH = 44, GAP = 30, SHX = 2, SHW = 72, BX = 100, BW = 340, OX = 468, OW = 110, IND = 24
const circled = (n: number) => (n <= 20 ? String.fromCharCode(0x245f + n) : `${n}.`)
const fit = (t: string, n: number) => (t.length > n ? t.slice(0, n - 1) + '…' : t)

function ProcDiagram({ r }: { r: RunResult }) {
  const rows = flatten(r.procs)
  if (!rows.length) {
    return <p className="caption">{r.outcome === 'syntax' ? '🚫 shell 看不懂這一行（語法錯誤），一個指令都沒執行。' : '（還沒有指令執行）'}</p>
  }
  const y = (i: number) => TOP + i * (RH + GAP)
  const colH = rows.length * RH + (rows.length - 1) * GAP
  const H = TOP + colH + 14
  const ran = rows.filter((x) => x.p.ran).length

  return (
    <svg className="diagram" viewBox={`0 0 580 ${H}`} role="img"
      aria-label={`shell 把這一行拆成 ${rows.length} 個指令：` + rows.map((x) =>
        `${x.op ? opText(x.op) + ' ' : ''}${x.p.argv.join(' ')}（${x.p.ran ? `結束碼 ${x.p.status}` : '沒執行'}）`).join('，')}>
      <text className={s.colTitle} x={SHX + SHW / 2} y={18} textAnchor="middle">shell</text>
      <text className={s.colTitle} x={BX + BW / 2} y={18} textAnchor="middle">拆出來的指令（由上往下執行）</text>
      <text className={s.colTitle} x={OX + OW / 2} y={18} textAnchor="middle">回應</text>

      <rect className="box-code" x={SHX} y={TOP} width={SHW} height={colH} rx="8" />
      <text className="d-title" x={SHX + SHW / 2} y={TOP + colH / 2 - 2} textAnchor="middle">🐚 sh</text>
      <text className="d-sub" x={SHX + SHW / 2} y={TOP + colH / 2 + 16} textAnchor="middle">跑了 {ran} 個</text>

      <rect className={r.leaked ? 'box-leak' : 'box'} x={OX} y={TOP} width={OW} height={colH} rx="8" />
      <text className="d-title" x={OX + OW / 2} y={TOP + colH / 2 - 2} textAnchor="middle">📤 回應</text>
      <text className="d-sub" x={OX + OW / 2} y={TOP + colH / 2 + 16} textAnchor="middle">{r.leaked ? '⚠️ 含外洩資料' : '攻擊者看得到'}</text>

      {rows.map((row, i) => {
        const { p, depth } = row
        const bx = BX + depth * IND
        const bw = BW - depth * IND
        const cy = y(i) + RH / 2
        const box = !p.ran ? `box ${s.skipped}` : p.injected ? 'box-attack' : 'box-code'
        const status = !p.ran ? '⏭ 沒執行' : p.status === 0 ? '✅ 結束碼 0' : `❌ 結束碼 ${p.status}`
        const toOutput = p.ran && (p.stderr || (depth === 0 && p.stdout && !p.piped))
        const outClass = r.leaked && (p.injected || p.subs.length) ? 'arrow-leak' : p.injected ? 'arrow-attack' : 'arrow-code'
        const gapLabel = row.fromSubs ? '⤴ 上面 $( ) 的輸出，塞回這個指令的參數'
          : i > 0 && row.op ? `${opText(row.op)}  ${OP_MEAN[row.op]}` : null
        const linked = i > 0 && (row.fromSubs || row.op === '|')
        return (
          <g key={i}>
            {gapLabel && <text className="label-attack" x={BX + 4} y={y(i) - 10}>{gapLabel}</text>}
            {linked && <path className="arrow-attack" d={`M${BX + BW - 30} ${y(i) - GAP} V${y(i) - 3}`} />}
            <path className={p.injected ? 'arrow-attack' : 'arrow-code'} d={`M${SHX + SHW} ${cy} H${bx - 3}`} />
            <rect className={box} x={bx} y={y(i)} width={bw} height={RH} rx="6">
              <title>{p.argv.join(' ')}</title>
            </rect>
            <text className={s.argv} x={bx + 10} y={cy + 5}>{circled(i + 1)} {fit(p.argv.join(' '), Math.floor((bw - 120) / 7.8))}</text>
            <text className={s.status} x={bx + bw - 8} y={cy + 5} textAnchor="end">{status}</text>
            {toOutput && <path className={outClass} d={`M${BX + BW} ${cy} H${OX - 3}`} />}
          </g>
        )
      })}
    </svg>
  )
}

// ---------- 結果 ----------

function ResultLine({ r }: { r: RunResult }) {
  if (r.outcome === 'empty') return <ResultBox tone="fail">請輸入要 ping 的 IP 或主機名稱</ResultBox>
  if (r.outcome === 'blocked') return <ResultBox tone="ok">🛡️ 擋下了（400）：{r.reason}，沒有執行任何指令</ResultBox>
  if (r.outcome === 'syntax') return <ResultBox tone="fail">❌ shell 語法錯誤，什麼都沒執行</ResultBox>
  const extra = ranProcs(r.procs).filter((p) => p.injected).length
  if (r.leaked) return <ResultBox tone="leak">🔓 你塞的 {extra} 個指令執行了，結果跟著回應送回來</ResultBox>
  if (r.injected) return <ResultBox tone="attack">🚨 你塞的 {extra} 個指令執行了</ResultBox>
  return r.procs[0]?.status === 0
    ? <ResultBox tone="ok">✅ ping 成功：連得到這台主機</ResultBox>
    : <ResultBox tone="fail">❌ ping 失敗</ResultBox>
}

function Output({ r }: { r: RunResult }) {
  if (!r.output) return null
  return <pre className={`${s.output} ${r.leaked ? s.outputLeak : ''}`} aria-label="伺服器回應的內容">{r.output}</pre>
}

function insights(r: RunResult) {
  const out: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] = []
  if (r.outcome !== 'ok') return out
  const all = ranProcs(r.procs)
  const top = r.procs.slice(1)
  if (top.some((p) => p.op === ';' || p.op === '&' || p.op === '\n')) {
    out.push({ tone: 'attack', text: <>shell 看到 <code>;</code>，就把一行拆成好幾個指令。伺服器以為只跑 ping，其實你塞的指令也跑了。</> })
  }
  if (top.some((p) => p.op === '&&' || p.op === '||')) {
    out.push({ tone: 'attack', text: <><code>&&</code>、<code>||</code> 看前一個指令的結束碼決定要不要跑下一個。攻擊者故意 ping 一台不存在的主機，再接 <code>||</code>，一樣能讓自己的指令執行。</> })
  }
  if (top.some((p) => p.op === '|')) {
    out.push({ tone: 'attack', text: <><code>|</code> 把 ping 的輸出接給下一個指令，所以畫面上只剩最後一個指令的輸出。</> })
  }
  if (all.some((p) => p.injected) && r.procs[0]?.subs.length) {
    out.push({ tone: 'attack', text: <><code>$( )</code> 會先執行裡面的指令，再把輸出塞回原位。ping 拿到一個怪主機名稱，錯誤訊息把它原封不動印出來，等於幫你把結果帶出伺服器。</> })
  }
  if (all.some((p) => p.injected && (p.argv[0] === 'whoami' || p.argv[0] === 'id'))) {
    out.push({ tone: 'leak', text: <><code>{USER}</code> 是網站程式的帳號，注入的指令用它的權限執行。網站如果用 root（最高權限）跑，攻擊者就等於拿下整台伺服器。</> })
  }
  if (all.some((p) => p.injected && p.argv[0] === 'cat' && p.argv.some((a) => a.includes('passwd')))) {
    out.push({ tone: 'leak', text: <><code>/etc/passwd</code> 是 Linux 的帳號清單。能讀它，代表你能讀這個帳號看得到的任何檔案。</> })
  }
  if (all.some((p) => p.injected && p.stderr.endsWith('not found') && p.argv[0] !== 'ping')) {
    out.push({ tone: 'attack', text: '這個模擬環境只有 ping、ls、cat、whoami、id、echo；真的伺服器上，攻擊者能執行任何已安裝的程式。' })
  }
  if (!r.injected) out.push({ tone: 'safe', text: '正常情況：只有一個 ping 在跑，你的輸入只是 ping 的一個參數。' })
  return out
}

// ---------- 第 3 段：三種寫法 ----------

const CODE: Record<Mode, ReactNode> = {
  vulnerable: (
    <>
      <span className="tok-cm">{'// 把使用者輸入接在指令後面，整行交給 shell\n'}</span>
      {'exec('}<span className="tok-str">'ping -c 1 '</span>{' + '}<span className="tok-var">host</span>{',\n'}
      {'  (err, stdout, stderr) => res.send(stdout + stderr))'}
    </>
  ),
  filter: (
    <>
      <span className="tok-cm">{'// ⚠️ 黑名單：擋掉 ; & |\n'}</span>
      {'if (/[;&|]/.test('}<span className="tok-var">host</span>{'))\n'}
      {'  return res.status(400).send('}<span className="tok-str">'含有危險字元'</span>{')\n'}
      {'exec('}<span className="tok-str">'ping -c 1 '</span>{' + '}<span className="tok-var">host</span>{', ...)'}
    </>
  ),
  patched: (
    <>
      <span className="tok-cm">{'// ① 格式檢查：只允許主機名稱 / IP 會用到的字元\n'}</span>
      {'if (!'}<span className="tok-safe">{'/^[a-z0-9][a-z0-9.-]*$/i'}</span>{'.test('}<span className="tok-var">host</span>{'))\n'}
      {'  return res.status(400).send('}<span className="tok-str">'格式不符'</span>{')\n'}
      <span className="tok-cm">{'// ② 不經過 shell：程式和參數分開交給作業系統\n'}</span>
      <span className="tok-safe">{'execFile'}</span>{'('}<span className="tok-str">'ping'</span>{', ['}<span className="tok-str">'-c'</span>{', '}<span className="tok-str">'1'</span>{', '}<span className="tok-var">host</span>{'], ...)'}
    </>
  ),
}

const MODE_HEAD: Record<Mode, ReactNode> = {
  vulnerable: <h3 className="head-vuln">❌ 漏洞版：整行交給 shell</h3>,
  filter: <h3 className="head-vuln">⚠️ 過濾版：黑名單擋 ; & |</h3>,
  patched: <h3 className="head-safe">✅ 修補版：格式檢查 + 不經過 shell</h3>,
}

const showArgv = (argv: string[]) => `[${argv.map((a) => `'${a}'`).join(', ')}]`

function Executed({ r }: { r: RunResult }) {
  if (r.argv) {
    const second = runArgv(r.argv)
    return (
      <>
        <p className={s.target}>交給作業系統的 argv：<b>{showArgv(r.argv)}</b></p>
        <p className={s.target}>
          第 ② 層保險：就算格式檢查漏掉，這個 argv 也只會跑 <b>1 個 ping</b>，你的輸入整串都只是主機名稱 →{' '}
          <b>{second.status === 0 ? 'ping 成功' : second.stderr}</b>
        </p>
      </>
    )
  }
  const ran = ranProcs(r.procs)
  return (
    <>
      <p className={s.target}>交給 shell 的整行：<b>{r.line}</b></p>
      {r.outcome === 'ok' && <p className={s.target}>實際執行：<b>{ran.map((p) => p.argv[0]).join('、')}</b>（{ran.length} 個 process）</p>}
    </>
  )
}

function ModeCard({ mode, host }: { mode: Mode; host: string }) {
  const r = useMemo(() => runPing(host, mode), [host, mode])
  return (
    <div className="card">
      {MODE_HEAD[mode]}
      <pre className="code-block">{CODE[mode]}</pre>
      {r.outcome !== 'empty' && <Executed r={r} />}
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
    title: '挑戰 1：讀出藏起來的 flag',
    mode: 'vulnerable',
    goal: <>漏洞版。伺服器上的 <code>/var/www/flag.txt</code> 裡有一個 <code>{'FLAG{...}'}</code>，把它讀出來。</>,
    hints: [
      <>先讓 ping 後面多跑一個指令：第 2 段的 <code>;</code> 就可以。</>,
      <><code>cat 檔名</code> 會印出檔案內容。不確定檔案在哪？先用 <code>ls</code> 看看（伺服器現在在 <code>{CWD}</code>）。</>,
      <>解答：<code>8.8.8.8; cat /var/www/flag.txt</code></>,
    ],
    why: <>伺服器把整行 <code>ping -c 1 8.8.8.8; cat /var/www/flag.txt</code> 交給 shell，shell 看到 <code>;</code> 就拆成兩個指令依序執行。網站本來只想 ping，卻變成你叫它執行什麼，它就執行什麼。</>,
  },
  {
    title: '挑戰 2：繞過黑名單',
    mode: 'filter',
    goal: <>過濾版：輸入裡有 <code>;</code>、<code>&</code>、<code>|</code> 就拒絕。一樣讀出 flag.txt 的 <code>{'FLAG{...}'}</code>。</>,
    hints: [
      '黑名單只擋了三個字元。第 2 段的範例裡，哪一招完全沒用到這三個字元？',
      <><code>$( )</code> 會先執行裡面的指令，再把輸出塞回原位。如果 ping 拿到一個奇怪的主機名稱，錯誤訊息會印出什麼？</>,
      <>解答：<code>$(cat /var/www/flag.txt)</code>（反引號也行：<code>`cat /var/www/flag.txt`</code>）</>,
    ],
    why: <><code>$( )</code> 不需要 <code>;</code> <code>&</code> <code>|</code>：shell 先跑 cat，把 FLAG 塞進 ping 的參數，變成 <code>{'ping -c 1 FLAG{...}'}</code>。ping 找不到這台主機，錯誤訊息把主機名稱（就是 FLAG）原封不動印出來。shell 的特殊符號太多，黑名單永遠列不完；修補版改成只允許「主機名稱會用到的字元」，再加上不經過 shell 的 execFile。</>,
  },
]

function Challenge({ def }: { def: ChallengeDef }) {
  const [host, setHost] = useState('')
  const r = useMemo(() => runPing(host, def.mode), [host, def.mode])
  const id = useId()
  return (
    <ChallengeCard title={def.title} goal={def.goal} solved={r.output.includes(FLAG)} hints={def.hints} why={def.why}>
      <TextField id={id} label={`host 參數（${MODE_LABEL[def.mode]}）`} value={host} onChange={setHost} placeholder="8.8.8.8" />
      {host && (
        <>
          <SegmentView label="交給 shell 的整行" segments={r.segments} />
          <ResultLine r={r} />
          <Output r={r} />
        </>
      )}
    </ChallengeCard>
  )
}

// ---------- 頁面 ----------

const PRESETS = [
  { label: '正常 ping 8.8.8.8', host: '8.8.8.8' },
  { label: '; whoami', host: '8.8.8.8; whoami' },
  { label: '&& ls', host: '8.8.8.8 && ls' },
  { label: '|| id', host: 'no-such-host || id' },
  { label: '| cat /etc/passwd', host: '8.8.8.8 | cat /etc/passwd' },
  { label: '$(whoami)', host: '$(whoami)' },
]

const NORMAL = runPing('8.8.8.8', 'vulnerable')

export default function CmdiPage() {
  const [host, setHost] = useState('8.8.8.8')
  const r = useMemo(() => runPing(host, 'vulnerable'), [host])

  return (
    <>
      <h1>Command Injection（命令注入）</h1>
      <OwaspLine category="A05 Injection（注入）" cwe="CWE-78" />

      <Section no={1} title="情境：一個「幫你 ping」的網路診斷工具">
        <p>
          這是假的「Demo 網路診斷工具」。你輸入一個 IP，伺服器在自己的機器上執行
          <Term tip="測試網路通不通的指令：對某台電腦送一個小封包，看它有沒有回應。">ping</Term>
          ，再把結果傳回來。伺服器的程式把你的輸入接在指令後面，整行交給
          <Term tip="伺服器上負責「讀一行指令、拆開、執行」的程式（例如 Linux 的 sh、bash）。它認得 ; | $( ) 這些特殊符號，會照著符號把一行拆成好幾個指令。">shell（命令列直譯器）</Term>
          執行：
        </p>
        <SegmentView label="伺服器交給 shell 的整行" segments={NORMAL.segments} />
        <ProcDiagram r={NORMAL} />
        <p>
          正常情況下，shell 只會執行一個
          <Term tip="程式執行起來的樣子。一行指令可能被 shell 拆成好幾個 process，一個接一個執行。">process（程序）</Term>
          ：ping。但 shell 允許用 <code>;</code>、<code>|</code> 這類符號在一行裡串好幾個指令。
          攻擊者的目標：在「IP」欄位塞進這些符號，讓伺服器多執行自己的指令。這種手法叫
          <Term tip="Command Injection（又叫 OS Command Injection）：網站把使用者輸入拼進系統指令，攻擊者塞進特殊符號，讓伺服器執行額外的指令。">Command Injection（命令注入）</Term>
          。
        </p>
      </Section>

      <Section no={2} title="動手攻擊：讓一行變成好幾個指令" lead={<>
        每打一個字，右邊就重新模擬一次（漏洞版）。圖裡每個指令旁邊都有
        <Term tip="exit code：每個指令跑完會回報一個數字，0 = 成功，其他 = 失敗。&& 和 || 就是看這個數字決定下一個要不要跑。">結束碼</Term>
        。先按「正常 ping」看正常長怎樣，再試其他按鈕。
      </>}>
        <div className="grid-2">
          <FakeSite url={`https://nettools.test/ping?host=${host}`}>
            <h3>🌐 Demo 網路診斷工具｜Ping</h3>
            <p className="hint">模擬環境只有 ping、ls、cat、whoami、id、echo 這幾個指令。</p>
            <TextField id="cmdi-host" label="host 參數（IP 或主機名稱）" value={host} onChange={setHost} />
            <ResultLine r={r} />
            <Output r={r} />
            <Presets items={PRESETS} onPick={(x) => setHost(x.host)} />
          </FakeSite>

          <div className="card panel">
            <div>
              <h3>🧩 伺服器交給 shell 的整行</h3>
              <SegmentView segments={r.segments} label="伺服器交給 shell 的整行" />
              <SegmentLegend code="程式設計師寫的指令" injected="你的輸入，變成了新的指令" />
            </div>
            <div>
              <h3>🔀 shell 內部：一行被拆成幾個指令</h3>
              <ProcDiagram r={r} />
              <p className="caption">藍色 = 伺服器原本要跑的 ping；紅色 = 你塞進去的指令；虛線 = 條件不成立，沒執行；黃色 = 外洩到回應裡。</p>
            </div>
            <Insights items={insights(r)} />
          </div>
        </div>

        <table className={`data-table ${s.cheat}`}>
          <caption className="caption" style={{ captionSide: 'top', textAlign: 'left' }}>shell 特殊符號小抄</caption>
          <thead><tr><th>符號</th><th>意思</th></tr></thead>
          <tbody>
            {([';', '&&', '||', '|'] as const).map((op) => <tr key={op}><td>{op}</td><td>{OP_MEAN[op]}</td></tr>)}
            <tr><td>$( ) 或 ` `</td><td>先執行裡面的指令，把輸出塞回原來的位置</td></tr>
          </tbody>
        </table>
      </Section>

      <Section no={3} title="修補：同一個輸入，三種寫法" lead="下面沿用第 2 段的輸入。中間的過濾版「看起來修了」：按第 2 段的 $(whoami)，看它擋不擋得住。">
        <div className="grid-3">
          <ModeCard mode="vulnerable" host={host} />
          <ModeCard mode="filter" host={host} />
          <ModeCard mode="patched" host={host} />
        </div>

        <div className="card" style={{ marginTop: '1.25rem' }}>
          <p style={{ marginTop: 0 }}>
            <strong>為什麼過濾版擋不住、修補版擋得住？</strong>
            過濾版在猜「哪些字元危險」，但 shell 的特殊符號很多（<code>$</code> <code>( )</code> 反引號、換行…），黑名單漏一個就破功（挑戰 2）。
            修補版從根本拿掉 shell：
            <Term tip="execFile（Python 是 subprocess.run([...])）：把「要執行的程式」和「參數」分開，用陣列交給作業系統。中間沒有 shell，所以沒有人會去解讀 ; 或 $( )。">execFile</Term>
            把程式和參數分開交給作業系統，你的輸入永遠只是 ping 的「一個參數」。格式檢查是另一層保險，兩層各自都擋得住這一頁的 payload。
          </p>
          <strong>其他防線（多一層保險）：</strong>
          <ul className="defenses">
            <li>最好的做法是根本不呼叫系統指令：改用程式語言內建的函式庫做同樣的事（例如用 DNS / 網路函式庫，而不是叫 shell 跑 ping）</li>
            <li>
              Python 用 <code>subprocess.run(['ping', '-c', '1', host])</code>，不要加 <code>shell=True</code>；PHP 的 <code>shell_exec</code>、<code>system</code> 都會經過 shell，要用
              <code>escapeshellarg</code> 包住參數
            </li>
            <li>
              格式檢查用
              <Term tip="白名單：只列出「允許」的東西，其他一律拒絕。跟黑名單（只列出禁止的）相反，安全得多。">allowlist</Term>
              （只允許的字元），不要用黑名單；也要擋 <code>-</code> 開頭，避免輸入被當成 ping 的選項
            </li>
            <li>網站用低權限帳號執行（最小權限）：就算被注入，能讀、能改的東西也有限</li>
          </ul>
        </div>
      </Section>

      <Section no={4} title="挑戰：換你當攻擊者" lead="卡住就按提示，提示會一個一個給。">
        {CHALLENGES.map((c) => <Challenge key={c.title} def={c} />)}
      </Section>
    </>
  )
}
