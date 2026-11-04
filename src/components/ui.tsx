import { useRef, useState, type ReactNode } from 'react'

// ---------- 型別 ----------

/**
 * 輸入分段的角色（SQL、HTML、shell 指令都通用）：
 * code     = 程式設計師寫的
 * data     = 你的輸入，乖乖當資料
 * injected = 你的輸入，變成了指令 / 標籤 / 程式
 * comment  = 被註解掉、不會執行
 */
export type SegKind = 'code' | 'data' | 'injected' | 'comment'
export interface Segment { text: string; kind: SegKind }

/** ok = 綠（正常 / 被擋下）、fail = 灰（一般失敗）、attack = 紅（攻擊成功 / 錯誤）、leak = 黃（資料外洩） */
export type Tone = 'ok' | 'fail' | 'attack' | 'leak'

// ---------- 版面 ----------

/** 模組的一段（1 情境 / 2 動手攻擊 / 3 修補對照 / 4 挑戰） */
export function Section({ no, title, lead, children }: {
  no: number
  title: string
  lead?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="section" aria-labelledby={`sec-${no}`}>
      <div className="section-head">
        <span className="section-no" aria-hidden="true">{no}</span>
        <h2 id={`sec-${no}`}>{title}</h2>
      </div>
      {lead && <p className="section-lead">{lead}</p>}
      {children}
    </section>
  )
}

/** 專有名詞＋白話解釋。滑鼠移上去、Tab 到它、手機點它都會顯示 */
export function Term({ children, tip }: { children: string; tip: string }) {
  const tipRef = useRef<HTMLSpanElement>(null)

  // tooltip 從名詞左邊往右展開；名詞靠近螢幕右邊時會超出去，量一下再往內推
  const fit = () => {
    const el = tipRef.current
    if (!el) return
    el.style.transform = ''
    const r = el.getBoundingClientRect()
    const margin = 8
    const vw = document.documentElement.clientWidth
    const shift = r.right > vw - margin ? vw - margin - r.right : r.left < margin ? margin - r.left : 0
    if (shift) el.style.transform = `translateX(${shift}px)`
  }

  return (
    <span className="term" tabIndex={0} aria-label={`${children}：${tip}`} onMouseEnter={fit} onFocus={fit}>
      {children}
      <span ref={tipRef} className="tip" role="tooltip">{tip}</span>
    </span>
  )
}

/** 假網站外框（有網址列） */
export function FakeSite({ url, children }: { url: string; children: ReactNode }) {
  return (
    <div className="fake-site">
      <div className="url-bar">{url}</div>
      <div className="site-body">{children}</div>
    </div>
  )
}

// ---------- 輸入 ----------

export function TextField({ id, label, value, onChange, placeholder }: {
  id: string
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      <input id={id} type="text" value={value} placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)} autoComplete="off" spellCheck={false} />
    </div>
  )
}

/** 一排「快速填入範例」按鈕 */
export function Presets<T extends { label: string }>({ items, onPick }: { items: T[]; onPick: (item: T) => void }) {
  return (
    <div className="presets" aria-label="快速填入範例">
      {items.map((x) => <button key={x.label} type="button" onClick={() => onPick(x)}>{x.label}</button>)}
    </div>
  )
}

// ---------- 結果與說明 ----------

export function ResultBox({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <div className={`result result-${tone}`} role="status">{children}</div>
}

/** 💡 發生了什麼事 */
export function Insights({ items }: { items: { tone: 'attack' | 'safe' | 'leak'; text: ReactNode }[] }) {
  if (items.length === 0) return null
  return (
    <ul className="insights" aria-label="發生了什麼事">
      {items.map((t, i) => <li key={i} className={t.tone}>💡 {t.text}</li>)}
    </ul>
  )
}

const SEG_LABEL: Record<SegKind, string> = { code: '程式', data: '你的輸入（資料）', injected: '你的輸入（變成指令）', comment: '被註解掉' }

/** 把一段程式碼依角色上色（藍字 / 紅框 / 紅底 / 灰色刪除線） */
export function SegmentView({ segments, label }: { segments: Segment[]; label: string }) {
  return (
    <pre className="seg-view" aria-label={label}>
      {segments.map((seg, i) => (
        <span key={i} className={`seg-${seg.kind}`} title={SEG_LABEL[seg.kind]}>{seg.text}</span>
      ))}
    </pre>
  )
}

/** SegmentView 的圖例；不傳 comment 就不顯示那一項 */
export function SegmentLegend({ code = '程式設計師寫的程式', injected = '你的輸入，變成了指令', comment }: {
  code?: string
  injected?: string
  comment?: string
}) {
  return (
    <ul className="seg-legend" aria-label="顏色說明">
      <li><span className="seg-code">藍字</span> {code}</li>
      <li><span className="seg-data">紅框</span> 你的輸入，還只是資料</li>
      <li><span className="seg-injected">紅底</span> {injected}</li>
      {comment && <li><span className="seg-comment">灰色刪除線</span> {comment}</li>}
    </ul>
  )
}

// ---------- 挑戰 ----------

/**
 * 挑戰卡：hints 最後一項是解答。children 放這個挑戰自己的互動區。
 * solved 由呼叫端根據模擬結果判斷。
 */
export function ChallengeCard({ title, goal, solved, hints, why, children }: {
  title: string
  goal: ReactNode
  solved: boolean
  hints: ReactNode[]
  why: ReactNode
  children: ReactNode
}) {
  const [shown, setShown] = useState(0)
  return (
    <div className={`card challenge ${solved ? 'solved' : ''}`}>
      <h3>{solved && '✅ '}{title}</h3>
      <p className="hint">目標：{goal}</p>
      {children}
      {solved
        ? <div className="solved-box" role="status"><strong>挑戰完成！</strong>為什麼會成功：{why}</div>
        : (
          <>
            {shown > 0 && <ol className="hints">{hints.slice(0, shown).map((h, i) => <li key={i}>{h}</li>)}</ol>}
            {shown < hints.length && (
              <button type="button" className="hint-btn" onClick={() => setShown(shown + 1)}>
                {shown === hints.length - 1 ? '看解答' : `給我提示（${shown + 1}/${hints.length - 1}）`}
              </button>
            )}
          </>
        )}
    </div>
  )
}

// ---------- 圖解 ----------

/**
 * SVG 箭頭定義。App.tsx 已在全站放了一份（id 不能重複，模組不要再放），
 * 線條加 className="arrow-attack | arrow-code | arrow-safe | arrow-leak" 就有對應顏色的箭頭。
 */
export function DiagramDefs() {
  const marker = (id: string, color: string) => (
    <marker id={id} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 10 5 0 10z" fill={`var(${color})`} />
    </marker>
  )
  return (
    <defs>
      {marker('arrow-attack', '--c-attack')}
      {marker('arrow-code', '--c-code')}
      {marker('arrow-safe', '--c-safe')}
      {marker('arrow-leak', '--c-leak')}
    </defs>
  )
}
