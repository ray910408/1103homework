import type { ReactNode } from 'react'

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

/** 專有名詞＋白話解釋。滑鼠移上去或 Tab 到它都會顯示 */
export function Term({ children, tip }: { children: ReactNode; tip: string }) {
  return (
    <span className="term" tabIndex={0} aria-label={`${String(children)}：${tip}`}>
      {children}
      <span className="tip" role="tooltip">{tip}</span>
    </span>
  )
}
