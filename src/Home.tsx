import { useState } from 'react'
import { Link } from 'react-router'
import { LEVEL_LABEL, TOPICS, type Level } from './topics.ts'

const LEVELS: Level[] = [1, 2, 3]

/** 難度標籤：圓點 + 文字，不只靠顏色 */
function LevelBadge({ level }: { level: Level }) {
  return (
    <span className="level-badge">
      <span aria-hidden="true">{'●'.repeat(level)}{'○'.repeat(3 - level)}</span> 難度{LEVEL_LABEL[level]}
    </span>
  )
}

export default function Home() {
  const [level, setLevel] = useState<Level | 0>(0)
  const topics = level ? TOPICS.filter((t) => t.level === level) : TOPICS

  return (
    <>
      <div className="hero">
        <h1>動手玩，看懂資安攻擊</h1>
        <p>
          每個主題都是一個假網站。你親手輸入攻擊字串，畫面同步畫出「伺服器裡發生了什麼事」，
          再切到修補版，看同一招為什麼失效。全部在瀏覽器裡模擬，放心亂試。
        </p>
        <div className="legend" aria-label="全站顏色說明">
          <span className="badge attack">紅：你的輸入</span>
          <span className="badge code">藍：伺服器程式</span>
          <span className="badge safe">綠：被擋下 / 修補後</span>
          <span className="badge leak">黃：外洩的資料</span>
        </div>
      </div>

      <div className="level-filter" role="group" aria-label="依難度篩選">
        <span>難度：</span>
        {([0, ...LEVELS] as const).map((l) => (
          <button key={l} type="button" aria-pressed={level === l} onClick={() => setLevel(l)}>
            {l ? LEVEL_LABEL[l] : '全部'}
          </button>
        ))}
        <span className="hint">新手建議從「低」開始</span>
      </div>

      <div className="topic-grid">
        {topics.map((t) => {
          const body = (
            <>
              <span className={`badge ${t.ready ? 'code' : ''}`}>{t.ready ? '可以玩了' : '製作中'}</span>
              <LevelBadge level={t.level} />
              <span className="owasp">OWASP {t.owasp}</span>
              <h3>{t.title}</h3>
              <p><strong>{t.zh}</strong>｜{t.summary}</p>
            </>
          )
          return t.ready
            ? <Link key={t.id} to={`/${t.id}`} className="card topic-card">{body}</Link>
            : <div key={t.id} className="card topic-card disabled" aria-disabled="true">{body}</div>
        })}
      </div>
    </>
  )
}
