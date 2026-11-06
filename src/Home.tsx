import { useState } from 'react'
import { Link } from 'react-router'
import { loadProgress, topicStatus } from './progress.ts'
import { LEVEL_LABEL, TOPICS, type Level, type Topic } from './topics.ts'

const LEVELS: Level[] = [1, 2, 3]

export default function Home() {
  const [level, setLevel] = useState<Level | 0>(0)
  const [progress] = useState(loadProgress)
  const status = (t: Topic) => topicStatus(progress, t.id)

  const ready = TOPICS.filter((t) => t.ready)
  const cleared = ready.filter((t) => status(t).cleared).length
  // 下一關：還沒破關的裡面，難度最低的那個
  const next = [...ready].sort((a, b) => a.level - b.level).find((t) => !status(t).cleared)
  const topics = level ? TOPICS.filter((t) => t.level === level) : TOPICS

  return (
    <>
      <div className="hero">
        <p className="kicker">HACK QUEST · 資安闖關</p>
        <h1>動手玩，看懂資安攻擊</h1>
        <p>
          每一關都是一個假網站。你親手輸入攻擊字串，畫面同步畫出「伺服器裡發生了什麼事」，
          再切到修補版，看同一招為什麼失效。全部在瀏覽器裡模擬，放心亂試。
        </p>
        <div className="legend" aria-label="全站顏色說明">
          <span className="badge attack">紅：你的輸入</span>
          <span className="badge code">藍：伺服器程式</span>
          <span className="badge safe">綠：被擋下 / 修補後</span>
          <span className="badge leak">黃：外洩的資料</span>
        </div>
      </div>

      <div className="card quest-progress">
        <div className="quest-progress-head">
          <strong>破關進度</strong>
          <span className="quest-count">{cleared} / {ready.length} 關</span>
        </div>
        <div className="quest-bar" role="progressbar" aria-label="破關進度"
          aria-valuemin={0} aria-valuemax={ready.length} aria-valuenow={cleared}>
          <div style={{ width: `${(cleared / ready.length) * 100}%` }} />
        </div>
        {next
          ? <Link to={`/${next.id}`} className="button primary">{cleared ? '繼續下一關' : '從第一關開始'}：{next.title} →</Link>
          : <p className="quest-done">🏆 全部破關！你已經看懂 {ready.length} 種攻擊了。</p>}
        <p className="hint">完成一關裡的所有「挑戰」就算破關；進度只存在這台電腦的瀏覽器裡。</p>
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
          const s = status(t)
          const body = (
            <>
              <div className="topic-meta">
                <span className="lv">LV.{t.level}</span>
                <span className="level-name">難度{LEVEL_LABEL[t.level]}</span>
                <span>OWASP {t.owasp}</span>
              </div>
              <h3>{t.title}</h3>
              <p><strong>{t.zh}</strong>｜{t.summary}</p>
              <span className="quest-status">
                {!t.ready ? '製作中'
                  : s.cleared ? <span className="badge safe">✓ 已破關</span>
                  : s.done ? <span className="badge accent">挑戰 {s.done} / {s.total}</span>
                  : '▶ 開始挑戰'}
              </span>
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
