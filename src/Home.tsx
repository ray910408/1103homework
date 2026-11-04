import { Link } from 'react-router'
import { TOPICS } from './topics.ts'

export default function Home() {
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

      <div className="topic-grid">
        {TOPICS.map((t) => {
          const body = (
            <>
              <span className={`badge ${t.ready ? 'code' : ''}`}>{t.ready ? '可以玩了' : '製作中'}</span>
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
