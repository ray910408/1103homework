import { useEffect } from 'react'
import { Link, NavLink, Route, Routes, useLocation } from 'react-router'
import Home from './Home.tsx'
import SqliPage from './modules/sqli/index.tsx'
import { TOPICS } from './topics.ts'

export default function App() {
  const { pathname } = useLocation()
  // 大括號不可省：新版瀏覽器的 scrollTo 會回傳 Promise，被 React 當成 cleanup 就會 crash
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])

  return (
    <>
      <header className="site-header">
        <nav aria-label="主選單">
          <Link to="/" className="brand">🛡️ 資安攻擊互動圖解</Link>
          {TOPICS.map((t) =>
            t.ready
              ? <NavLink key={t.id} to={`/${t.id}`}>{t.title}</NavLink>
              : <span key={t.id} className="soon" title="製作中">{t.title}</span>,
          )}
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/sqli" element={<SqliPage />} />
          <Route path="*" element={<Home />} />
        </Routes>
      </main>
      <footer className="disclaimer">
        ⚠️ 本站所有攻擊都在你的瀏覽器內模擬，不會連到任何真實系統。內容僅供教學；
        未經授權攻擊他人系統，觸犯《刑法》妨害電腦使用罪（第 358 條起）。
      </footer>
    </>
  )
}
