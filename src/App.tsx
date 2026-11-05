import { useEffect } from 'react'
import { Link, NavLink, Route, Routes, useLocation } from 'react-router'
import { DiagramDefs } from './components/ui.tsx'
import Home from './Home.tsx'
import BrutePage from './modules/brute/index.tsx'
import CmdiPage from './modules/cmdi/index.tsx'
import CsrfPage from './modules/csrf/index.tsx'
import IdorPage from './modules/idor/index.tsx'
import JwtPage from './modules/jwt/index.tsx'
import PathPage from './modules/path/index.tsx'
import SqliPage from './modules/sqli/index.tsx'
import SsrfPage from './modules/ssrf/index.tsx'
import XssPage from './modules/xss/index.tsx'
import { TOPICS } from './topics.ts'

export default function App() {
  const { pathname } = useLocation()
  // 大括號不可省：新版瀏覽器的 scrollTo 會回傳 Promise，被 React 當成 cleanup 就會 crash
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])

  return (
    <>
      {/* 全站共用的 SVG 箭頭定義，只放一份，避免 id 重複 */}
      <svg width="0" height="0" style={{ position: 'absolute' }} aria-hidden="true"><DiagramDefs /></svg>
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
          <Route path="/xss" element={<XssPage />} />
          <Route path="/ssrf" element={<SsrfPage />} />
          <Route path="/csrf" element={<CsrfPage />} />
          <Route path="/idor" element={<IdorPage />} />
          <Route path="/path" element={<PathPage />} />
          <Route path="/jwt" element={<JwtPage />} />
          <Route path="/brute" element={<BrutePage />} />
          <Route path="/cmdi" element={<CmdiPage />} />
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
