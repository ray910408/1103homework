import { useEffect, useLayoutEffect, useState } from 'react'
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

const FONT_SIZES = ['87.5%', '100%', '112.5%', '125%']

/** 讀寫 localStorage 的偏好設定；無痕模式等存不了就只在這次瀏覽有效 */
function usePref(key: string, fallback: string) {
  const [value, setValue] = useState(() => {
    try { return localStorage.getItem(key) ?? fallback } catch { return fallback }
  })
  const set = (v: string) => {
    setValue(v)
    try { localStorage.setItem(key, v) } catch { /* 存不了就算了 */ }
  }
  return [value, set] as const
}

/** 字體大小 + 亮暗模式。用 layout effect 在畫面繪出前套用，避免閃一下 */
function Prefs() {
  const [font, setFont] = usePref('font-size', '100%')
  const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const [theme, setTheme] = usePref('theme', systemDark ? 'dark' : 'light')
  const i = Math.max(0, FONT_SIZES.indexOf(font))

  useLayoutEffect(() => {
    document.documentElement.style.fontSize = FONT_SIZES[i]
    document.documentElement.dataset.theme = theme
  }, [i, theme])

  const dark = theme === 'dark'
  return (
    <div className="prefs" role="group" aria-label="顯示設定">
      <button type="button" aria-label="縮小字體" disabled={i === 0} onClick={() => setFont(FONT_SIZES[i - 1])}>A−</button>
      <button type="button" aria-label="放大字體" disabled={i === FONT_SIZES.length - 1} onClick={() => setFont(FONT_SIZES[i + 1])}>A+</button>
      <button type="button" aria-label={dark ? '切換成淺色模式' : '切換成深色模式'} onClick={() => setTheme(dark ? 'light' : 'dark')}>
        {dark ? '☀️ 淺色' : '🌙 深色'}
      </button>
    </div>
  )
}

export default function App() {
  const { pathname } = useLocation()
  // 大括號不可省：新版瀏覽器的 scrollTo 會回傳 Promise，被 React 當成 cleanup 就會 crash
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])

  return (
    <>
      {/* 全站共用的 SVG 箭頭定義，只放一份，避免 id 重複 */}
      <svg width="0" height="0" style={{ position: 'absolute' }} aria-hidden="true"><DiagramDefs /></svg>
      <header className="site-header">
        <div className="header-inner">
          <nav aria-label="主選單">
            <Link to="/" className="brand">🛡️ 資安攻擊互動圖解</Link>
            {TOPICS.map((t) =>
              t.ready
                ? <NavLink key={t.id} to={`/${t.id}`}>{t.title}</NavLink>
                : <span key={t.id} className="soon" title="製作中">{t.title}</span>,
            )}
          </nav>
          <Prefs />
        </div>
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
