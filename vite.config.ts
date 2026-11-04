import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  // 相對路徑：GitHub Pages 不管 repo 叫什麼名字都能用（搭配 HashRouter）
  base: './',
  plugins: [react()],
})
