/**
 * 破關進度，存在 localStorage：{ 主題 id: { 挑戰標題: 是否完成 } }。
 * 挑戰卡出現在畫面上時先登記成 false、完成時改成 true，
 * 所以首頁不用另外手寫「每關有幾個挑戰」。
 * ponytail: 挑戰改標題會留下舊的 key，讓總數多 1；真的改名再清 localStorage。
 */
export type Progress = Record<string, Record<string, boolean>>

const KEY = 'progress'

export function loadProgress(): Progress {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KEY) ?? '{}')
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Progress : {}
  } catch {
    return {}
  }
}

/** 已經完成的挑戰不會被改回未完成 */
export function recordChallenge(topic: string, title: string, solved: boolean) {
  const all = loadProgress()
  const t = all[topic] ?? {}
  if (t[title] === true || t[title] === solved) return
  all[topic] = { ...t, [title]: solved }
  try { localStorage.setItem(KEY, JSON.stringify(all)) } catch { /* 無痕模式存不了就算了 */ }
}

export function topicStatus(p: Progress, topic: string) {
  const v = Object.values(p[topic] ?? {})
  const done = v.filter(Boolean).length
  return { done, total: v.length, cleared: v.length > 0 && done === v.length }
}
