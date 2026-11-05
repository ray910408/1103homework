/**
 * IDOR 模擬：假商店 shop.test 的「看訂單」與「改 Email」API。純函式，不依賴 React。
 * 漏洞版只檢查「有沒有登入」；修補版再檢查「這筆資料是不是登入的人的」。
 */

export type Mode = 'vulnerable' | 'patched'

/** 目前登入的人（session cookie 裡記的是他） */
export const ME = 'alice'
export const MY_ID = 2

export const FLAG_ORDER = 'FLAG{1d0r_3num3r4t3d_0rd3r}'

export interface Order {
  id: number
  owner: string
  item: string
  total: number
  name: string
  phone: string
  address: string
  note: string
}

/** 訂單編號是連號的：這正是攻擊者最喜歡的設計 */
export const ORDERS: Order[] = [
  { id: 1000, owner: 'admin', item: '內部測試訂單（請勿出貨）', total: 0, name: '系統管理員', phone: '—', address: '—', note: FLAG_ORDER },
  { id: 1001, owner: 'bob', item: '機械鍵盤', total: 2490, name: '鮑伯（假資料）', phone: '09xx-xxx-001', address: '範例市測試區假路 1 號', note: '' },
  { id: 1002, owner: 'alice', item: '貓咪滑鼠墊', total: 350, name: 'Alice（你）', phone: '09xx-xxx-002', address: '範例市示範區假路 2 號', note: '' },
  { id: 1003, owner: 'carol', item: '降噪耳機', total: 3990, name: '卡蘿（假資料）', phone: '09xx-xxx-003', address: '範例市測試區假路 3 號', note: '請放管理室' },
  { id: 1004, owner: 'bob', item: 'USB 隨身碟', total: 299, name: '鮑伯（假資料）', phone: '09xx-xxx-001', address: '範例市測試區假路 1 號', note: '' },
]

export interface OrderResult {
  id: string
  status: 200 | 404
  /** 資料庫裡那張訂單（上帝視角；不管有沒有回給你） */
  target?: Order
  /** 真的回給你的訂單 */
  order?: Order
  mine: boolean
  /** 回了別人的訂單 */
  leaked: boolean
  /** 修補版擋下：訂單存在，但不是你的 */
  blocked: boolean
}

/** GET /orders/:id */
export function getOrder(id: string, mode: Mode): OrderResult {
  const raw = id.trim()
  const base = { id: raw, mine: false, leaked: false, blocked: false }
  // 參數化查詢：'1002 OR 1=1' 只是一個查不到的值，不會變成 SQL
  if (!/^\d+$/.test(raw)) return { ...base, status: 404 }
  const target = ORDERS.find((o) => o.id === Number(raw))
  const mine = target?.owner === ME
  if (!target) return { ...base, status: 404 }
  // 修補版：WHERE id = ? AND owner = ?，不是你的就跟不存在一樣
  if (mode === 'patched' && !mine) return { ...base, status: 404, target, blocked: true }
  return { ...base, status: 200, target, order: target, mine, leaked: !mine }
}

// ---------- 寫入：改 Email ----------

export interface User { id: number; username: string; email: string }

export const USERS: User[] = [
  { id: 1, username: 'admin', email: 'admin@shop.test' },
  { id: 2, username: 'alice', email: 'alice@example.test' },
  { id: 3, username: 'bob', email: 'bob@example.test' },
]

export interface EmailResult {
  status: 200 | 400 | 403 | 404
  /** 執行後的會員表（不改動傳進來的陣列） */
  users: User[]
  target?: User
  /** 改到別人的 Email */
  takeover: boolean
}

/** PUT /api/users/:id/email */
export function updateEmail(users: User[], id: string, email: string, mode: Mode): EmailResult {
  const raw = id.trim()
  const fail = { users, takeover: false }
  if (!/^\d+$/.test(raw) || !/^[^\s@]+@[^\s@]+$/.test(email.trim())) return { ...fail, status: 400 }
  // 修補版：編號不是登入的人就拒絕，而且在查資料庫之前就拒絕（不透露這個編號存不存在）
  if (mode === 'patched' && Number(raw) !== MY_ID) return { ...fail, status: 403 }
  const target = users.find((u) => u.id === Number(raw))
  if (!target) return { ...fail, status: 404 }
  return {
    status: 200,
    users: users.map((u) => (u === target ? { ...u, email: email.trim() } : u)),
    target,
    takeover: target.id !== MY_ID,
  }
}
