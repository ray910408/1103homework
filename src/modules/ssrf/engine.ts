// SSRF 模擬引擎：純 TS，不依賴 React / DOM。
// 整個「網路」都是記憶體裡的假 DNS + 假服務，絕對不發真實請求。

export type Mode = 'vulnerable' | 'blacklist' | 'patched'

/** 拓撲圖上的節點 */
export type NodeId = 'web' | 'cdn' | 'attacker' | 'metadata' | 'admin' | 'redis'

export const INTERNAL: ReadonlySet<NodeId> = new Set<NodeId>(['web', 'metadata', 'admin', 'redis'])

export const FLAG_METADATA = 'FLAG{ssrf_m3t4d4t4_l00t}'
export const FLAG_ADMIN = 'FLAG{bl4ckl1st_byp4ss3d}'

/** 黑名單版比對的字串 */
export const BLACKLIST = ['localhost', '127.0.0.1', '169.254.169.254']

/** 假 DNS：網域 → IP */
export const DNS: Record<string, string> = {
  'cdn.example.com': '93.184.216.34',
  'localhost': '127.0.0.1',
  'redis.internal': '10.0.0.5',
  'rebind.attacker.test': '127.0.0.1', // 攻擊者把自己的網域指向內網
  'redirect.attacker.test': '203.0.113.66',
}

export interface Resp {
  status: number
  type: 'image' | 'json' | 'text'
  body: string
  location?: string
  /** 內容是機密（外洩要顯示黃色） */
  secret?: boolean
}

const CREDS = JSON.stringify({ AccessKeyId: 'FAKE-ACCESS-KEY-DEMO', SecretAccessKey: FLAG_METADATA, Token: 'demo-token' }, null, 2)

const METADATA: Record<string, string> = {
  '/': 'latest/',
  '/latest/': 'meta-data/',
  '/latest/meta-data/': 'ami-id\nhostname\nlocal-ipv4\niam/',
  '/latest/meta-data/ami-id': 'ami-0demo0fake0',
  '/latest/meta-data/hostname': 'ip-10-0-0-8.demo.internal',
  '/latest/meta-data/local-ipv4': '10.0.0.8',
  '/latest/meta-data/iam/': 'security-credentials/',
  '/latest/meta-data/iam/security-credentials/': 'web-role',
}

const FILES: Record<string, string> = {
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ndemo:x:1000:1000:Demo User（假資料）:/home/demo:/bin/bash',
  '/etc/hostname': 'imghost-demo',
}

const NOT_FOUND: Resp = { status: 404, type: 'text', body: 'Not Found' }
const ok = (body: string, type: Resp['type'] = 'text', secret = false): Resp => ({ status: 200, type, body, secret })

/** 每個節點的服務：port → 處理函式 */
const SERVICES: Record<Exclude<NodeId, 'web'>, { ports: number[]; handle: (path: string, query: URLSearchParams) => Resp }> = {
  cdn: {
    ports: [80, 443],
    handle: (p) => (p === '/cat.png' ? ok('cat.png', 'image') : p === '/' ? ok('cdn.example.com：圖片 CDN') : NOT_FOUND),
  },
  attacker: {
    ports: [80, 443],
    handle: (p, q) => {
      if (p === '/r') {
        // 開放轉址：?url= 指定要轉去哪，預設轉到雲端金鑰
        const to = q.get('url') ?? 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role'
        return { status: 302, type: 'text', body: `302 Found → ${to}`, location: to }
      }
      return p === '/' ? ok('😈 攻擊者自己的伺服器') : NOT_FOUND
    },
  },
  metadata: {
    ports: [80],
    handle: (p) => {
      if (p === '/latest/meta-data/iam/security-credentials/web-role') return ok(CREDS, 'json', true)
      const body = METADATA[p] ?? METADATA[p + '/']
      return body === undefined ? NOT_FOUND : ok(body)
    },
  },
  admin: {
    ports: [8080],
    handle: (p) => {
      if (p === '/admin' || p === '/admin/') {
        return ok(`🔧 內部管理後台（僅限內網）\n\n使用者清單：\n  admin    admin@imghost.demo\n  alice    alice@imghost.demo\n\n後台密鑰：${FLAG_ADMIN}`, 'text', true)
      }
      return p === '/' ? ok('Internal admin service. 請到 /admin') : NOT_FOUND
    },
  },
  redis: {
    ports: [6379],
    handle: () => ok("-ERR unknown command 'GET'\n# 這是內部 Redis（redis_version:7.2.0-demo）\n# 能連到它，就能對它下指令"),
  },
}

// ---------- IP 工具 ----------

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/** ::1 → 127.0.0.1、::ffff:7f00:1 → 127.0.0.1；其他 IPv6 原樣 */
function toV4(ip: string): string {
  const v = ip.toLowerCase()
  if (v === '::1') return '127.0.0.1'
  const mapped = v.match(/^::ffff:(.+)$/)
  if (mapped) {
    if (IPV4.test(mapped[1])) return mapped[1]
    const [hi, lo] = mapped[1].split(':').map((h) => parseInt(h, 16))
    if (hi !== undefined && lo !== undefined) return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.')
  }
  return v
}

/** 內網位址的種類；公網回傳 undefined */
export function privateRange(ip: string): string | undefined {
  const v = toV4(ip)
  if (v.includes(':')) {
    if (v === '::') return '未指定位址（::）'
    if (/^f[cd]/.test(v)) return 'private（fc00::/7）'
    if (/^fe[89ab]/.test(v)) return 'link-local（fe80::/10）'
    return undefined
  }
  const [a, b] = v.split('.').map(Number)
  if (a === 127) return 'loopback（本機，127.0.0.0/8）'
  if (a === 10) return 'private（10.0.0.0/8）'
  if (a === 172 && b >= 16 && b <= 31) return 'private（172.16.0.0/12）'
  if (a === 192 && b === 168) return 'private（192.168.0.0/16）'
  if (a === 169 && b === 254) return 'link-local（169.254.0.0/16，雲端 metadata 就在這裡）'
  if (a === 0) return '0.0.0.0/8（等於連本機）'
  return undefined
}

const IP_NODE: Record<string, Exclude<NodeId, 'web'>> = {
  '169.254.169.254': 'metadata', '10.0.0.5': 'redis', '93.184.216.34': 'cdn', '203.0.113.66': 'attacker',
}

function nodeOf(ip: string): Exclude<NodeId, 'web'> | undefined {
  const v = toV4(ip)
  if (v.startsWith('127.') || v.startsWith('0.')) return 'admin' // 本機上跑著管理後台
  return IP_NODE[v]
}

/** 不連線，只算出這個網址「會連到哪」：host、IP、port、節點 */
function resolve(url: URL): { host: string; ip?: string; isIp: boolean; port: number; node?: NodeId } {
  if (url.protocol === 'file:') return { host: '', isIp: false, port: 0, node: 'web' }
  const host = url.hostname.replace(/^\[|\]$/g, '')
  const isIp = IPV4.test(host) || host.includes(':')
  const ip = isIp ? host : DNS[host]
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80
  return { host, ip, isIp, port, node: ip ? nodeOf(ip) : undefined }
}

// ---------- 主流程 ----------

export interface Hop {
  url: string
  host: string
  ip?: string
  port?: number
  node?: NodeId
  status: 'ok' | 'redirect' | 'blocked' | 'error'
}

export interface Step { tone: 'info' | 'attack' | 'safe' | 'leak'; text: string }

export interface FetchResult {
  outcome: 'ok' | 'blocked' | 'error'
  /** 被擋或失敗的原因 */
  reason?: string
  steps: Step[]
  /** 每一次連線嘗試（轉址會有多個） */
  hops: Hop[]
  response?: Resp
  /** 你打的主機字串（含 port），用來對照正規化後的結果 */
  rawHost?: string
  /** URL 解析器正規化後的主機（含 port） */
  parsedHost?: string
  /** 有沒有用 @ 把真正的主機藏在後面 */
  userinfo?: string
  /** 成功連進內網（含伺服器自己的檔案） */
  internal: boolean
  /** 抓回機密內容 */
  leaked: boolean
}

const MAX_HOPS = 4

export function serverFetch(input: string, mode: Mode): FetchResult {
  const raw = input.trim()
  const steps: Step[] = []
  const hops: Hop[] = []
  const done = (outcome: FetchResult['outcome'], extra: Partial<FetchResult> = {}): FetchResult => {
    const reached = hops.filter((h) => (h.status === 'ok' || h.status === 'redirect') && h.node && INTERNAL.has(h.node))
    return { outcome, steps, hops, internal: reached.length > 0, leaked: !!extra.response?.secret && outcome === 'ok', ...extra }
  }

  let url: URL
  try {
    url = new URL(raw)
  } catch {
    steps.push({ tone: 'info', text: '網址格式錯誤，伺服器看不懂' })
    return done('error', { reason: '網址格式錯誤（要像 https://cdn.example.com/cat.png）' })
  }
  const rawHost = raw.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1]?.replace(/^.*@/, '')
  const info = { rawHost, parsedHost: url.host, userinfo: url.username || undefined }
  steps.push({ tone: 'info', text: `解析網址：協定 ${url.protocol}，主機 ${url.host || '（無）'}，路徑 ${url.pathname}` })
  if (rawHost !== undefined && rawHost.toLowerCase() !== url.host) {
    steps.push({ tone: 'attack', text: `注意：你打的主機「${rawHost}」被正規化成「${url.host}」` })
  }

  if (mode === 'blacklist') {
    const hit = BLACKLIST.find((b) => raw.toLowerCase().includes(b))
    if (hit) {
      steps.push({ tone: 'safe', text: `字串檢查：網址裡有黑名單字串「${hit}」，拒絕` })
      const t = resolve(url)
      hops.push({ url: url.href, host: t.host, ip: t.ip, port: t.port, node: t.node, status: 'blocked' })
      return done('blocked', { ...info, reason: `網址裡有黑名單字串「${hit}」` })
    }
    steps.push({ tone: 'attack', text: '字串檢查：網址裡沒有 localhost / 127.0.0.1 / 169.254.169.254，放行' })
  }

  for (let n = 0; n < MAX_HOPS; n++) {
    const hop: Hop = { url: url.href, host: url.hostname, status: 'error' }
    hops.push(hop)

    if (url.protocol === 'file:') {
      hop.node = 'web'
      if (mode === 'patched') {
        hop.status = 'blocked'
        steps.push({ tone: 'safe', text: '協定檢查：只允許 http / https，不允許 file:' })
        return done('blocked', { ...info, reason: '只允許 http / https，不允許 file:' })
      }
      const body = FILES[url.pathname]
      if (body === undefined) {
        steps.push({ tone: 'attack', text: `讀取伺服器自己的檔案 ${url.pathname}：檔案不存在` })
        return done('error', { ...info, reason: `檔案 ${url.pathname} 不存在` })
      }
      hop.status = 'ok'
      steps.push({ tone: 'leak', text: `file: 協定讓伺服器讀了自己硬碟上的 ${url.pathname}` })
      return done('ok', { ...info, response: ok(body, 'text', true) })
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      steps.push({ tone: mode === 'patched' ? 'safe' : 'info', text: `不支援的協定 ${url.protocol}` })
      if (mode === 'patched') {
        hop.status = 'blocked'
        return done('blocked', { ...info, reason: `只允許 http / https，不允許 ${url.protocol}` })
      }
      return done('error', { ...info, reason: `不支援的協定 ${url.protocol}` })
    }

    const { host, ip, isIp, port, node } = resolve(url)
    if (!ip) {
      steps.push({ tone: 'info', text: `DNS：查不到 ${host}` })
      return done('error', { ...info, reason: `DNS 查不到主機 ${host}` })
    }
    if (!isIp) {
      const range = privateRange(ip)
      steps.push({ tone: range ? 'attack' : 'info', text: `DNS：${host} → ${ip}${range ? `（這是內網位址！）` : ''}` })
    }
    hop.ip = ip
    hop.port = port
    hop.node = node

    if (mode === 'patched') {
      const range = privateRange(ip)
      if (range) {
        hop.status = 'blocked'
        steps.push({ tone: 'safe', text: `IP 檢查：${ip} 屬於 ${range}，拒絕連線` })
        return done('blocked', { ...info, reason: `目標 IP ${ip} 屬於 ${range}` })
      }
      steps.push({ tone: 'info', text: `IP 檢查：${ip} 是公網位址，放行` })
    }

    const svc = hop.node && hop.node !== 'web' ? SERVICES[hop.node] : undefined
    if (!svc || !svc.ports.includes(port)) {
      steps.push({ tone: privateRange(ip) ? 'attack' : 'info', text: `連線 ${ip}:${port}：沒有回應（那台機器沒開這個 port）` })
      return done('error', { ...info, reason: `連線 ${ip}:${port} 失敗` })
    }

    const resp = svc.handle(url.pathname, url.searchParams)
    const internal = INTERNAL.has(hop.node!)
    steps.push({ tone: internal ? 'attack' : 'info', text: `連線 ${ip}:${port}${internal ? '（內網！）' : ''}，GET ${url.pathname}${url.search} → ${resp.status}` })

    if (resp.location) {
      hop.status = 'redirect'
      let next: URL
      try {
        next = new URL(resp.location, url)
      } catch {
        return done('error', { ...info, reason: '轉址網址格式錯誤' })
      }
      steps.push({ tone: 'attack', text: `${resp.status} 轉址到 ${next.href}${mode === 'patched' ? '：每一跳都重新檢查' : '：伺服器照著轉過去'}` })
      url = next
      continue
    }

    hop.status = 'ok'
    if (resp.secret) steps.push({ tone: 'leak', text: '伺服器把抓到的機密內容原封不動回給你' })
    return done('ok', { ...info, response: resp })
  }
  return done('error', { ...info, reason: '轉址次數太多' })
}
