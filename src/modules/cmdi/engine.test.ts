import { describe, expect, it } from 'vitest'
import { FLAG, PREFIX, runArgv, runPing, type Proc } from './engine.ts'

const names = (ps: Proc[]) => ps.map((p) => p.argv[0])

describe('正常使用', () => {
  it.each(['vulnerable', 'filter', 'patched'] as const)('%s：ping 8.8.8.8 正常', (mode) => {
    const r = runPing('8.8.8.8', mode)
    expect(r.outcome).toBe('ok')
    expect(r.procs).toHaveLength(1)
    expect(r.output).toContain('1 received')
    expect(r.injected).toBe(false)
    expect(r.leaked).toBe(false)
  })

  it('找不到主機', () => {
    const r = runPing('no-such-host', 'vulnerable')
    expect(r.output).toBe('ping: no-such-host: Name or service not known')
    expect(r.procs[0].status).toBe(2)
  })

  it('空輸入', () => {
    expect(runPing('  ', 'vulnerable').outcome).toBe('empty')
  })
})

describe('經典 payload：8.8.8.8; cat /etc/passwd', () => {
  const payload = '8.8.8.8; cat /etc/passwd'

  it('漏洞版：一行拆成兩個 process，passwd 外洩', () => {
    const r = runPing(payload, 'vulnerable')
    expect(names(r.procs)).toEqual(['ping', 'cat'])
    expect(r.procs[1].injected).toBe(true)
    expect(r.output).toContain('root:x:0:0')
    expect(r.injected).toBe(true)
    expect(r.leaked).toBe(true)
  })

  it('輸出依執行順序：先 ping 再 cat', () => {
    const out = runPing(payload, 'vulnerable').output
    expect(out.indexOf('PING')).toBeLessThan(out.indexOf('root:x'))
  })

  it('過濾版：; 被黑名單擋下', () => {
    const r = runPing(payload, 'filter')
    expect(r.outcome).toBe('blocked')
    expect(r.reason).toContain(';')
  })

  it('修補版：格式檢查擋下', () => {
    const r = runPing(payload, 'patched')
    expect(r.outcome).toBe('blocked')
    expect(r.procs).toHaveLength(0)
  })

  it('修補版的第二層：就算格式檢查漏掉，argv 不經過 shell，; 只是主機名稱的一部分', () => {
    const p = runArgv(['ping', '-c', '1', payload])
    expect(p.stderr).toBe(`ping: ${payload}: Name or service not known`)
    expect(p.stdout).toBe('')
  })
})

describe('運算子', () => {
  it('&&：前一個成功才執行', () => {
    expect(runPing('8.8.8.8 && whoami', 'vulnerable').output).toContain('www-data')
    const r = runPing('no-such-host && whoami', 'vulnerable')
    expect(r.procs[1].ran).toBe(false)
    expect(r.injected).toBe(false)
  })

  it('||：前一個失敗才執行', () => {
    expect(runPing('no-such-host || id', 'vulnerable').output).toContain('uid=33(www-data)')
    expect(runPing('8.8.8.8 || id', 'vulnerable').procs[1].ran).toBe(false)
  })

  it('|：ping 的輸出被接走，只看到最後一個指令的輸出', () => {
    const r = runPing('8.8.8.8 | cat /etc/hostname', 'vulnerable')
    expect(r.procs[0].piped).toBe(true)
    expect(r.output).toBe('nettools-demo')
  })

  it('| cat 沒給檔名：讀前一個指令的輸出', () => {
    expect(runPing('8.8.8.8 | cat', 'vulnerable').output).toContain('PING 8.8.8.8')
  })

  it('a || b && c：左到右，跳過的不改變結束碼', () => {
    const r = runPing('8.8.8.8 || whoami && id', 'vulnerable')
    expect(r.procs.map((p) => p.ran)).toEqual([true, false, true])
  })

  it('& 和 ; 一樣會接著執行', () => {
    expect(names(runPing('8.8.8.8 & whoami', 'vulnerable').procs)).toEqual(['ping', 'whoami'])
  })

  it('結尾的 ; 合法；結尾的 && 是語法錯誤', () => {
    expect(runPing('8.8.8.8;', 'vulnerable').outcome).toBe('ok')
    expect(runPing('8.8.8.8 &&', 'vulnerable').outcome).toBe('syntax')
    expect(runPing('8.8.8.8 ;; id', 'vulnerable').outcome).toBe('syntax')
  })

  it('引號裡的 ; 只是字元', () => {
    const r = runPing("'8.8.8.8; id'", 'vulnerable')
    expect(r.procs).toHaveLength(1)
    expect(r.output).toBe('ping: 8.8.8.8; id: Name or service not known')
  })

  it('引號沒關 → 語法錯誤', () => {
    expect(runPing("8.8.8.8'", 'vulnerable').outcome).toBe('syntax')
  })

  it('不存在的指令', () => {
    expect(runPing('8.8.8.8; rm -rf /', 'vulnerable').output).toContain('sh: 1: rm: not found')
  })

  it('原型鏈上的名字不是指令', () => {
    expect(runPing('8.8.8.8; constructor', 'vulnerable').output).toContain('constructor: not found')
    expect(runPing('constructor', 'vulnerable').output).toContain('Name or service not known')
  })
})

describe('$( ) 與反引號', () => {
  it('$(whoami) 先執行，輸出塞回 ping 的參數', () => {
    const r = runPing('$(whoami)', 'vulnerable')
    expect(r.procs[0].argv).toEqual(['ping', '-c', '1', 'www-data'])
    expect(names(r.procs[0].subs)).toEqual(['whoami'])
    expect(r.output).toBe('ping: www-data: Name or service not known')
    expect(r.leaked).toBe(true)
  })

  it('反引號效果一樣', () => {
    expect(runPing('`whoami`', 'vulnerable').procs[0].argv[3]).toBe('www-data')
  })

  it('雙引號裡的 $( ) 一樣會執行', () => {
    expect(runPing('"$(whoami)"', 'vulnerable').procs[0].argv[3]).toBe('www-data')
  })

  it('單引號裡的 $( ) 不會執行', () => {
    expect(runPing("'$(whoami)'", 'vulnerable').procs[0].subs).toHaveLength(0)
  })

  it('空的 $( ) 什麼都不塞', () => {
    expect(runPing('8.8.8.8$()', 'vulnerable').procs[0].argv).toEqual(['ping', '-c', '1', '8.8.8.8'])
  })
})

describe('上色', () => {
  it('程式 / 資料 / 注入', () => {
    expect(runPing('8.8.8.8; id', 'vulnerable').segments).toEqual([
      { kind: 'code', text: PREFIX },
      { kind: 'data', text: '8.8.8.8' },
      { kind: 'injected', text: '; id' },
    ])
  })
  it('$( ) 整段是注入', () => {
    expect(runPing('$(id)', 'vulnerable').segments.at(-1)).toEqual({ kind: 'injected', text: '$(id)' })
  })
})

describe('挑戰 1：漏洞版讀出 flag.txt', () => {
  it.each(['8.8.8.8; cat /var/www/flag.txt', '8.8.8.8; cat ../flag.txt', 'x || cat ../flag.txt'])('%s', (p) => {
    expect(runPing(p, 'vulnerable').output).toContain(FLAG)
  })
  it('ls 看得到 flag.txt', () => {
    expect(runPing('8.8.8.8; ls ..', 'vulnerable').output).toContain('flag.txt')
  })
  it('修補版：擋下', () => {
    expect(runPing('8.8.8.8; cat ../flag.txt', 'patched').output).not.toContain(FLAG)
  })
})

describe('挑戰 2：繞過擋 ; & | 的黑名單', () => {
  it.each(['$(cat ../flag.txt)', '`cat /var/www/flag.txt`'])('過濾版：%s 從錯誤訊息拿到 FLAG', (p) => {
    const r = runPing(p, 'filter')
    expect(r.outcome).toBe('ok')
    expect(r.output).toBe(`ping: ${FLAG}: Name or service not known`)
    expect(r.leaked).toBe(true)
  })
  it('修補版：$ ( ) 不在允許的字元裡', () => {
    const r = runPing('$(cat ../flag.txt)', 'patched')
    expect(r.outcome).toBe('blocked')
    expect(r.output).not.toContain(FLAG)
  })
  it('修補版：- 開頭會被當成 ping 的選項，也擋', () => {
    expect(runPing('-f', 'patched').outcome).toBe('blocked')
  })
})
