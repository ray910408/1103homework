import { beforeEach, describe, expect, it, vi } from 'vitest'
import { loadProgress, recordChallenge, topicStatus } from './progress.ts'

beforeEach(() => {
  const store = new Map<string, string>()
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => { store.set(k, v) },
  })
})

describe('破關進度', () => {
  it('挑戰全部完成才算破關', () => {
    recordChallenge('xss', '挑戰 1', false)
    recordChallenge('xss', '挑戰 2', false)
    expect(topicStatus(loadProgress(), 'xss')).toEqual({ done: 0, total: 2, cleared: false })

    recordChallenge('xss', '挑戰 1', true)
    expect(topicStatus(loadProgress(), 'xss')).toEqual({ done: 1, total: 2, cleared: false })

    recordChallenge('xss', '挑戰 2', true)
    expect(topicStatus(loadProgress(), 'xss').cleared).toBe(true)
  })

  it('完成過的挑戰重新進頁面不會被改回未完成', () => {
    recordChallenge('sqli', '挑戰 1', true)
    recordChallenge('sqli', '挑戰 1', false)
    expect(topicStatus(loadProgress(), 'sqli').cleared).toBe(true)
  })

  it('沒玩過的主題、壞掉的資料都當成 0', () => {
    expect(topicStatus(loadProgress(), 'jwt')).toEqual({ done: 0, total: 0, cleared: false })
    localStorage.setItem('progress', '{壞掉')
    expect(loadProgress()).toEqual({})
    localStorage.setItem('progress', '[1,2]')
    expect(loadProgress()).toEqual({})
  })
})
