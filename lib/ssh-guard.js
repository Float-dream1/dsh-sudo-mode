import { detectDangerousCommand } from './danger.js'

export const SSH_FAILURE_WINDOW_MS = 60_000
export const SSH_FAILURE_LIMIT = 3
export const SSH_BLOCK_MS = 5 * 60_000

const sessions = new Map()

const SSH_FAILURE_RE = /Permission denied|Connection refused|Connection timed out|Connection closed by|Host key verification failed|No route to host|Could not resolve hostname|Authentication failed|Too many authentication failures|Network is unreachable|Connection reset by peer|Received disconnect|kex_exchange_identification/i

function sessionKey(exec) {
  return exec?.agent?.session?.id || 'global'
}

function stateFor(exec) {
  const key = sessionKey(exec)
  let state = sessions.get(key)
  if (!state) {
    state = { failures: [], blockedUntil: 0 }
    sessions.set(key, state)
  }
  return state
}

export function isSshCommand(command) {
  if (!command) return false
  try {
    return detectDangerousCommand(command).categories.includes('ssh')
  } catch {
    return false
  }
}

export function checkSshBlocked(exec, command) {
  if (!isSshCommand(command)) return null
  const state = stateFor(exec)
  const now = Date.now()
  if (state.blockedUntil > now) {
    const seconds = Math.ceil((state.blockedUntil - now) / 1000)
    return `SSH 已被自动阻断：短时间内连续 ${SSH_FAILURE_LIMIT} 次 SSH 失败。请在 ${seconds} 秒后重试，或先让用户检查网络/凭据。`
  }
  if (state.blockedUntil !== 0) {
    state.blockedUntil = 0
    state.failures = []
  }
  return null
}

function resultText(result) {
  const parts = []
  if (typeof result?.value?.stderr === 'string') parts.push(result.value.stderr)
  if (typeof result?.value?.stdout === 'string') parts.push(result.value.stdout)
  if (typeof result?.value?.output === 'string') parts.push(result.value.output)
  if (Array.isArray(result?.content)) {
    for (const block of result.content) {
      if (block?.type === 'text' && typeof block.text === 'string') parts.push(block.text)
    }
  }
  return parts.join('\n')
}

function exitCodeOf(result) {
  const value = result?.value
  if (typeof value?.exitCode === 'number') return value.exitCode
  if (typeof value?.code === 'number') return value.code
  return null
}

function isFailure(result) {
  const code = exitCodeOf(result)
  const text = resultText(result)
  if (code === 255) return true
  if (code === 0 && !result?.isError) return false
  return SSH_FAILURE_RE.test(text)
}

export function noteSshResult(exec, command, result) {
  if (!isSshCommand(command)) return
  const state = stateFor(exec)
  const now = Date.now()

  if (!isFailure(result)) {
    state.failures = []
    state.blockedUntil = 0
    return
  }

  state.failures = state.failures.filter((time) => now - time < SSH_FAILURE_WINDOW_MS)
  state.failures.push(now)
  if (state.failures.length >= SSH_FAILURE_LIMIT) {
    state.blockedUntil = now + SSH_BLOCK_MS
    state.failures = []
  }
}
