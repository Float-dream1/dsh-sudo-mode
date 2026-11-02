const WINDOW_MS = 60_000
const COOLDOWN_MS = 5 * 60_000
const MAX_CONSECUTIVE_CANCELS = 2

const states = new Map()

function stateFor(sessionId) {
  const key = String(sessionId || 'unknown')
  let state = states.get(key)
  if (!state) {
    state = {
      lastAt: 0,
      lastOutcome: null,
      consecutiveCancels: 0,
      cooldownUntil: 0
    }
    states.set(key, state)
  }
  if (state.cooldownUntil && state.cooldownUntil <= Date.now()) {
    state.cooldownUntil = 0
    state.consecutiveCancels = 0
  }
  return state
}

function cooldownMessage(state) {
  const seconds = Math.max(1, Math.ceil((state.cooldownUntil - Date.now()) / 1000))
  const minutes = Math.ceil(seconds / 60)
  return `已拒绝：连续取消后进入冷却期（剩余 ${minutes} 分钟）。这是为了防止重复弹窗导致误点；冷却期内不会再次弹出确认框。`
}

/**
 * Called before opening a secondary confirmation dialog. Password-only sudo
 * calls must never call this; only blacklist/score confirmations are limited.
 */
export function checkConfirmationAllowed(sessionId) {
  const state = stateFor(sessionId)
  if (state.cooldownUntil > Date.now()) return cooldownMessage(state)

  if (state.lastAt && Date.now() - state.lastAt < WINDOW_MS) {
    return '已拒绝：同一会话每分钟最多允许 1 次高危确认；请稍后再试。'
  }
  return null
}

/**
 * Record the result of a dialog that was actually shown. Cancels and
 * timeouts count toward the cooldown; an approval resets the counter.
 */
export function noteConfirmation(sessionId, outcome) {
  const state = stateFor(sessionId)
  const now = Date.now()

  if (outcome === 'approved') {
    state.lastAt = now
    state.lastOutcome = 'approved'
    state.consecutiveCancels = 0
    state.cooldownUntil = 0
    return
  }

  if (outcome === 'cancelled' || outcome === 'timeout') {
    state.lastAt = now
    state.lastOutcome = outcome
    state.consecutiveCancels += 1
    if (state.consecutiveCancels >= MAX_CONSECUTIVE_CANCELS) {
      state.cooldownUntil = now + COOLDOWN_MS
    }
  }
}

export function resetConfirmationState(sessionId) {
  states.delete(String(sessionId || 'unknown'))
}

export const CONFIRMATION_WINDOW_MS = WINDOW_MS
export const CONFIRMATION_COOLDOWN_MS = COOLDOWN_MS
