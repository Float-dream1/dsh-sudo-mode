import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, statSync } from 'node:fs'

export const DEFAULT_CONFIRM_TIMEOUT_SECONDS = 120

export const NO_DISPLAY_MESSAGE =
  '已拒绝：这台机器当前没有可用的图形会话（试过 :0 / :1），无法弹出授权窗口。' +
  '提权确认必须在电脑本机的图形桌面上完成，远程或纯命令行环境无法提权。'

export function confirmationTimeoutMessage(seconds) {
  return `已拒绝：等待本机确认超时（${seconds} 秒内无人点击）。提权确认只能在电脑的图形桌面上手动完成。`
}

export function confirmTimeoutSeconds() {
  const raw = process.env.DSH_SUDO_CONFIRM_TIMEOUT
  if (raw === undefined || raw === '') return DEFAULT_CONFIRM_TIMEOUT_SECONDS
  const value = Number(raw)
  if (!Number.isFinite(value) || value < 0) return DEFAULT_CONFIRM_TIMEOUT_SECONDS
  return Math.floor(value)
}

function uidOf(file) {
  try {
    return statSync(file).uid
  } catch {
    return null
  }
}

function xauthCandidates() {
  const uid = typeof process.getuid === 'function' ? process.getuid() : null
  const candidates = []
  const seen = new Set()
  const add = (file) => {
    if (!file || seen.has(file) || !existsSync(file)) return
    if (uid !== null && uidOf(file) !== uid) return
    seen.add(file)
    candidates.push(file)
  }

  add(process.env.XAUTHORITY)

  try {
    for (const entry of readdirSync('/tmp')) {
      if (!entry.startsWith('xauth_')) continue
      add(`/tmp/${entry}`)
    }
  } catch {
    // No /tmp or unreadable: env XAUTHORITY is the only candidate.
  }

  return candidates
}

export function probeDisplay(display, xauth, timeoutMs = 2000) {
  if (!display || !existsSync('/usr/bin/xdpyinfo')) return false
  const env = { ...process.env, DISPLAY: display }
  if (xauth) env.XAUTHORITY = xauth
  try {
    return spawnSync('/usr/bin/xdpyinfo', [], {
      env,
      timeout: Math.max(1, timeoutMs),
      stdio: 'ignore'
    }).status === 0
  } catch {
    return false
  }
}

/**
 * Find an X11 display that can actually be reached from this process.
 *
 * The environment inherited at DSH startup can be stale after switching
 * desktop sessions, so try the original DISPLAY first, then every local X
 * socket, pairing each with an xauth file owned by this user.
 */
export function resolveXDisplay() {
  const displays = []
  const seenDisplays = new Set()
  const addDisplay = (display) => {
    if (!display || seenDisplays.has(display)) return
    seenDisplays.add(display)
    displays.push(display)
  }

  addDisplay(process.env.DISPLAY)

  try {
    for (const entry of readdirSync('/tmp/.X11-unix')) {
      const match = /^X(\d+)$/.exec(entry)
      if (match) addDisplay(`:${match[1]}`)
    }
  } catch {
    // No X11 socket directory.
  }

  const xauths = xauthCandidates()
  const deadline = Date.now() + 3000
  const remaining = () => Math.max(0, deadline - Date.now())

  for (const display of displays) {
    for (const xauth of xauths) {
      const budget = Math.min(2000, remaining())
      if (budget <= 0) return null
      if (probeDisplay(display, xauth, budget)) return { display, xauth }
    }
    // Some X servers allow local connections without an xauth file.
    const budget = Math.min(2000, remaining())
    if (budget > 0 && probeDisplay(display, null, budget)) {
      return { display, xauth: null }
    }
  }

  return null
}

export function displayEnv(display, xauth, base = process.env) {
  const env = { ...base, DISPLAY: display }
  if (xauth) env.XAUTHORITY = xauth
  else delete env.XAUTHORITY
  return env
}
