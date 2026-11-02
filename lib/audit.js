import { chmodSync, closeSync, mkdirSync, openSync, writeSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const MAX_COMMAND_CHARS = 2000
const AUDIT_FILE = 'sudo-audit.jsonl'

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function localTimestamp(date = new Date()) {
  const pad = (value) => String(value).padStart(2, '0')
  const offset = -date.getTimezoneOffset()
  const sign = offset >= 0 ? '+' : '-'
  const hours = pad(Math.floor(Math.abs(offset) / 60))
  const minutes = pad(Math.abs(offset) % 60)
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` +
    `${sign}${hours}:${minutes}`
  )
}

function clip(value, max) {
  const text = String(value ?? '')
  return text.length > max ? text.slice(0, max) : text
}

/**
 * Append one audit record. This intentionally uses a single append-only write:
 * no read-modify-write, no whole-file rewrite. A logging failure must never
 * change the outcome of the command, so all errors are swallowed after a short
 * stderr note.
 */
export function audit(record = {}) {
  const line = JSON.stringify({
    ts: localTimestamp(),
    session: clip(record.session ?? 'unknown', 200),
    cwd: clip(record.cwd ?? '', 2000),
    command: clip(record.command ?? '', MAX_COMMAND_CHARS),
    kind: record.kind === 'script' ? 'script' : 'command',
    level: record.level ?? null,
    categories: Array.isArray(record.categories) ? record.categories.slice(0, 20) : [],
    score: Number.isFinite(record.score) ? record.score : null,
    confirm: record.confirm ?? 'refused',
    exitCode: Number.isFinite(record.exitCode) ? record.exitCode : -1,
    durationMs: Number.isFinite(record.durationMs) ? Math.max(0, record.durationMs) : 0,
    clientPid: Number.isInteger(record.clientPid) ? record.clientPid : null,
    ...(record.reason ? { reason: clip(record.reason, 500) } : {})
  })

  let fd
  try {
    const dir = dshHome()
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const file = join(dir, AUDIT_FILE)
    fd = openSync(file, 'a', 0o600)
    writeSync(fd, `${line}\n`)
    try {
      chmodSync(file, 0o600)
    } catch {
      // Mode correction is best effort; the file was created with 0600.
    }
  } catch (error) {
    try {
      process.stderr.write(`[sudo-mode] audit write failed: ${error instanceof Error ? error.message : String(error)}\n`)
    } catch {
      // Nothing else can be done.
    }
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd)
      } catch {
        // ignore
      }
    }
  }
}

export function auditPath() {
  return join(dshHome(), AUDIT_FILE)
}
