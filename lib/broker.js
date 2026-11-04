import { spawn } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { confirmDangerous, detectDangerousCommand } from './danger.js'
import { isReadOnlyCommand, runReadOnlyCommand } from './read-only.js'
import { displayEnv, NO_DISPLAY_MESSAGE, resolveXDisplay } from './display.js'
import { audit, auditPath } from './audit.js'
import { checkConfirmationAllowed, noteConfirmation } from './confirm-guard.js'

const PRESET_NAME = 'sudo-access'
const MAX_OUTPUT = 60_000
const TIMEOUT_MS = 300_000
const SOCKET_NAME = 'broker.sock'

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function runtimeDir() {
  return join(dshHome(), 'sudo-mode')
}

function escapeMarkup(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function truncate(text) {
  if (text.length <= MAX_OUTPUT) return text
  return `${text.slice(0, MAX_OUTPUT)}\n…（输出已截断，共 ${text.length} 字符）`
}

function askpassText(command) {
  const shown = command.length > 1200 ? `${command.slice(0, 1200)}…` : command
  return [
    'DSH 终端请求以 root 执行下面这条命令。',
    '',
    '命令：',
    escapeMarkup(shown),
    '',
    '核对命令内容后再输入 root 密码；取消不会执行。'
  ].join('\n')
}

/**
 * Write the SUDO_ASKPASS helper. It contains no password: zenity displays the
 * dialog and writes only the typed password to stdout, which sudo reads.
 */
function ensureAskpass() {
  const dir = runtimeDir()
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const file = join(dir, 'askpass.sh')
  const script = `#!/bin/sh
# DSH sudo askpass helper. No secret is stored in this file.
# The Python wrapper marks the dialog process non-dumpable before exec, so
# same-user processes cannot read the password out of /proc or ptrace it.
exec /usr/bin/python3 - "$DSH_SUDO_TEXT" <<'PY'
import ctypes
import os
import sys

text = sys.argv[1] if len(sys.argv) > 1 else ""
ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
os.execv("/usr/bin/zenity", [
    "zenity",
    "--forms",
    "--title=DSH Sudo 授权",
    "--text=" + text,
    "--add-password=Root 密码",
])
PY
`
  writeFileSync(file, script, { encoding: 'utf8', mode: 0o700 })
  chmodSync(file, 0o700)
  return file
}

function writeRuntimeFiles() {
  const dir = runtimeDir()
  const bin = join(dir, 'bin')
  mkdirSync(bin, { recursive: true, mode: 0o700 })

  const socketPath = join(dir, SOCKET_NAME)
  const gatePath = join(dir, 'peer-gate.py')
  const clientPath = join(dir, 'sudo-client.py')
  const shimPath = join(bin, 'sudo')
  const rcPath = join(dir, 'terminal.bashrc')
  const shellPath = join(dir, 'terminal-shell.sh')

  const client = `#!/usr/bin/python3
import base64
import json
import os
import shlex
import socket
import sys

SOCKET_PATH = ${JSON.stringify(socketPath)}

def fail(message, code=1):
    print(message, file=sys.stderr)
    raise SystemExit(code)

args = sys.argv[1:]
if not args:
    fail("用法：sudo <命令>（DSH 终端 sudo broker 只接受非交互命令）", 1)

command = " ".join(shlex.quote(a) for a in args)
session = os.environ.get("DSH_SESSION_ID", "")
if not session:
    fail("无法确定 DSH 会话；请在 DSH 的终端里运行 sudo。", 1)

request = {
    "sessionId": session,
    "clientPid": os.getpid(),
    "cwd": os.getcwd(),
    "command": command,
}

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(180)
try:
    sock.connect(SOCKET_PATH)
    sock.sendall(json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\\n")
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
except FileNotFoundError:
    fail("DSH sudo broker 未运行；请确认 dsh-sudo-mode 已加载并重启 DSH。", 1)
except (ConnectionError, OSError) as error:
    fail(f"无法连接 DSH sudo broker：{error}", 1)
finally:
    sock.close()

if not chunks:
    fail("DSH sudo broker 没有返回结果。", 1)

try:
    response = json.loads(b"".join(chunks).decode("utf-8"))
except Exception as error:
    fail(f"DSH sudo broker 返回了无效结果：{error}", 1)

stdout = base64.b64decode(response.get("stdout_b64", ""))
stderr = base64.b64decode(response.get("stderr_b64", ""))
if stdout:
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
if stderr:
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()
raise SystemExit(int(response.get("exitCode", 1)))
`

  const shim = `#!/bin/sh
exec /usr/bin/python3 ${JSON.stringify(clientPath)} "$@"
`

  const rc = `export PATH=${JSON.stringify(bin)}:"$PATH"
`

  const shell = `#!/bin/sh
# DSH sudo terminal wrapper: keep the PTY in the sandbox, but give it a
# sudo command that talks to the host-side broker.
exec /bin/bash --rcfile ${JSON.stringify(rcPath)} -i
`

  writeFileSync(gatePath, readFileSync(new URL('./peer-gate.py', import.meta.url)), { encoding: 'utf8', mode: 0o700 })
  writeFileSync(clientPath, client, { encoding: 'utf8', mode: 0o700 })
  writeFileSync(shimPath, shim, { encoding: 'utf8', mode: 0o700 })
  writeFileSync(rcPath, rc, { encoding: 'utf8', mode: 0o600 })
  writeFileSync(shellPath, shell, { encoding: 'utf8', mode: 0o700 })
  for (const file of [gatePath, clientPath, shimPath, shellPath]) chmodSync(file, 0o700)

  return { dir, socketPath, gatePath, clientPath, shimPath, rcPath, shellPath }
}

async function runSudo(command, cwd, meta = {}) {
  const started = Date.now()
  const info = {
    session: meta.sessionId || 'unknown',
    cwd,
    command,
    kind: 'command',
    level: null,
    categories: [],
    score: null,
    confirm: 'refused',
    readOnly: false,
    elevated: false,
    clientPid: Number.isInteger(meta.clientPid) ? meta.clientPid : null
  }

  let result
  try {
    result = await runSudoCore(command, cwd, meta, info)
  } catch (error) {
    result = {
      exitCode: -1,
      stdout: '',
      stderr: `sudo broker 内部错误：${error instanceof Error ? error.message : String(error)}`
    }
    info.reason = 'internal-error'
  }

  audit({
    ...info,
    exitCode: result.exitCode,
    durationMs: Date.now() - started
  })
  return result
}

async function runSudoCore(command, cwd, meta, info) {
  const readOnly = isReadOnlyCommand(command)
  info.readOnly = readOnly
  if (!readOnly && !existsSync('/usr/bin/sudo')) {
    return { exitCode: -1, stdout: '', stderr: '找不到 /usr/bin/sudo，无法执行 root 命令。' }
  }
  if (!existsSync('/usr/bin/zenity')) {
    return { exitCode: -1, stdout: '', stderr: '找不到 /usr/bin/zenity，无法弹出确认框。' }
  }
  if (!readOnly && !existsSync('/usr/bin/python3')) {
    return { exitCode: -1, stdout: '', stderr: '找不到 /usr/bin/python3，无法启动隔离的密码框。' }
  }

  const danger = detectDangerousCommand(command)
  info.categories = [...danger.categories]
  if (danger.dangerous) info.level = 'critical'
  if (danger.categories.includes('bruteforce')) {
    return {
      exitCode: -1,
      stdout: '',
      stderr: '已拒绝：禁止尝试爆破、猜测或破解 root 密码（包括宿主机、虚拟机、容器、SSH、su、sudo 和弱口令）。'
    }
  }

  const display = resolveXDisplay()
  if (!display) {
    return { exitCode: -1, stdout: '', stderr: NO_DISPLAY_MESSAGE }
  }

  if (readOnly) {
    info.level = danger.dangerous ? 'critical' : 'read-only'
    const result = await confirmDangerous({
      level: info.level,
      reasons: danger.dangerous ? danger.reasons : ['只读命令；确认后以当前用户执行，不提权'],
      command,
      purpose: '你在 DSH 终端中请求执行这条只读命令；不会请求 root 密码。',
      kind: 'command',
      score: null,
      threshold: null,
      readOnly: true
    }, undefined, display)

    if (!result.confirmed) {
      if (result.reason === 'timeout') {
        info.confirm = 'timeout'
        return { exitCode: -1, stdout: '', stderr: result.message }
      }
      if (result.reason === 'no-display') {
        info.confirm = 'refused'
        return { exitCode: -1, stdout: '', stderr: NO_DISPLAY_MESSAGE }
      }
      if (result.reason === 'unavailable') {
        info.confirm = 'refused'
        return { exitCode: -1, stdout: '', stderr: '已拒绝：无法弹出本机确认窗口，未执行。' }
      }
      info.confirm = 'cancelled'
      return { exitCode: -1, stdout: '', stderr: '已取消：只读命令未通过确认，未执行。' }
    }

    info.confirm = 'approved'
    info.elevated = false
    const unprivileged = await runReadOnlyCommand(command, cwd, {
      timeoutMs: TIMEOUT_MS,
      maxOutput: MAX_OUTPUT
    })
    return {
      exitCode: unprivileged.exitCode,
      stdout: unprivileged.stdout,
      stderr: `${unprivileged.stderr}${unprivileged.stderr ? '\n' : ''}[sudo-mode] 只读命令未提权，以当前用户执行。`
    }
  }

  if (danger.dangerous) {
    const limited = checkConfirmationAllowed(meta.sessionId)
    if (limited) {
      info.confirm = 'refused'
      info.reason = limited
      if (limited.includes('每分钟')) noteConfirmation(meta.sessionId, 'cancelled')
      return { exitCode: -1, stdout: '', stderr: limited }
    }

    const result = await confirmDangerous({
      level: 'critical',
      reasons: danger.reasons,
      command,
      purpose: '你在 DSH 终端中请求执行这条命令。',
      kind: 'command',
      score: null,
      threshold: null
    }, undefined, display)

    if (!result.confirmed) {
      if (result.reason === 'timeout') {
        info.confirm = 'timeout'
        noteConfirmation(meta.sessionId, 'timeout')
        return { exitCode: -1, stdout: '', stderr: result.message }
      }
      if (result.reason === 'no-display') {
        info.confirm = 'refused'
        return { exitCode: -1, stdout: '', stderr: NO_DISPLAY_MESSAGE }
      }
      if (result.reason === 'unavailable') {
        info.confirm = 'refused'
        return { exitCode: -1, stdout: '', stderr: '已拒绝：无法弹出本机确认窗口，未执行。' }
      }
      info.confirm = 'cancelled'
      noteConfirmation(meta.sessionId, 'cancelled')
      return { exitCode: -1, stdout: '', stderr: '已取消：高危命令未通过二次确认，未执行。' }
    }
    info.confirm = 'approved'
    noteConfirmation(meta.sessionId, 'approved')
  } else {
    info.confirm = 'approved'
  }

  info.elevated = true
  return new Promise((resolve) => {
    let askpass
    try {
      askpass = ensureAskpass()
    } catch (error) {
      resolve({ exitCode: -1, stdout: '', stderr: `无法准备密码框脚本：${error.message}` })
      return
    }

    let child
    try {
      child = spawn('/usr/bin/sudo', ['-A', '-k', '--', '/bin/bash', '-lc', command], {
        cwd,
        env: {
          ...displayEnv(display.display, display.xauth),
          SUDO_ASKPASS: askpass,
          SUDO_ASKPASS_REQUIRE: 'force',
          DSH_SUDO_TEXT: askpassText(command)
        },
        stdio: ['ignore', 'pipe', 'pipe']
      })
    } catch (error) {
      resolve({ exitCode: -1, stdout: '', stderr: `启动 sudo 失败：${error.message}` })
      return
    }

    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')

    let stdout = ''
    let stderr = ''
    let timedOut = false

    const take = (previous, chunk) => {
      if (previous.length >= MAX_OUTPUT) return previous
      const next = previous + chunk
      return next.length > MAX_OUTPUT ? next.slice(0, MAX_OUTPUT) : next
    }

    child.stdout.on('data', (chunk) => { stdout = take(stdout, chunk) })
    child.stderr.on('data', (chunk) => { stderr = take(stderr, chunk) })

    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGTERM')
    }, TIMEOUT_MS)

    child.on('error', (error) => {
      clearTimeout(timer)
      resolve({ exitCode: -1, stdout, stderr: `${stderr}\n[sudo-mode] ${error.message}` })
    })
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      let exitCode = code ?? -1
      if (timedOut) {
        exitCode = -1
        stderr += `\n\n[sudo-mode] 命令超过 ${TIMEOUT_MS / 1000} 秒，已终止。`
      } else if (signal) {
        stderr += `\n\n[sudo-mode] 进程被信号 ${signal} 终止。`
      }
      // Clear any timestamp sudo may have cached for this terminal.
      try {
        spawn('/usr/bin/sudo', ['-k'], { stdio: 'ignore' }).unref()
      } catch {
        // best effort only
      }
      resolve({ exitCode, stdout: truncate(stdout), stderr: truncate(stderr) })
    })
  })
}

function reply(socket, value) {
  socket.end(`${JSON.stringify(value)}\n`)
}

async function handleRequest(ctx, line, socket, peerPid = null) {
  let request
  try {
    request = JSON.parse(line)
  } catch {
    reply(socket, { exitCode: 1, stdout_b64: '', stderr_b64: Buffer.from('请求格式无效。').toString('base64') })
    return
  }

  const sessionId = typeof request.sessionId === 'string' ? request.sessionId : ''
  const clientPid = Number.isInteger(peerPid)
    ? peerPid
    : (Number.isInteger(request.clientPid) ? request.clientPid : null)
  const command = typeof request.command === 'string' ? request.command.trim() : ''
  const cwd = typeof request.cwd === 'string' && request.cwd ? request.cwd : process.cwd()

  if (!sessionId) {
    reply(socket, { exitCode: 1, stdout_b64: '', stderr_b64: Buffer.from('缺少 DSH 会话。').toString('base64') })
    return
  }
  if (!command) {
    reply(socket, { exitCode: 1, stdout_b64: '', stderr_b64: Buffer.from('命令不能为空。').toString('base64') })
    return
  }
  if (command.includes('\0')) {
    reply(socket, { exitCode: 1, stdout_b64: '', stderr_b64: Buffer.from('命令不能包含 NUL 字符。').toString('base64') })
    return
  }

  const agents = ctx.get('agents')
  const agent = agents?.get?.(sessionId)
  if (!agent) {
    reply(socket, { exitCode: 1, stdout_b64: '', stderr_b64: Buffer.from('找不到对应的 DSH 会话。').toString('base64') })
    return
  }

  let current
  try {
    current = ctx.permissionPresets.current(agent.session)
  } catch (error) {
    reply(socket, {
      exitCode: 1,
      stdout_b64: '',
      stderr_b64: Buffer.from(`无法读取当前权限模式：${error instanceof Error ? error.message : String(error)}`).toString('base64')
    })
    return
  }
  if (current !== PRESET_NAME) {
    reply(socket, {
      exitCode: 1,
      stdout_b64: '',
      stderr_b64: Buffer.from(`当前权限模式是「${current}」，不是「Sudo 访问」。请先切换权限模式。`).toString('base64')
    })
    return
  }

  try {
    if (!statSync(cwd).isDirectory()) throw new Error('not a directory')
  } catch {
    reply(socket, { exitCode: 1, stdout_b64: '', stderr_b64: Buffer.from(`cwd 不存在或不可访问：${cwd}`).toString('base64') })
    return
  }

  const result = await runSudo(command, cwd, { sessionId, clientPid })
  reply(socket, {
    exitCode: result.exitCode,
    stdout_b64: Buffer.from(result.stdout).toString('base64'),
    stderr_b64: Buffer.from(result.stderr).toString('base64')
  })
}

/**
 * Start the host-side Unix-socket broker and write the terminal shim/runtime
 * files. The broker is only useful when a terminal shell uses the generated
 * wrapper; it always re-checks the caller's current permission preset.
 */
export function startTerminalBroker(ctx) {
  const runtime = writeRuntimeFiles()
  try {
    unlinkSync(runtime.socketPath)
  } catch {
    // no stale socket
  }

  let gate
  try {
    gate = spawn(
      '/usr/bin/python3',
      [runtime.gatePath, runtime.socketPath, auditPath()],
      { stdio: ['pipe', 'pipe', 'ignore'] }
    )
  } catch {
    gate = null
  }

  let buffer = ''
  gate?.stdout?.setEncoding('utf8')
  gate?.stdout?.on('data', (chunk) => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) !== -1) {
      const raw = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      let message
      try {
        message = JSON.parse(raw)
      } catch {
        continue
      }
      if (!message || typeof message.id !== 'string' || typeof message.line !== 'string') continue
      const requestId = message.id
      const fakeSocket = {
        end(data) {
          if (!gate?.stdin?.writable) return
          gate.stdin.write(`${JSON.stringify({ id: requestId, data: String(data) })}\n`)
        }
      }
      handleRequest(ctx, message.line, fakeSocket).catch((error) => {
        fakeSocket.end(JSON.stringify({
          exitCode: 1,
          stdout_b64: '',
          stderr_b64: Buffer.from(`sudo broker 内部错误：${error instanceof Error ? error.message : String(error)}`).toString('base64')
        }) + '\n')
      })
    }
  })
  gate?.on('error', () => {})
  gate?.stdin?.on('error', () => {})

  return () => {
    try {
      gate?.kill('SIGTERM')
    } catch {
      // already gone
    }
    try {
      unlinkSync(runtime.socketPath)
    } catch {
      // already gone
    }
  }
}
