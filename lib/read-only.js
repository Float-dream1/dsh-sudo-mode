import { spawn } from 'node:child_process'

/**
 * Commands that only inspect files, processes or read-only system state.
 * This is deliberately a conservative allowlist: a command that is not
 * obviously read-only must go through the password path. It is not a security
 * boundary by itself; it only avoids a root password for harmless inspection.
 */
const READ_ONLY_COMMANDS = new Set([
  'ls', 'dir', 'vdir', 'tree', 'pwd', 'stat', 'file', 'readlink', 'realpath',
  'du', 'df', 'lsblk', 'blkid', 'findmnt', 'mount',
  'cat', 'head', 'tail', 'wc', 'nl', 'grep', 'egrep', 'fgrep', 'rg',
  'sort', 'uniq', 'cut', 'tr', 'rev', 'cmp', 'diff',
  'sha1sum', 'sha256sum', 'sha512sum', 'md5sum',
  'id', 'whoami', 'groups', 'uname', 'hostname', 'date', 'uptime', 'free',
  'lscpu', 'ps', 'ss', 'netstat', 'ip',
  'systemctl', 'journalctl', 'dmesg',
  'git', 'tar', 'unzip',
  'virsh', 'docker', 'lxc',
  'npm', 'pnpm'
])

const SHELL_META = /[;&|<>`$(){}\\\n\r]/

function tokensOf(text) {
  const tokens = []
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g
  let match
  while ((match = re.exec(text)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3])
  }
  return tokens
}

function has(args, ...needles) {
  return args.some((arg) => needles.includes(arg))
}

function findIsReadOnly(args) {
  return !args.some((arg) => /^-(?:exec|execdir|ok|okdir|delete|fprint|fprintf|fls)(?:=|$)/.test(arg))
}

function tarIsReadOnly(args) {
  const flags = args.filter((arg) => arg.startsWith('-'))
  if (flags.some((arg) => /^-[^-]*[xcruA]/.test(arg))) return false
  if (flags.some((arg) => ['--create', '--extract', '--append', '--update', '--delete'].includes(arg))) return false
  return flags.some((arg) => /^-[^-]*t/.test(arg) || arg === '--list')
}

function gitIsReadOnly(args) {
  if (!args.length) return false
  if (!['status', 'log', 'diff', 'show'].includes(args[0])) return false
  return !has(args, '--output', '-o')
}

function systemctlIsReadOnly(args) {
  if (!args.length) return false
  const sub = args[0]
  if (sub.startsWith('-')) return ['status', 'show', 'cat', 'is-active', 'is-enabled', 'is-failed', 'list-units', 'list-unit-files', 'list-timers', 'list-sockets'].includes(args[1])
  return ['status', 'show', 'cat', 'is-active', 'is-enabled', 'is-failed', 'list-units', 'list-unit-files', 'list-timers', 'list-sockets'].includes(sub)
}

function journalctlIsReadOnly(args) {
  return !args.some((arg) => /^--(?:vacuum|rotate|flush|sync|setup-keys|relinquish-var)/.test(arg))
}

function dmesgIsReadOnly(args) {
  return !has(args, '-c', '-C', '--clear', '--read-clear')
}

function dockerIsReadOnly(args) {
  if (!args.length) return false
  const sub = args.find((arg) => !arg.startsWith('-'))
  return ['ps', 'images', 'inspect', 'logs', 'version', 'info', 'stats'].includes(sub)
}

function virshIsReadOnly(args) {
  if (!args.length) return false
  const sub = args.find((arg) => !arg.startsWith('-'))
  return ['list', 'dominfo', 'domstate', 'version', 'nodeinfo'].includes(sub)
}

function lxcIsReadOnly(args) {
  if (!args.length) return false
  const sub = args.find((arg) => !arg.startsWith('-'))
  return ['list', 'info', 'show'].includes(sub)
}

function npmIsReadOnly(args) {
  if (!args.length) return false
  return ['ls', 'list', 'why', 'view', 'info', 'outdated'].includes(args[0])
}

function ipIsReadOnly(args) {
  if (!args.length) return false
  return !has(args, 'add', 'del', 'delete', 'flush', 'change', 'replace', 'set')
}

function mountIsReadOnly(args) {
  return args.length === 0 || args.every((arg) => arg === '-l' || arg === '--show-labels')
}

/**
 * Return true only for a single, simple, read-only command. Shell operators
 * are rejected so the command cannot become `ls; rm ...`, `find -delete`,
 * `cat >file`, command substitution, etc.
 */
export function isReadOnlyCommand(command) {
  if (typeof command !== 'string') return false
  const text = command.trim()
  if (!text || SHELL_META.test(text)) return false

  const tokens = tokensOf(text)
  if (!tokens.length) return false
  const name = tokens[0].split('/').pop()
  if (name === 'sudo' || !READ_ONLY_COMMANDS.has(name)) return false
  const args = tokens.slice(1)

  switch (name) {
    case 'find': return findIsReadOnly(args)
    case 'tar': return tarIsReadOnly(args)
    case 'git': return gitIsReadOnly(args)
    case 'systemctl': return systemctlIsReadOnly(args)
    case 'journalctl': return journalctlIsReadOnly(args)
    case 'dmesg': return dmesgIsReadOnly(args)
    case 'docker': return dockerIsReadOnly(args)
    case 'virsh': return virshIsReadOnly(args)
    case 'lxc': return lxcIsReadOnly(args)
    case 'npm':
    case 'pnpm': return npmIsReadOnly(args)
    case 'ip': return ipIsReadOnly(args)
    case 'mount': return mountIsReadOnly(args)
    case 'sort': return !has(args, '-o', '--output')
    case 'diff': return !has(args, '--output')
    case 'uniq': return args.filter((arg) => !arg.startsWith('-')).length <= 1
    default: return true
  }
}

/**
 * Run an already-confirmed read-only command as the current user. No sudo and
 * no password dialog are involved. Root-only paths will fail with the normal
 * permission error; the caller can tell the user to use the password path if
 * they really need privileged access.
 */
export function runReadOnlyCommand(command, cwd, {
  timeoutMs = 300_000,
  maxOutput = 60_000,
  signal
} = {}) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn('/bin/bash', ['-lc', command], {
        cwd,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe']
      })
    } catch (error) {
      resolve({ exitCode: -1, stdout: '', stderr: `无法启动只读命令：${error.message}` })
      return
    }

    let stdout = ''
    let stderr = ''
    let timedOut = false
    let aborted = false

    const take = (previous, chunk) => {
      if (previous.length >= maxOutput) return previous
      const next = previous + chunk
      return next.length > maxOutput ? next.slice(0, maxOutput) : next
    }

    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => { stdout = take(stdout, chunk) })
    child.stderr.on('data', (chunk) => { stderr = take(stderr, chunk) })

    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGTERM')
    }, timeoutMs)

    const onAbort = () => {
      aborted = true
      child.kill('SIGTERM')
    }
    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }

    child.on('error', (error) => {
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve({ exitCode: -1, stdout, stderr: `${stderr}\n${error.message}` })
    })
    child.on('close', (code, closeSignal) => {
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      let exitCode = code ?? -1
      if (timedOut) {
        exitCode = -1
        stderr += `\n[sudo-mode] 只读命令超过 ${timeoutMs / 1000} 秒，已终止。`
      } else if (aborted) {
        exitCode = -1
        stderr += '\n[sudo-mode] 只读命令已取消。'
      } else if (closeSignal) {
        stderr += `\n[sudo-mode] 进程被信号 ${closeSignal} 终止。`
      }
      resolve({ exitCode, stdout, stderr })
    })
  })
}
