import { spawn } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { startTerminalBroker } from './broker.js'
import { confirmDangerous, detectDangerousCommand } from './danger.js'

export const name = 'sudo-mode'
export const inject = ['tools', 'permissionPresets', 'systemPrompt']

const PRESET_NAME = 'sudo-access'
const MAX_OUTPUT = 60_000
const TOOL_TIMEOUT_MS = 300_000

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function escapeMarkup(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function askpassText(purpose, command) {
  const shownPurpose = purpose.length > 600 ? `${purpose.slice(0, 600)}…` : purpose
  const shownCommand = command.length > 1200 ? `${command.slice(0, 1200)}…` : command
  return [
    'DSH 请求执行一条需要 root 权限的命令。',
    '',
    `作用：${escapeMarkup(shownPurpose)}`,
    '',
    '命令：',
    escapeMarkup(shownCommand),
    '',
    '核对无误后再输入 root 密码；取消不会执行。'
  ].join('\n')
}

/**
 * Write the SUDO_ASKPASS helper. It contains no password: zenity displays the
 * dialog and writes only the typed password to stdout, which sudo reads.
 */
function ensureAskpass() {
  const dir = join(dshHome(), 'sudo-mode')
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

function fail(command, purpose, message) {
  return {
    ok: false,
    exitCode: -1,
    stdout: '',
    stderr: message,
    command,
    purpose
  }
}

function truncate(text) {
  if (text.length <= MAX_OUTPUT) return text
  return `${text.slice(0, MAX_OUTPUT)}\n…（输出已截断，共 ${text.length} 字符）`
}

function createTool(ctx) {
  return {
  name: 'sudo_exec',
  description:
    '在「Sudo 访问」权限模式下执行一条需要 root 权限的 shell 命令。' +
    '调用前必须在 purpose 参数里用用户能看懂的话说明这条命令的作用；' +
    '调用时系统会弹出密码框，由用户手动输入 root 密码，密码不会进入对话、模型上下文或日志。' +
    '每次执行都会用 sudo -k 清除旧凭据，因此每次都需要重新输入密码。' +
    '只有用户明确要求系统级操作时才使用；不要用它代替普通文件修改，也不要用它绕过工作区外写入的审批。',
  parameters: {
    type: 'object',
    properties: {
      command: {
        type: 'string',
        description: '要交给 root shell 执行的完整命令（通过 /bin/bash -lc 执行）。'
      },
      purpose: {
        type: 'string',
        description: '用中文向用户说明这条命令的作用、影响范围以及为什么需要 root 权限。会显示在密码框和工具结果里。'
      },
      cwd: {
        type: 'string',
        description: '可选的工作目录绝对路径；默认使用 DSH 进程当前目录。'
      }
    },
    required: ['command', 'purpose'],
    additionalProperties: false
  },
  output: {
    schema: {
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        exitCode: { type: 'number' },
        stdout: { type: 'string' },
        stderr: { type: 'string' },
        command: { type: 'string' },
        purpose: { type: 'string' }
      },
      required: ['ok', 'exitCode', 'stdout', 'stderr', 'command', 'purpose'],
      additionalProperties: false
    },
    render(_args, value) {
      const lines = [
        `$ ${value.command}`,
        `作用：${value.purpose}`,
        `退出码：${value.exitCode}`
      ]
      if (value.stdout) lines.push('', 'stdout:', value.stdout)
      if (value.stderr) lines.push('', 'stderr:', value.stderr)
      lines.push('', '（root 密码由系统密码框收集，未写入对话或日志。）')
      return [{ type: 'text', text: lines.join('\n') }]
    }
  },
  timeoutMs: TOOL_TIMEOUT_MS,
  async execute(args, exec) {
    const command = typeof args.command === 'string' ? args.command.trim() : ''
    const purpose = typeof args.purpose === 'string' ? args.purpose.trim() : ''

    if (!command) return fail(command, purpose, 'command 不能为空。')
    if (!purpose) return fail(command, purpose, 'purpose 不能为空：必须先向用户说明命令的作用。')
    if (command.includes('\0')) return fail(command, purpose, 'command 不能包含 NUL 字符。')

    let current
    try {
      current = ctx.permissionPresets.current(exec.agent.session)
    } catch (error) {
      return fail(command, purpose, `无法读取当前权限模式：${error instanceof Error ? error.message : String(error)}`)
    }
    if (current !== PRESET_NAME) {
      return fail(
        command,
        purpose,
        `当前权限模式是「${current}」，不是「Sudo 访问」。请先在输入框下方的权限选择器里切换到「Sudo 访问」。`
      )
    }

    if (!existsSync('/usr/bin/sudo')) {
      return fail(command, purpose, '找不到 /usr/bin/sudo，无法执行 root 命令。')
    }
    if (!existsSync('/usr/bin/zenity')) {
      return fail(command, purpose, '找不到 /usr/bin/zenity，无法弹出密码框。请先安装 zenity。')
    }
    if (!existsSync('/usr/bin/python3')) {
      return fail(command, purpose, '找不到 /usr/bin/python3，无法启动隔离的密码框。')
    }

    let cwd = process.cwd()
    if (typeof args.cwd === 'string' && args.cwd.trim()) {
      cwd = args.cwd.trim()
      try {
        if (!statSync(cwd).isDirectory()) return fail(command, purpose, `cwd 不是目录：${cwd}`)
      } catch {
        return fail(command, purpose, `cwd 不存在或不可访问：${cwd}`)
      }
    }

    const danger = detectDangerousCommand(command)
    if (danger.dangerous) {
      const confirmed = await confirmDangerous(danger, command, purpose, exec.signal)
      if (!confirmed) return fail(command, purpose, '已取消：高危命令未通过二次确认，未执行。')
    }

    let askpass
    try {
      askpass = ensureAskpass()
    } catch (error) {
      return fail(command, purpose, `无法准备密码框脚本：${error instanceof Error ? error.message : String(error)}`)
    }

    let child
    try {
      child = spawn('/usr/bin/sudo', ['-A', '-k', '--', '/bin/bash', '-lc', command], {
        cwd,
        env: {
          ...process.env,
          SUDO_ASKPASS: askpass,
          SUDO_ASKPASS_REQUIRE: 'force',
          DSH_SUDO_TEXT: askpassText(purpose, command)
        },
        stdio: ['ignore', 'pipe', 'pipe']
      })
    } catch (error) {
      return fail(command, purpose, `启动 sudo 失败：${error instanceof Error ? error.message : String(error)}`)
    }

    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')

    let stdout = ''
    let stderr = ''
    let timedOut = false
    let aborted = false

    const take = (previous, chunk) => {
      if (previous.length >= MAX_OUTPUT) return previous
      const next = previous + chunk
      return next.length > MAX_OUTPUT ? next.slice(0, MAX_OUTPUT) : next
    }

    child.stdout.on('data', (chunk) => {
      stdout = take(stdout, chunk)
    })
    child.stderr.on('data', (chunk) => {
      stderr = take(stderr, chunk)
    })

    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGTERM')
    }, TOOL_TIMEOUT_MS)

    const onAbort = () => {
      aborted = true
      child.kill('SIGTERM')
    }
    if (exec.signal) {
      if (exec.signal.aborted) onAbort()
      else exec.signal.addEventListener('abort', onAbort, { once: true })
    }

    const result = await new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (exec.signal) exec.signal.removeEventListener('abort', onAbort)
        resolve(value)
      }

      child.on('error', (error) => {
        finish({ code: -1, error })
      })
      child.on('close', (code, signal) => {
        finish({ code: code ?? -1, signal })
      })
    })

    // Clear any timestamp sudo may have cached for this terminal.
    try {
      spawn('/usr/bin/sudo', ['-k'], { stdio: 'ignore' }).unref()
    } catch {
      // best effort only
    }

    let exitCode = result.code
    if (timedOut) {
      exitCode = -1
      stderr += `\n\n[sudo-mode] 命令超过 ${TOOL_TIMEOUT_MS / 1000} 秒，已终止。`
    } else if (aborted) {
      exitCode = -1
      stderr += '\n\n[sudo-mode] 命令已取消。'
    } else if (result.error) {
      exitCode = -1
      stderr += `\n\n[sudo-mode] ${result.error.message}`
    } else if (result.signal) {
      stderr += `\n\n[sudo-mode] 进程被信号 ${result.signal} 终止。`
    }

    return {
      ok: exitCode === 0,
      exitCode,
      stdout: truncate(stdout),
      stderr: truncate(stderr),
      command,
      purpose
    }
  }
  }
}

export function apply(ctx) {
  ctx.effect(() => ctx.tools.register(createTool(ctx)), 'sudo-mode.sudo_exec')
  ctx.effect(() => startTerminalBroker(ctx), 'sudo-mode.terminal-broker')
  ctx.effect(
    () =>
      ctx.systemPrompt.section({
        name: 'tool:sudo_exec',
        order: ctx.systemPrompt.getSectionOrder('TOOL_BASH') + 1,
        text:
          '在「Sudo 访问」权限模式下，需要 root 权限的命令必须调用 sudo_exec，不要用 bash 直接运行 sudo。' +
          '调用 sudo_exec 前必须用 purpose 向用户说明命令作用和影响；用户会在系统密码框里看到完整命令并手动输入 root 密码。' +
          '每次执行都会清除旧凭据，所以每次都要重新授权。普通命令继续使用 bash。' +
          '在 Sudo 访问模式下，DSH 终端的 `sudo <命令>` 会由 host broker 接管，同样显示命令并询问密码；' +
          '它只支持非交互命令，且本轮对话里的 sudo_exec 仍是助手执行 root 命令的首选。' +
          '普通文件修改仍用 write/edit；工作区外写入必须先带 sandbox_permissions 和 justification 请求升级并等待用户批准，不能用 sudo_exec 绕过。'
      }),
    'sudo-mode.prompt'
  )
}
