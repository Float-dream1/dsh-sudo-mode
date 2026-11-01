import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'

const DANGEROUS_COMMANDS = new Map([
  ['rm', '删除文件；递归/强制删除可能不可恢复'],
  ['mv', '移动或覆盖文件；可能破坏系统路径'],
  ['chmod', '修改文件权限；可能使系统或服务无法启动'],
  ['chown', '修改文件所有者；可能使系统或服务无法启动'],
  ['kill', '终止进程；可能中断系统服务'],
  ['pkill', '按名称终止进程；可能中断系统服务'],
  ['killall', '终止同名进程；可能中断系统服务'],
  ['reboot', '重启系统'],
  ['shutdown', '关闭或重启系统'],
  ['poweroff', '关闭系统'],
  ['halt', '停止系统'],
  ['mkfs', '格式化文件系统；可能丢失数据'],
  ['mke2fs', '格式化文件系统；可能丢失数据'],
  ['wipefs', '清除文件系统/分区签名；可能丢失数据'],
  ['fdisk', '修改磁盘分区表；可能丢失数据'],
  ['parted', '修改磁盘分区表；可能丢失数据'],
  ['sgdisk', '修改 GPT 分区表；可能丢失数据'],
  ['sfdisk', '修改磁盘分区表；可能丢失数据'],
  ['dd', '直接写块设备；可能覆盖磁盘数据'],
  ['efibootmgr', '修改 EFI 启动项；可能导致无法启动'],
  ['grub-install', '重写 GRUB 引导；可能导致无法启动'],
  ['grub-mkconfig', '重写 GRUB 配置；可能导致无法启动'],
  ['update-grub', '重写 GRUB 配置；可能导致无法启动'],
  ['bootctl', '修改 systemd-boot/EFI 引导；可能导致无法启动'],
  ['refind-install', '安装/修改 rEFInd 引导；可能导致无法启动'],
  ['systemd-boot', '修改 systemd-boot 引导；可能导致无法启动']
])

const WRAPPERS = new Set([
  'sudo', 'env', 'command', 'nohup', 'time', 'exec', 'then', 'do', 'else',
  'if', 'while', 'until', '!', '{', '('
])

function escapeMarkup(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function truncate(text, max = 1200) {
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function stripQuotes(token) {
  return token.replace(/^['"]|['"]$/g, '')
}

function commandName(token) {
  return stripQuotes(token).split('/').pop() || ''
}

/**
 * Split a shell command into top-level segments. This deliberately does not
 * try to be a complete shell parser; it only needs command boundaries for the
 * dangerous-command classifier.
 */
function splitSegments(command) {
  const segments = []
  let current = ''
  let quote = ''
  let escaped = false

  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]
    if (escaped) {
      current += char
      escaped = false
      continue
    }
    if (char === '\\') {
      current += char
      escaped = true
      continue
    }
    if (quote) {
      current += char
      if (char === quote) quote = ''
      continue
    }
    if (char === '"' || char === "'") {
      current += char
      quote = char
      continue
    }
    if (char === '\n' || char === ';' || char === '|') {
      if (current.trim()) segments.push(current)
      current = ''
      continue
    }
    if (char === '&') {
      if (command[i + 1] === '&') {
        if (current.trim()) segments.push(current)
        current = ''
        i += 1
      } else {
        current += char
      }
      continue
    }
    current += char
  }
  if (current.trim()) segments.push(current)
  return segments
}

function tokenize(segment) {
  const tokens = []
  let current = ''
  let quote = ''
  let escaped = false
  for (const char of segment) {
    if (escaped) {
      current += char
      escaped = false
      continue
    }
    if (char === '\\') {
      escaped = true
      continue
    }
    if (quote) {
      if (char === quote) quote = ''
      else current += char
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      continue
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current)
        current = ''
      }
      continue
    }
    current += char
  }
  if (current) tokens.push(current)
  return tokens
}

function skipWrapper(tokens, index) {
  let i = index
  while (i < tokens.length) {
    const token = tokens[i]
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
      i += 1
      continue
    }
    const base = commandName(token)
    if (!WRAPPERS.has(base)) return i
    if (base === 'sudo') {
      i += 1
      while (i < tokens.length && tokens[i].startsWith('-')) {
        const option = tokens[i]
        i += 1
        if ((option === '-u' || option === '-g' || option === '-p') && i < tokens.length) i += 1
      }
      continue
    }
    if (base === 'env') {
      i += 1
      while (i < tokens.length && (tokens[i].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]))) i += 1
      continue
    }
    i += 1
  }
  return i
}

function addReason(reasons, reason) {
  if (!reasons.includes(reason)) reasons.push(reason)
}

/**
 * Classify only genuinely destructive root commands. The caller still shows a
 * second confirmation dialog; this function merely decides whether to show it.
 */
export function detectDangerousCommand(command) {
  const reasons = []
  const text = String(command || '')

  for (const segment of splitSegments(text)) {
    const tokens = tokenize(segment)
    const index = skipWrapper(tokens, 0)
    const name = commandName(tokens[index] || '')
    if (!name) continue

    if (DANGEROUS_COMMANDS.has(name)) {
      addReason(reasons, DANGEROUS_COMMANDS.get(name))
    }

    if (name === 'systemctl') {
      const subcommand = tokens.slice(index + 1).find((token) => !token.startsWith('-'))
      if (subcommand === 'reboot' || subcommand === 'poweroff') {
        addReason(reasons, subcommand === 'reboot' ? '重启系统' : '关闭系统')
      }
    }

    if (name === 'find') {
      const joined = tokens.join(' ')
      if (/\s-delete\b/.test(joined) || /\s-exec(?:dir)?\s+(?:\S*\/)?rm\b/.test(joined)) {
        addReason(reasons, 'find 删除/执行删除；可能不可恢复')
      }
    }

    if (name === 'bash' || name === 'sh' || name === 'zsh') {
      const dashC = tokens.findIndex((token) => token === '-c')
      if (dashC !== -1 && tokens[dashC + 1]) {
        const nested = detectDangerousCommand(tokens.slice(dashC + 1).join(' '))
        for (const reason of nested.reasons) addReason(reasons, reason)
      }
    }
  }

  // Fallbacks for patterns that are hard to attribute to one segment.
  if (/\brm\s+(?:-[^\s]*[rRfF]|--recursive|--force)\b/.test(text)) {
    addReason(reasons, '删除文件；递归/强制删除可能不可恢复')
  }
  if (/\bdd\s+(?:if|of)=/.test(text)) {
    addReason(reasons, '直接写块设备；可能覆盖磁盘数据')
  }
  if (/\b(?:mkfs(?:\.\w+)?|mke2fs|wipefs)\b/.test(text)) {
    addReason(reasons, '格式化/清除文件系统；可能丢失数据')
  }
  if (/\b(?:efibootmgr|grub-install|grub-mkconfig|update-grub|bootctl|refind-install)\b/.test(text)) {
    addReason(reasons, '修改 EFI/引导配置；可能导致无法启动')
  }
  if (/(?:^|[\s"'`])(?:\/boot\/efi|\/boot\/loader|\/etc\/default\/grub|\/boot\/grub|\/etc\/fstab)(?:[\s"'`]|$)/.test(text)) {
    addReason(reasons, '涉及引导或挂载配置；修改后可能导致无法启动')
  }
  if (/\binit\s+[06]\b/.test(text)) {
    addReason(reasons, '切换运行级别/重启或关机')
  }
  if (/:\s*\(\s*\)\s*\{/.test(text)) {
    addReason(reasons, '疑似 fork bomb；可能耗尽系统进程')
  }

  return { dangerous: reasons.length > 0, reasons }
}

export const SCORE_THRESHOLDS = {
  command: 80,
  script: 70
}

/**
 * Decide which confirmation (if any) a root command needs.
 *
 * Ordering is intentional and security-relevant:
 * 1. the hard-coded blacklist always runs first and cannot be overridden by a
 *    model-provided score or by prompt text;
 * 2. only if the blacklist misses do we look at the model's score.
 */
export function confirmationFor({ command, purpose = '', score, kind = 'command' }) {
  const blacklist = detectDangerousCommand(command)
  if (blacklist.dangerous) {
    return {
      level: 'critical',
      reasons: blacklist.reasons,
      command,
      purpose,
      kind,
      score: null,
      threshold: null
    }
  }

  const threshold = SCORE_THRESHOLDS[kind] ?? SCORE_THRESHOLDS.command
  if (Number.isInteger(score) && score > threshold) {
    return {
      level: 'high',
      reasons: [`模型评估危险度 ${score}/100，超过${kind === 'script' ? '脚本' : '单条命令'}阈值 ${threshold}`],
      command,
      purpose,
      kind,
      score,
      threshold
    }
  }

  return null
}

/**
 * Show a separate high-risk confirmation before the sudo password dialog.
 * Exit 0 is a deliberate "继续执行"; anything else keeps the command unrun.
 *
 * Blacklist hits use a red critical dialog; model-score hits use a yellow
 * high-risk dialog. All user-controlled text is Pango-escaped.
 */
export function confirmDangerous(confirmation, signal) {
  return new Promise((resolve) => {
    if (!existsSync('/usr/bin/zenity')) {
      resolve(false)
      return
    }

    const critical = confirmation.level === 'critical'
    const color = critical ? '#c00000' : '#b58900'
    const title = critical ? 'DSH 极高危命令二次确认' : 'DSH 高风险命令二次确认'
    const heading = critical
      ? '极高危险命令（黑名单命中）'
      : `高风险命令（模型评分 ${confirmation.score}/100）`
    const intro = critical
      ? '这条命令命中系统写死的高危黑名单。它不需要模型打分，也不会被模型评分覆盖。'
      : `这条命令没有命中黑名单，但模型认为它的危险度超过阈值 ${confirmation.threshold}。`

    const riskText = (confirmation.reasons || []).join('；') || '该命令可能影响系统'
    const lines = [
      `<span foreground="${color}" size="x-large" weight="bold">${heading}</span>`,
      '',
      `<span foreground="${color}" weight="bold">${intro}</span>`,
      '',
      `风险：${escapeMarkup(riskText)}`
    ]
    if (confirmation.purpose) lines.push('', `作用：${escapeMarkup(confirmation.purpose)}`)
    lines.push(
      '',
      '命令：',
      `<span font_family="monospace">${escapeMarkup(truncate(confirmation.command))}</span>`,
      '',
      '点“继续执行”后才会进入密码框；点“取消”不会执行。'
    )

    let child
    try {
      child = spawn('/usr/bin/zenity', [
        '--question',
        `--title=${title}`,
        `--text=${lines.join('\n')}`,
        '--ok-label=继续执行',
        '--cancel-label=取消',
        '--default-cancel',
        '--width=700'
      ], { stdio: 'ignore' })
    } catch {
      resolve(false)
      return
    }

    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve(value)
    }
    const onAbort = () => {
      try {
        child.kill('SIGTERM')
      } catch {
        // best effort
      }
      finish(false)
    }
    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }

    child.on('error', () => finish(false))
    child.on('close', (code) => finish(code === 0))
  })
}
