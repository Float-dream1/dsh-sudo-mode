import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import {
  confirmationTimeoutMessage,
  confirmTimeoutSeconds,
  displayEnv,
  NO_DISPLAY_MESSAGE,
  resolveXDisplay
} from './display.js'
import { classifyNetwork, hasPrivateHost } from './network.js'

/**
 * Hard-coded destructive commands. This list is intentionally independent of
 * the model and of the model's danger score: a hit is always a red critical
 * confirmation, and a brute-force hit is refused outright.
 */
const DANGEROUS_COMMANDS = new Map([
  ['rm', '删除文件；递归/强制删除可能不可恢复'],
  ['unlink', '删除文件；可能不可恢复'],
  ['shred', '覆写并删除文件；可能不可恢复'],
  ['truncate', '截断/清空文件；可能丢失数据'],
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
  ['systemd-boot', '修改 systemd-boot 引导；可能导致无法启动'],
  ['virsh', '管理虚拟机；停止/销毁/修改虚拟机可能中断正在工作的虚拟机'],
  ['docker', '管理容器；停止/删除/修改容器可能中断正在工作的服务'],
  ['lxc', '管理 LXC 容器；停止/修改容器可能中断正在工作的服务'],
  ['lxd', '管理 LXD 实例；停止/修改实例可能中断正在工作的服务']
])

const SSH_COMMANDS = new Map([
  ['ssh', 'SSH 登录/连接其他计算机；必须由用户审核'],
  ['scp', '通过 SSH 复制文件到其他计算机；必须由用户审核'],
  ['sftp', '通过 SSH 访问其他计算机文件；必须由用户审核'],
  ['sshpass', '非交互 SSH 密码登录；必须由用户审核，且禁止用于猜测密码'],
  ['autossh', '自动维持 SSH 连接；必须由用户审核'],
  ['mosh', '通过 SSH 建立远程终端；必须由用户审核']
])

const LAN_TOOLS = new Map([
  ['nmap', '网络探测/扫描；可能访问局域网其他计算机'],
  ['nc', '网络连接/监听；可能访问局域网其他计算机'],
  ['netcat', '网络连接/监听；可能访问局域网其他计算机'],
  ['telnet', '明文远程登录；可能访问局域网其他计算机'],
  ['arp-scan', '扫描局域网主机；必须由用户审核'],
  ['fping', '批量探测局域网主机；必须由用户审核'],
  ['smbclient', '访问局域网 SMB 共享；必须由用户审核'],
  ['rdesktop', '远程桌面连接；必须由用户审核'],
  ['vncviewer', 'VNC 远程桌面连接；必须由用户审核']
])

const SCREEN_CAPTURE_COMMANDS = new Map([
  ['spectacle', '读取屏幕内容，可能包含密码管理器、聊天和私人信息'],
  ['grim', '读取屏幕内容，可能包含密码管理器、聊天和私人信息'],
  ['scrot', '读取屏幕内容，可能包含密码管理器、聊天和私人信息'],
  ['flameshot', '读取屏幕内容，可能包含密码管理器、聊天和私人信息'],
  ['maim', '读取屏幕内容，可能包含密码管理器、聊天和私人信息'],
  ['xwd', '读取屏幕内容，可能包含密码管理器、聊天和私人信息'],
  ['gnome-screenshot', '读取屏幕内容，可能包含密码管理器、聊天和私人信息']
])

function screenCaptureReason(name, joined) {
  if (SCREEN_CAPTURE_COMMANDS.has(name)) return SCREEN_CAPTURE_COMMANDS.get(name)
  if (name === 'import' && /(?:-window\s+root|-screen|(?:^|\s)x:)/.test(joined)) {
    return '读取屏幕内容，可能包含密码管理器、聊天和私人信息'
  }
  if (name === 'ffmpeg' && /(?:-f\s+x11grab|\bx11grab\b)/.test(joined)) {
    return '录制屏幕内容，可能包含密码管理器、聊天和私人信息'
  }
  if (name === 'xdotool' && /(?:getwindowfocus|getactivewindow)/.test(joined)) {
    return '读取当前窗口/屏幕内容，可能包含密码管理器、聊天和私人信息'
  }
  return null
}

const BRUTEFORCE_COMMANDS = new Map([
  ['hydra', '暴力破解/密码猜测工具；绝对禁止'],
  ['sshpass', '非交互密码登录/猜测工具；绝对禁止用于 root 密码'],
  ['john', '密码哈希破解工具；绝对禁止'],
  ['hashcat', '密码哈希破解工具；绝对禁止'],
  ['medusa', '暴力破解/密码猜测工具；绝对禁止'],
  ['patator', '暴力破解/密码猜测工具；绝对禁止'],
  ['ncrack', '暴力破解/密码猜测工具；绝对禁止'],
  ['crowbar', '暴力破解/密码猜测工具；绝对禁止'],
  ['brutespray', '自动化密码猜测工具；绝对禁止'],
  ['crackmapexec', '凭据爆破/横向移动工具；绝对禁止'],
  ['nxc', '凭据爆破/横向移动工具；绝对禁止'],
  ['chntpw', '修改/破解 Windows 密码工具；绝对禁止']
])

const VIRSH_CONFIG_SUBCOMMANDS = new Set([
  'edit', 'define', 'undefine', 'create', 'destroy', 'shutdown', 'reboot',
  'reset', 'suspend', 'resume', 'attach-device', 'detach-device',
  'attach-interface', 'detach-interface', 'setmem', 'setmaxmem', 'setvcpus',
  'set-user', 'qemu-agent-command', 'guest-exec'
])

const WRAPPERS = new Set([
  'sudo', 'doas', 'pkexec', 'env', 'command', 'builtin', 'nohup', 'time',
  'exec', 'then', 'do', 'else', 'if', 'while', 'until', '!', '{', '(',
  'xargs', 'parallel', 'timeout', 'nice', 'ionice', 'stdbuf', 'setsid',
  'chroot', 'busybox', 'toybox', 'su'
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

/**
 * Normalize shell spelling before classification. This is not a shell parser;
 * it removes common spelling differences so `r\m`, `r''m`, `${IFS}` and
 * line-continuation tricks collapse to the same words. Commands are still
 * executed exactly as supplied.
 */
function normalizeCommand(value) {
  return String(value || '')
    .replace(/\\\r?\n/g, ' ')
    .replace(/\$\{IFS\}|\$IFS/g, ' ')
    .replace(/\\([\s\S])/g, '$1')
    .replace(/['"]/g, '')
    .replace(/(^|[\s;|&])#.*$/gm, '$1')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase()
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
    i += 1

    if (base === 'sudo' || base === 'doas' || base === 'pkexec') {
      while (i < tokens.length && tokens[i].startsWith('-')) {
        const option = tokens[i]
        i += 1
        if ((option === '-u' || option === '-g' || option === '-p' || option === '-C') && i < tokens.length) i += 1
      }
      continue
    }

    if (base === 'env') {
      while (i < tokens.length && (tokens[i].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]))) i += 1
      continue
    }

    if (base === 'timeout') {
      while (i < tokens.length && tokens[i].startsWith('-')) i += 1
      if (i < tokens.length && /^\d+(?:\.\d+)?[smhd]?$/.test(tokens[i])) i += 1
      continue
    }

    if (base === 'nice') {
      while (i < tokens.length && tokens[i].startsWith('-')) {
        if (tokens[i] === '-n' && i + 1 < tokens.length) i += 2
        else i += 1
      }
      continue
    }

    if (base === 'xargs' || base === 'parallel') {
      while (i < tokens.length && tokens[i].startsWith('-')) i += 1
      continue
    }

    if (base === 'chroot') {
      while (i < tokens.length && tokens[i].startsWith('-')) i += 1
      if (i < tokens.length) i += 1
      continue
    }

    while (i < tokens.length && tokens[i].startsWith('-')) i += 1
    continue
  }
  return i
}

function firstNonOption(tokens) {
  return tokens.find((token) => !token.startsWith('-')) || ''
}

function addReason(reasons, categories, reason, category = 'destructive') {
  if (!reasons.includes(reason)) reasons.push(reason)
  categories.add(category)
}

/**
 * Detect attempts to brute-force, guess, or crack any password. This is a hard
 * rule: callers must refuse these commands, not merely ask for confirmation.
 */
export function detectPasswordBruteForce(command) {
  const text = normalizeCommand(command)
  const reasons = []

  for (const segment of splitSegments(text)) {
    const tokens = tokenize(segment)
    const index = skipWrapper(tokens, 0)
    const name = commandName(tokens[index] || '')
    if (!name) continue

    if (BRUTEFORCE_COMMANDS.has(name)) {
      if (!reasons.includes(BRUTEFORCE_COMMANDS.get(name))) reasons.push(BRUTEFORCE_COMMANDS.get(name))
    }
    if (name === 'nmap' && /(?:brute|ssh-brute)/.test(segment)) {
      if (!reasons.includes('网络扫描中的密码爆破脚本；绝对禁止')) reasons.push('网络扫描中的密码爆破脚本；绝对禁止')
    }
    if (name === 'expect' && /\b(?:su|ssh|sshpass)\b/.test(segment)) {
      if (!reasons.includes('用 expect 自动输入/猜测密码；绝对禁止')) reasons.push('用 expect 自动输入/猜测密码；绝对禁止')
    }
    if ((name === 'su' || name === 'ssh' || name === 'sshpass') && /\b(?:echo|printf)\b[^|]*\|/.test(segment)) {
      if (!reasons.includes('把密码通过管道喂给 su/ssh；绝对禁止')) reasons.push('把密码通过管道喂给 su/ssh；绝对禁止')
    }
  }

  if (/\b(?:for|while|until)\b[\s\S]{0,300}\b(?:su|sshpass)\b/.test(text)) {
    if (!reasons.includes('循环尝试 su/ssh 密码；绝对禁止')) reasons.push('循环尝试 su/ssh 密码；绝对禁止')
  }
  if (/\b(?:echo|printf|cat)\b[^|]*\|\s*(?:su|ssh|sshpass)\b/.test(text)) {
    if (!reasons.includes('把密码通过管道喂给 su/ssh；绝对禁止')) reasons.push('把密码通过管道喂给 su/ssh；绝对禁止')
  }
  if (/\b(?:john|hashcat|unshadow)\b/.test(text) && /(?:shadow|gshadow)/.test(text)) {
    if (!reasons.includes('读取/破解密码哈希；绝对禁止')) reasons.push('读取/破解密码哈希；绝对禁止')
  }

  return { dangerous: reasons.length > 0, reasons }
}

/**
 * Classify root commands, network access and virtualization operations.
 *
 * The blacklist is intentionally conservative: it may ask for confirmation on
 * a harmless command, but it must not silently allow a destructive one. The
 * caller still shows the confirmation dialog; this function only decides
 * whether a confirmation is mandatory.
 */
export function detectDangerousCommand(command) {
  const reasons = []
  const categories = new Set()
  const text = normalizeCommand(command)

  for (const segment of splitSegments(text)) {
    const tokens = tokenize(segment)
    const index = skipWrapper(tokens, 0)
    const name = commandName(tokens[index] || '')
    if (!name) continue
    const rest = tokens.slice(index + 1)
    const joined = rest.join(' ')

    const capture = screenCaptureReason(name, joined)
    if (capture) addReason(reasons, categories, capture, 'screen-capture')

    if (DANGEROUS_COMMANDS.has(name)) {
      addReason(reasons, categories, DANGEROUS_COMMANDS.get(name), 'destructive')
      if (name === 'virsh' || name === 'docker' || name === 'lxc' || name === 'lxd') {
        categories.add('virtualization')
      }
    }

    if (SSH_COMMANDS.has(name)) {
      addReason(reasons, categories, SSH_COMMANDS.get(name), 'ssh')
    }

    if (LAN_TOOLS.has(name)) {
      addReason(reasons, categories, LAN_TOOLS.get(name), 'lan')
    }

    if (name === 'ping' && hasPrivateHost(text)) {
      addReason(reasons, categories, '探测局域网主机；必须由用户审核', 'lan')
    }

    if ((name === 'curl' || name === 'wget') && hasPrivateHost(text)) {
      addReason(reasons, categories, '访问局域网地址；必须由用户审核', 'lan')
    }

    if (name === 'rsync' && (/[^:\s]+:/.test(joined) || /\bssh\b/.test(joined))) {
      addReason(reasons, categories, '通过 SSH 同步到其他计算机；必须由用户审核', 'ssh')
    }

    if (name === 'git' && (/git@|ssh:\/\//.test(joined))) {
      addReason(reasons, categories, '通过 SSH 访问远程 Git 仓库；必须由用户审核', 'ssh')
    }

    if (name === 'systemctl') {
      const subcommand = firstNonOption(rest)
      if (subcommand === 'reboot' || subcommand === 'poweroff') {
        addReason(reasons, categories, subcommand === 'reboot' ? '重启系统' : '关闭系统', 'boot')
      }
    }

    if (name === 'find') {
      if (/\s-delete\b/.test(joined) || /\s-exec(?:dir)?\s+(?:\S*\/)?rm\b/.test(joined)) {
        addReason(reasons, categories, 'find 删除/执行删除；可能不可恢复', 'destructive')
      }
    }

    if (name === 'virsh') {
      const subcommand = firstNonOption(rest)
      if (VIRSH_CONFIG_SUBCOMMANDS.has(subcommand)) {
        addReason(reasons, categories, '修改/停止虚拟机配置或用户；必须由用户审核', 'vm-config')
      }
    }

    if (name === 'lxc' || name === 'lxd') {
      const subcommand = firstNonOption(rest)
      if (subcommand === 'config' || /\b(?:useradd|usermod|passwd|userdel)\b/.test(joined)) {
        addReason(reasons, categories, '修改容器配置或用户；必须由用户审核', 'vm-config')
      }
    }

    if (name === 'docker') {
      if (/(?:^|\s)(?:--user|-u|useradd|usermod|passwd|userdel|--privileged|--pid=host|--network=host)\b/.test(joined) ||
          /-v\s+\/:\/host\b/.test(joined)) {
        addReason(reasons, categories, '修改容器用户/宿主配置或提升容器权限；必须由用户审核', 'vm-config')
      }
    }

    if (name === 'bash' || name === 'sh' || name === 'zsh' || name === 'dash' || name === 'ksh') {
      const dashC = tokens.findIndex((token) => token === '-c')
      if (dashC !== -1 && tokens[dashC + 1]) {
        const nested = detectDangerousCommand(tokens.slice(dashC + 1).join(' '))
        for (const category of nested.categories) categories.add(category)
        for (const reason of nested.reasons) addReason(reasons, categories, reason, nested.categories[0] || 'destructive')
      }
    }

    if (name === 'eval' || name === 'source') {
      const nested = detectDangerousCommand(rest.join(' '))
      for (const category of nested.categories) categories.add(category)
      for (const reason of nested.reasons) addReason(reasons, categories, reason, nested.categories[0] || 'destructive')
    }

    if (name === 'su' || name === 'doas' || name === 'pkexec') {
      const dashC = tokens.findIndex((token) => token === '-c' || token === '--command')
      if (dashC !== -1 && tokens[dashC + 1]) {
        const nested = detectDangerousCommand(tokens.slice(dashC + 1).join(' '))
        for (const category of nested.categories) categories.add(category)
        for (const reason of nested.reasons) addReason(reasons, categories, reason, nested.categories[0] || 'destructive')
      }
    }
  }

  // Fallbacks for patterns that are hard to attribute to one segment.
  if (/\brm\s+(?:-[^\s]*[rRfF]|--recursive|--force)\b/.test(text)) {
    addReason(reasons, categories, '删除文件；递归/强制删除可能不可恢复', 'destructive')
  }
  if (/\bdd\s+(?:if|of)=/.test(text)) {
    addReason(reasons, categories, '直接写块设备；可能覆盖磁盘数据', 'destructive')
  }
  if (/\b(?:mkfs(?:\.\w+)?|mke2fs|wipefs)\b/.test(text)) {
    addReason(reasons, categories, '格式化/清除文件系统；可能丢失数据', 'destructive')
  }
  if (/\b(?:efibootmgr|grub-install|grub-mkconfig|update-grub|bootctl|refind-install)\b/.test(text)) {
    addReason(reasons, categories, '修改 EFI/引导配置；可能导致无法启动', 'boot')
  }
  if (/(?:^|[\s"'`])(?:\/boot\/efi|\/boot\/loader|\/etc\/default\/grub|\/boot\/grub|\/etc\/fstab)(?:[\s"'`]|$)/.test(text)) {
    addReason(reasons, categories, '涉及引导或挂载配置；修改后可能导致无法启动', 'boot')
  }
  if (/\binit\s+[06]\b/.test(text)) {
    addReason(reasons, categories, '切换运行级别/重启或关机', 'boot')
  }
  if (/:\s*\(\s*\)\s*\{/.test(text)) {
    addReason(reasons, categories, '疑似 fork bomb；可能耗尽系统进程', 'destructive')
  }
  if (/\b(?:base64|xxd|openssl)\b[^\n|]*\|\s*(?:bash|sh|zsh)\b/.test(text)) {
    addReason(reasons, categories, '编码/混淆后执行命令；必须由用户审核', 'obfuscation')
  }
  if (hasPrivateHost(text) &&
      /\b(?:ssh|scp|sftp|rsync|curl|wget|nmap|nc|netcat|ping|telnet|smbclient|ipaddress)\b/.test(text)) {
    addReason(reasons, categories, '访问局域网其他计算机；必须由用户审核', 'lan')
  }

  const network = classifyNetwork(text)
  for (const reason of network.reasons) addReason(reasons, categories, reason, 'lan')

  const brute = detectPasswordBruteForce(text)
  for (const reason of brute.reasons) addReason(reasons, categories, reason, 'bruteforce')

  return { dangerous: reasons.length > 0, reasons, categories: [...categories] }
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
export function confirmDangerous(confirmation, signal, displayInfo) {
  return new Promise((resolve) => {
    const display = displayInfo === undefined ? resolveXDisplay() : displayInfo
    if (!display) {
      resolve({ confirmed: false, reason: 'no-display', message: NO_DISPLAY_MESSAGE })
      return
    }
    if (!existsSync('/usr/bin/zenity')) {
      resolve({ confirmed: false, reason: 'unavailable' })
      return
    }

    const readOnly = confirmation.readOnly === true
    const critical = confirmation.level === 'critical'
    const color = critical ? '#c00000' : readOnly ? '#2e7d32' : '#b58900'
    const title = readOnly
      ? 'DSH 只读命令确认'
      : critical ? 'DSH 极高危命令二次确认' : 'DSH 高风险命令二次确认'
    const heading = readOnly
      ? critical ? '极高危只读命令（黑名单命中）' : '只读命令（不提权）'
      : critical
        ? '极高危险命令（黑名单命中）'
        : `高风险命令（模型评分 ${confirmation.score}/100）`
    const intro = readOnly
      ? '这是只读命令；不会请求 root 密码，确认后以当前用户执行。若目标只有 root 可读，会返回权限错误。'
      : critical
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
      readOnly
        ? '点“继续执行”后以当前用户运行；点“取消”不会执行。'
        : '点“继续执行”后才会进入密码框；点“取消”不会执行。'
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
      ], {
        stdio: 'ignore',
        env: displayEnv(display.display, display.xauth)
      })
    } catch {
      resolve({ confirmed: false, reason: 'unavailable' })
      return
    }

    let settled = false
    let timer = null
    const finish = (result) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve(result)
    }
    const onAbort = () => {
      try {
        child.kill('SIGTERM')
      } catch {
        // best effort
      }
      finish({ confirmed: false, reason: 'aborted' })
    }
    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }

    const timeoutSeconds = confirmTimeoutSeconds()
    if (!settled && timeoutSeconds > 0) {
      timer = setTimeout(() => {
        try {
          child.kill('SIGTERM')
        } catch {
          // best effort
        }
        finish({
          confirmed: false,
          reason: 'timeout',
          message: confirmationTimeoutMessage(timeoutSeconds)
        })
      }, timeoutSeconds * 1000)
    }

    child.on('error', () => finish({ confirmed: false, reason: 'unavailable' }))
    child.on('close', (code) => finish(
      code === 0
        ? { confirmed: true }
        : { confirmed: false, reason: 'cancel' }
    ))
  })
}
