import { isIP } from 'node:net'

/**
 * Private / special-use IPv4 ranges. Kept explicit so wildcard and CIDR
 * patterns can be compared by interval instead of by a fragile regex.
 */
const PRIVATE_V4 = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local
  ['172.16.0.0', 12],
  ['192.168.0.0', 16]
]

function ipv4ToInt(value) {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    result = ((result << 8) | octet) >>> 0
  }
  return result
}

function cidrRange(value, bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null
  if (value === null) return null
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  const start = (value & mask) >>> 0
  const end = (start | (~mask >>> 0)) >>> 0
  return [start, end]
}

function privateRanges() {
  return PRIVATE_V4
    .map(([address, bits]) => cidrRange(ipv4ToInt(address), bits))
    .filter(Boolean)
}

function overlaps(start, end, range) {
  return start <= range[1] && end >= range[0]
}

function parseIpv4Pattern(value) {
  const clean = value.replace(/^\[|\]$/g, '')
  const slash = clean.lastIndexOf('/')
  const address = slash === -1 ? clean : clean.slice(0, slash)
  const prefix = slash === -1 ? null : Number(clean.slice(slash + 1))
  const parts = address.split('.')
  if (parts.length !== 4) return null

  if (prefix !== null) {
    const numeric = ipv4ToInt(address)
    return cidrRange(numeric, prefix)
  }

  let low = 0
  let high = 0
  for (const part of parts) {
    if (part === '*') {
      low = (low << 8) >>> 0
      high = ((high << 8) | 255) >>> 0
      continue
    }
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    low = ((low << 8) | octet) >>> 0
    high = ((high << 8) | octet) >>> 0
  }
  return [low, high]
}

function isPrivateV4Address(value) {
  const numeric = ipv4ToInt(value)
  if (numeric === null) return false
  return privateRanges().some((range) => numeric >= range[0] && numeric <= range[1])
}

function isPrivateV6Address(value) {
  const clean = value.replace(/^\[|\]$/g, '').toLowerCase()
  if (isIP(clean) !== 6) return false
  if (clean === '::1' || clean === '::') return true
  if (/^fe[89ab][0-9a-f]:/.test(clean)) return true // fe80::/10
  if (/^f[cd][0-9a-f]{2}:/.test(clean)) return true // fc00::/7 ULA
  const mapped = clean.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (mapped) return isPrivateV4Address(mapped[1])
  return false
}

export function isPrivateHost(value) {
  const text = String(value || '').trim()
  if (!text) return false
  if (/^(?:localhost|.*\.local|.*\.localhost)$/i.test(text)) return true

  const v4 = parseIpv4Pattern(text)
  if (v4) return privateRanges().some((range) => overlaps(v4[0], v4[1], range))

  const v6 = text.replace(/^\[|\]$/g, '').split('%')[0]
  if (isIP(v6) === 6) return isPrivateV6Address(v6)
  return false
}

/**
 * Find private/LAN indicators in arbitrary shell text. This deliberately
 * recognises wildcard ranges (`192.168.*.*`), CIDR (`10.0.0.0/8`), explicit
 * private IPv4/IPv6 literals and `.local` names, because a model can express
 * the same destination in several spellings.
 */
export function hasPrivateHost(text) {
  const haystack = String(text || '')
  if (!haystack) return false
  if (/(?:^|[\s"'`@/])(?:localhost|[a-z0-9_.-]+\.local)(?:[\s"'`:;,)]|$)/i.test(haystack)) return true

  const v4Patterns = haystack.match(/(?:\d{1,3}|\*)\.(?:\d{1,3}|\*)\.(?:\d{1,3}|\*)\.(?:\d{1,3}|\*)(?:\/\d{1,2})?/g) || []
  for (const pattern of v4Patterns) {
    if (isPrivateHost(pattern)) return true
  }

  const v6Candidates = haystack.match(/\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]*::[0-9a-fA-F:.]*|(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*/g) || []
  for (const candidate of v6Candidates) {
    const address = candidate.replace(/^\[|\]$/g, '').split('%')[0]
    if (isIP(address) === 6 && isPrivateV6Address(address)) return true
  }

  return false
}

/**
 * First-queue network classification. These reasons never depend on the model
 * danger score; callers show them as hard review / critical confirmation.
 */
export function classifyNetwork(text) {
  const reasons = []
  if (hasPrivateHost(text)) {
    reasons.push('访问局域网/私网地址；局域网内任何操作都必须由用户审核')
  }
  if (/\bipaddress\b/i.test(String(text || ''))) {
    reasons.push('使用 ipaddress 解析网段；必须向用户说明用途并经用户审核')
  }
  return { reasons, categories: reasons.length > 0 ? ['lan'] : [] }
}
