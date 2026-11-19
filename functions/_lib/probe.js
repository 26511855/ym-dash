// probe.js — 探活与 URL 安全校验（SSRF 防护）
// 同步点：worker/worker.js 里有一份同逻辑副本（Worker 独立部署、不能跨目录 import）。
// 修改本文件的 validateUrl / probeUrl 时，必须同步修改 worker/worker.js，反之亦然。

// ---- IPv6 完整解析（C-20：自 ym-nav functions/_ssrf.js 搬入）----
// 旧版只认 ::1 / :: / fc00 / fe80 前缀与 ::ffff: 开头，漏了 ::a.b.c.d
// 兼容形式（如 ::127.0.0.1 直接放行）、文档段 2001:db8::/32、NAT64
// 64:ff9b::/96 与 6to4 2002::/16 内嵌的 IPv4。这里按段解析成 8 组再
// 逐项判断，内嵌 IPv4 交给 ipv4Blocked 复核。
function ipv4Blocked(a, b, c, d) {
  if ([a, b, c, d].some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 192 && b === 88 && c === 99) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224 && a < 240) return true;
  if (a >= 240) return true;
  return false;
}

function ipv6Blocked(host) {
  let h = String(host || '').toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  const zone = h.indexOf('%');
  if (zone >= 0) h = h.slice(0, zone);
  const lastColon = h.lastIndexOf(':');
  if (lastColon >= 0 && h.slice(lastColon + 1).includes('.')) {
    const p = h.slice(lastColon + 1).split('.').map(Number);
    if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    h = h.slice(0, lastColon + 1) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = h.split('::');
  if (halves.length > 2) return true;
  const parseSide = (s) => (s === '' ? [] : s.split(':').map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const left = parseSide(halves[0]);
  const right = halves.length === 2 ? parseSide(halves[1]) : [];
  if (left.some(Number.isNaN) || right.some(Number.isNaN)) return true;
  let g;
  if (halves.length === 2) {
    const missing = 8 - left.length - right.length;
    if (missing < 0) return true;
    g = [...left, ...Array(missing).fill(0), ...right];
  } else {
    if (left.length !== 8) return true;
    g = left;
  }
  const embeddedV4 = (hi, lo) => ipv4Blocked((hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255);
  if (g.every((x) => x === 0)) return true; // :: unspecified
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1 loopback
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return embeddedV4(g[6], g[7]); // ::ffff:a.b.c.d v4-mapped
  }
  if (g.slice(0, 6).every((x) => x === 0) && !(g[6] === 0 && g[7] <= 1)) {
    return embeddedV4(g[6], g[7]); // ::a.b.c.d v4-compatible (deprecated)
  }
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // 2001:db8::/32 documentation
  if (g[0] === 0x0064 && g[1] === 0xff9b) return embeddedV4(g[6], g[7]); // 64:ff9b::/96 NAT64
  if (g[0] === 0x2002) return embeddedV4(g[1], g[2]); // 2002::/16 6to4
  return false;
}

// 只允许 http/https；拒绝回环 / 内网 / 链路本地等地址，防止把本站当跳板扫内网（SSRF）。
export function validateUrl(raw) {
  let u;
  try { u = new URL(String(raw || '').trim()); }
  catch { return { ok: false, error: '网址格式不对' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, error: '只允许 http/https 网址' };
  }
  // 带用户名/密码的网址一律拒绝：会被原样存进 KV 并经公开接口返回，
  // 而且不少探针/客户端会把这段当凭证处理，风险大于用途
  if (u.username || u.password) {
    return { ok: false, error: '网址不能带用户名 / 密码' };
  }
  let host = u.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1); // IPv6 字面量去方括号（不同运行时返回不一）
  host = host.replace(/\.$/, ''); // 尾点规范化：localhost. / 192.168.1.1. 不能绕过下面的判断
  if (!host) return { ok: false, error: '网址缺少域名' };
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return { ok: false, error: '不允许本机 / 内网域名' };
  }
  // IPv4 字面量：直接复用 ipv4Blocked（与 DoH 路径同一口径，含
  // 192.0.2.0/24 等文档/保留段——旧版手写分支漏了这些段，见审计 #11）
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    if (ipv4Blocked(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]))) {
      return { ok: false, error: '不允许内网 / 回环 / 保留地址' };
    }
  }
  // IPv6 字面量（URL 解析后 hostname 不带方括号）：完整解析判断
  // （C-20，含 ::a.b.c.d 兼容形式 / 映射 / 文档段 / NAT64 / 6to4 内嵌）
  if (host.includes(':')) {
    if (ipv6Blocked(host)) return { ok: false, error: '不允许内网 / 回环 / 保留地址' };
  }
  return { ok: true, url: u.toString() };
}

// 解析后校验（2026-11-17 审计核验 #11）：validateUrl 只看字符串——域名
// 完全可以解析到内网地址（恶意域名 / DNS 重绑定），字符串校验拦不住。
// 探活每跳发请求前先经 DoH（cloudflare-dns.com）解析 A/AAAA，任一结果
// 落到内网 / 保留 / 文档示例段就拒绝。残余风险如实记：DoH 与 fetch 各自
// 解析存在 TOCTOU 窗口，Workers 没有可用的自定义解析器，这是平台内能
// 做到的最强校验。DoH 本身故障时 fail-closed：不发请求、本轮记为
// 「解析不确定」（审计 #11 复核后改口径，旧版 fail-open 只剩字符串
// 校验、等于把这层防护临时摘掉）。
export function ipBlocked(ip) {
  const s = String(ip || '').toLowerCase();
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) return ipv4Blocked(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]));
  if (s.includes(':')) return ipv6Blocked(s); // C-20：完整解析（同 validateUrl）
  return false;
}

// 子请求预算估算（H4）：一轮探活里单个站大约烧多少次子请求——
// 域名站 = DoH A + AAAA 两次解析 + 目标请求 1 次 = 3（重定向/CNAME
// 还会更多，这里按基线估）；IP 字面量站不查 DoH，只有目标请求 = 1。
// 加站时按这个数累计卡总预算，别等真跑起来撞免费版约 50 次上限。
export const SUBREQUEST_BUDGET = 45;
export function estimateProbeCost(url) {
  try {
    const h = new URL(String(url || '')).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')) return 1;
    return 3;
  } catch { return 3; }
}

// 返回 { blocked, uncertain }：DoH 查不到（请求失败/非 200/解析异常）
// 时 fail-closed——uncertain=true，调用方不发目标请求、如实记
// 「解析不确定」。旧版 fail-open（catch 直接放行）在 DoH 故障时只剩
// 字符串校验，恶意域名可趁解析服务抖动绕过（审计 #11 后半）。
// A 与 AAAA 并行查（旧版串行多等一轮）；Answer 里的 CNAME（type 5）
// 若没带最终地址，就顺着别名再查一轮（最多 3 跳，防别名环）。
export async function dnsBlocked(host, signal) {
  try {
    const q = async (name, type) => {
      const r = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type, {
        headers: { accept: 'application/dns-json' },
        signal,
      });
      if (!r.ok) throw new Error('doh http ' + r.status);
      const j = await r.json();
      return j.Answer || [];
    };
    let name = String(host || '').toLowerCase();
    const seen = new Set();
    for (let depth = 0; depth < 4; depth++) {
      if (seen.has(name)) throw new Error('cname loop');
      seen.add(name);
      const [aAns, aaaaAns] = await Promise.all([q(name, 'A'), q(name, 'AAAA')]);
      const answers = [...aAns, ...aaaaAns];
      const ips = answers.filter(a => a.type === 1 || a.type === 28).map(a => a.data);
      if (ips.length) return { blocked: ips.some(ip => ipBlocked(ip)), uncertain: false };
      const cname = answers.find(a => a.type === 5 && a.data);
      if (!cname) return { blocked: false, uncertain: false }; // 查到了、就是没地址：交给目标请求自然失败
      name = String(cname.data).replace(/\.$/, '').toLowerCase();
    }
    throw new Error('cname too deep');
  } catch {
    return { blocked: true, uncertain: true };
  }
}

// 探活一次：手动跟随重定向（最多 5 跳），每一跳都重新过 validateUrl——
// 自动 follow 时第二跳起就没人校验，一个公网网址 302 到内网地址
// 就能绕过 SSRF 防护。整条链共用一个超时预算。2xx/3xx 视为可用（up）。
// 返回 { up, status(0=没拿到响应), ms, err }
const MAX_HOPS = 5;
export async function probeUrl(url, timeoutMs = 10000) {
  const started = Date.now();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const done = (up, status, err = '') => ({ up, status, ms: Date.now() - started, err });
  try {
    let current = url;
    const visited = new Set(); // L1：自环重定向去重，别白烧子请求
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      if (visited.has(current)) return done(false, 0, '重定向成环，已拦截');
      visited.add(current);
      const v = validateUrl(current);
      if (!v.ok) return done(false, 0, hop === 0 ? '地址不安全，已跳过探活' : '重定向到不安全地址，已拦截');
      // 域名（非 IP 字面量）发请求前先解析校验，每一跳都查（#11）
      const hopHost = new URL(v.url).hostname.replace(/^\[|\]$/g, '').toLowerCase();
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hopHost) && !hopHost.includes(':')) {
        const dns = await dnsBlocked(hopHost, ctl.signal);
        if (dns.uncertain) return done(false, 0, '域名解析不确定（解析服务查询失败），本轮已跳过探活');
        if (dns.blocked) return done(false, 0, '域名解析到内网 / 保留地址，已拦截');
      }
      const res = await fetch(v.url, {
        method: 'GET',
        redirect: 'manual',
        signal: ctl.signal,
        headers: { 'user-agent': 'ym-dash-probe/1.0 (+status check)' },
      });
      const status = res.status || 0;
      // 不读正文，及时释放连接
      try { if (res.body && res.body.cancel) await res.body.cancel(); } catch { /* 忽略 */ }
      if (status >= 300 && status < 400) {
        const loc = res.headers.get('location');
        if (!loc) return done(true, status); // 无 Location 的 3xx，按可用计（与旧行为一致）
        if (hop === MAX_HOPS - 1) return done(false, status, '重定向次数过多');
        try { current = new URL(loc, v.url).toString(); }
        catch { return done(false, status, '重定向地址无效'); }
        continue;
      }
      return done(status >= 200 && status < 400, status, status >= 400 ? `HTTP ${status}` : '');
    }
    return done(false, 0, '重定向次数过多');
  } catch (e) {
    const err = (e && e.name === 'AbortError') ? `超时 ${timeoutMs / 1000}s` : String((e && e.message) || e || '网络错误').slice(0, 120);
    return done(false, 0, err);
  } finally {
    clearTimeout(timer);
  }
}
