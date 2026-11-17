// ym-dash 探活 DNS 解析校验测试（node tests/probe-dns.mjs）
// fetch 全打桩：DoH 按域名返回预设解析结果，目标站按 URL 返回预设响应。
import { probeUrl, ipBlocked } from '../functions/_lib/probe.js';

const DNS = {
  'good.example.com': ['93.184.216.34'],
  'evil.example.com': ['192.168.1.1'],
  'mixed.example.com': ['93.184.216.34', '10.0.0.5'],
  'v6evil.example.com': ['fd00::1'],
  'redir.example.com': ['93.184.216.34'],
};
let fetchedTargets = [];
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  if (u.hostname === 'cloudflare-dns.com') {
    const name = u.searchParams.get('name');
    const type = u.searchParams.get('type');
    if (name === 'doh-down.example.com') throw new Error('doh boom');
    const ips = (DNS[name] || []).filter(ip => (type === 'A') === !ip.includes(':'));
    return new Response(JSON.stringify({ Answer: ips.map(data => ({ type: data.includes(':') ? 28 : 1, data })) }), { status: 200, headers: { 'content-type': 'application/dns-json' } });
  }
  fetchedTargets.push(u.hostname);
  if (u.hostname === 'redir.example.com') {
    return new Response('', { status: 302, headers: { location: 'https://evil.example.com/' } });
  }
  return new Response('ok', { status: 200 });
};

let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

chk('ipBlocked 私网/回环/CGNAT', ipBlocked('10.1.2.3') && ipBlocked('127.0.0.1') && ipBlocked('100.64.1.1') && ipBlocked('172.16.0.1'));
chk('ipBlocked 公网放行', !ipBlocked('93.184.216.34') && !ipBlocked('172.32.0.1') && !ipBlocked('2606:4700::1'));
chk('ipBlocked v6 内网', ipBlocked('fd00::1') && ipBlocked('fe80::1') && ipBlocked('::1'));

fetchedTargets = [];
let r = await probeUrl('https://good.example.com/');
chk('公网解析 → 正常探活 up', r.up === true && fetchedTargets.includes('good.example.com'), JSON.stringify(r));

fetchedTargets = [];
r = await probeUrl('https://evil.example.com/');
chk('解析到内网 → 拦截且不发请求', r.up === false && r.err.includes('解析') && !fetchedTargets.includes('evil.example.com'), JSON.stringify(r));

r = await probeUrl('https://mixed.example.com/');
chk('解析结果混有内网 → 拦截', r.up === false && r.err.includes('解析'), JSON.stringify(r));

r = await probeUrl('https://v6evil.example.com/');
chk('解析到 v6 内网 → 拦截', r.up === false && r.err.includes('解析'), JSON.stringify(r));

fetchedTargets = [];
r = await probeUrl('https://redir.example.com/');
chk('重定向第二跳解析到内网 → 拦截', r.up === false && r.err.includes('解析') && !fetchedTargets.includes('evil.example.com'), JSON.stringify(r));

r = await probeUrl('https://doh-down.example.com/');
chk('DoH 故障 → 回退字符串校验、照常探活', r.up === true, JSON.stringify(r));

console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
