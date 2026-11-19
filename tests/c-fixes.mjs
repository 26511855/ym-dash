// ym-dash 对抗复读 C 部分定向测试（node tests/c-fixes.mjs）
//   C-20 探活 IPv6 校验：[::127.0.0.1] / [::ffff:127.0.0.1] / [::1] /
//        文档段 2001:db8:: 必须拦，正常公网 IPv6 放行；functions 与
//        worker 两份副本都验（worker 经 scheduled 行为验）。
//   C-21 登录失败改内存计数：200 次不同 IP 失败，login_guard 的 KV
//        put = 0（改前每失败 1 笔）；同 IP 第 5 次后锁定语义不变。
//   C-31 events 落盘写后复核合并：flush 写完后被并发写覆盖时能把本轮
//        事件补回去（functions 与 worker 两份副本都验）。
//   C-30 站点增删改指纹复核：写前被并发改过 sites 时不丢对方数据。
//   C-28 首次设置写后回读比对：admin 被并发覆盖时 setup 报错、不发会话。
import { validateUrl, ipBlocked } from '../functions/_lib/probe.js';
import { hashPassword, verifyLogin } from '../functions/_lib/auth.js';
import { loadHistBatch } from '../functions/_lib/store.js';
import { handle } from '../functions/_lib/router.js';
import worker from '../worker/worker.js';

class KVShim {
  constructor() { this.map = new Map(); this.puts = 0; this.putKeys = []; this.onPut = null; this.onGet = null; }
  async get(k) {
    const v = this.map.has(k) ? this.map.get(k) : null;
    if (this.onGet) { const f = this.onGet; if (f(k)) this.onGet = null; }
    return v;
  }
  async put(k, v) {
    this.puts++; this.putKeys.push(k); this.map.set(k, String(v));
    if (this.onPut) { const f = this.onPut; if (f(k)) this.onPut = null; }
  }
  async delete(k) { this.map.delete(k); }
}
const makeEnv = () => ({ DASH_KV: new KVShim() });
let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

// ---------- C-20 functions 副本 ----------
chk('C-20 [::127.0.0.1] 拦（v4 兼容形式）', validateUrl('http://[::127.0.0.1]/').ok === false);
chk('C-20 [::ffff:127.0.0.1] 拦（v4 映射）', validateUrl('http://[::ffff:127.0.0.1]/').ok === false);
chk('C-20 [::1] 拦（回环）', validateUrl('http://[::1]/').ok === false);
chk('C-20 [2001:db8::1] 拦（文档段）', validateUrl('http://[2001:db8::1]/').ok === false);
chk('C-20 公网 IPv6 放行', validateUrl('http://[2606:4700:4700::1111]/').ok === true);
chk('C-20 ipBlocked ::127.0.0.1', ipBlocked('::127.0.0.1') === true);
chk('C-20 ipBlocked ::ffff:127.0.0.1', ipBlocked('::ffff:127.0.0.1') === true);
chk('C-20 ipBlocked NAT64 内嵌元数据地址', ipBlocked('64:ff9b::a9fe:a9fe') === true);
chk('C-20 ipBlocked 公网 v6 放行', ipBlocked('2606:4700::1') === false);

// ---------- C-20 worker 副本（行为验：scheduled 记「不安全」且不真探） ----------
{
  const env = makeEnv();
  await env.DASH_KV.put('sites', JSON.stringify([{ id: 'w1', name: 'W', url: 'http://[::127.0.0.1]/', note: '', createdAt: 1 }]));
  let fetched = false;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { fetched = true; throw new Error('must not fetch'); };
  try { await worker.scheduled({}, env, {}); } finally { globalThis.fetch = realFetch; }
  const hist = JSON.parse(await env.DASH_KV.get('histall'));
  chk('C-20 worker 副本 [::127.0.0.1] 只记不安全、不真探',
    !fetched && hist.sites.w1 && hist.sites.w1[0].err.includes('不安全'), JSON.stringify(hist));
}

// ---------- C-21 登录失败内存计数 ----------
{
  const env = makeEnv();
  const salt = 'saltX';
  await env.DASH_KV.put('admin', JSON.stringify({ username: 'boss', salt, hash: await hashPassword('right-pw', salt), ver: 'v1' }));
  env.DASH_KV.puts = 0; env.DASH_KV.putKeys = [];
  // 同 IP 锁定语义先验（全局顺序：先做同 IP，再做多 IP 写量）
  let r;
  for (let i = 0; i < 5; i++) r = await verifyLogin(env, 'boss', 'wrong', '9.9.9.9');
  chk('C-21 同 IP 第 5 次失败当次仍普通失败', r.ok === false && !r.locked, JSON.stringify(r));
  r = await verifyLogin(env, 'boss', 'wrong', '9.9.9.9');
  chk('C-21 同 IP 第 6 次起锁定', r.ok === false && !!r.locked, JSON.stringify(r));
  env.DASH_KV.puts = 0; env.DASH_KV.putKeys = [];
  const jobs = [];
  for (let i = 0; i < 200; i++) jobs.push(verifyLogin(env, 'boss', 'wrong', `30.${(i >> 8) & 255}.${i & 255}.3`));
  const all = await Promise.all(jobs);
  const guardPuts = env.DASH_KV.putKeys.filter(k => k.startsWith('login_guard:')).length;
  chk('C-21 200 次不同 IP 失败全失败', all.every(x => x.ok === false));
  chk('C-21 login_guard KV put = 0', guardPuts === 0, `guardPuts=${guardPuts} totalPuts=${env.DASH_KV.puts}`);
}

// ---------- C-31 functions 副本：flush 写后被覆盖能补回 ----------
{
  const env = makeEnv();
  // v1.1.5：flush 落盘事件要过 validIds（L5），先把 sX 建成真实站点，
  // 否则它的事件会被当已删站事件过滤掉（那正是 L5 要的行为）
  await env.DASH_KV.put('sites', JSON.stringify([{ id: 'sX', name: 'X', url: 'https://x.example.com/', note: '', createdAt: 1 }]));
  const ev = { t: 12345, siteId: 'sX', name: 'X', type: 'down', detail: 'boom' };
  // 对手：我们 flush 写 events 后，立刻用「不含本轮事件」的旧值覆盖回去
  env.DASH_KV.onPut = (k) => {
    if (k !== 'events') return false;
    env.DASH_KV.map.set('events', JSON.stringify([{ t: 1, siteId: 'old', name: 'O', type: 'up', detail: '' }]));
    return true;
  };
  const batch = await loadHistBatch(env);
  batch.pendingEvents.push(ev);
  await batch.flush();
  const events = JSON.parse(await env.DASH_KV.get('events'));
  chk('C-31 functions flush 被并发覆盖后事件补回', events.some(e => e.t === 12345 && e.siteId === 'sX'), JSON.stringify(events));
  chk('C-31 functions 对方事件不丢', events.some(e => e.siteId === 'old'), JSON.stringify(events));
}

// ---------- C-31 worker 副本：scheduled 落盘同样补回 ----------
{
  const env = makeEnv();
  await env.DASH_KV.put('sites', JSON.stringify([{ id: 'w2', name: 'W2', url: 'http://93.184.216.34/', note: '', createdAt: 1 }]));
  await env.DASH_KV.put('state:w2', JSON.stringify({ up: false, since: 1 })); // 预置 down，本轮探到 up → 翻转事件
  env.DASH_KV.onPut = (k) => {
    if (k !== 'events') return false;
    env.DASH_KV.map.set('events', JSON.stringify([{ t: 2, siteId: 'old', name: 'O', type: 'up', detail: '' }]));
    return true;
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200, body: null });
  try { await worker.scheduled({}, env, {}); } finally { globalThis.fetch = realFetch; }
  const events = JSON.parse(await env.DASH_KV.get('events'));
  chk('C-31 worker flush 被并发覆盖后事件补回', events.some(e => e.siteId === 'w2' && e.type === 'up'), JSON.stringify(events));
}

// ---------- C-30 站点新增指纹复核：并发写不丢 ----------
// ---------- C-28 首次设置写后回读：被覆盖即报错 ----------
{
  // C-28 先验（要未初始化环境）
  const env = makeEnv();
  env.DASH_KV.onPut = (k) => {
    if (k !== 'admin') return false;
    const rival = { username: 'evil', salt: 'x', hash: 'y', pwv: 2, iter: 100000, ver: 'evil-ver', createdAt: 0 };
    env.DASH_KV.map.set('admin', JSON.stringify(rival));
    return true;
  };
  const req = new Request('https://dash.test/api/setup', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'boss', password: 'pw-123456' }),
  });
  const res = await handle({ request: req, env });
  const j = await res.json();
  chk('C-28 admin 被并发覆盖时 setup 报错', res.status === 409 && j.ok === false, `status=${res.status} ${JSON.stringify(j)}`);
  chk('C-28 冲突时不发会话 Cookie', !res.headers.get('set-cookie'));
}
{
  const env = makeEnv();
  // 先正常初始化 + 登录拿 Cookie
  const setupReq = new Request('https://dash.test/api/setup', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'boss', password: 'pw-123456' }),
  });
  const setupRes = await handle({ request: setupReq, env });
  const cookie = setupRes.headers.get('set-cookie');
  chk('C-30 前置：正常初始化成功', setupRes.status === 200 && !!cookie, 'status=' + setupRes.status);
  await env.DASH_KV.put('sites', JSON.stringify([]));
  // 对手：POST /api/sites 第一次读 sites 后，往库里塞一个并发新增的站
  env.DASH_KV.onGet = (k) => {
    if (k !== 'sites') return false;
    const cur = JSON.parse(env.DASH_KV.map.get('sites') || '[]');
    cur.push({ id: 'rival1', name: '并发站', url: 'https://rival.example.com/', note: '', createdAt: 9 });
    env.DASH_KV.map.set('sites', JSON.stringify(cur));
    return true;
  };
  const addReq = new Request('https://dash.test/api/sites', {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name: '我的站', url: 'https://mine.example.com' }),
  });
  const addRes = await handle({ request: addReq, env });
  const sites = JSON.parse(await env.DASH_KV.get('sites'));
  chk('C-30 新增成功且并发站不丢', addRes.status === 200 && sites.some(s => s.id === 'rival1') && sites.some(s => s.name === '我的站'),
    `status=${addRes.status} sites=${JSON.stringify(sites)}`);
}

console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
