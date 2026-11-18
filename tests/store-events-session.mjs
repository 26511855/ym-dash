// ym-dash 定向测试（node tests/store-events-session.mjs）
// 覆盖 Chief 审计 #2 + #7：
//   ① deleteSiteData 删站时把 events 里该站事件一并清掉，其他站事件保留，
//      publicData 的时间线不再出现已删站点；无该站事件时不多写 KV。
//   ② 会话键名改 session:<sha256(token)>：KV 里不出现令牌原文作键，
//      Cookie（原文）照常校验、退出照常删除。
import { createHash } from 'node:crypto';
import { deleteSiteData, publicData } from '../functions/_lib/store.js';
import { setupAdmin, createSession, getSessionUser, destroySession } from '../functions/_lib/auth.js';

class KVShim {
  constructor() { this.map = new Map(); this.puts = 0; }
  async get(k) { return this.map.has(k) ? this.map.get(k) : null; }
  async put(k, v) { this.puts++; this.map.set(k, String(v)); }
  async delete(k) { this.map.delete(k); }
}
const makeEnv = () => ({ DASH_KV: new KVShim() });

let pass = 0, failN = 0;
const chk = (name, cond, extra = '') => { if (cond) { pass++; console.log('PASS', name); } else { failN++; console.log('FAIL', name, extra); } };

// ① 删站清事件
{
  const env = makeEnv();
  const sites = [
    { id: 'siteA', name: '站A', url: 'https://a.example.com', note: '', createdAt: 1 },
    { id: 'siteB', name: '站B', url: 'https://b.example.com', note: '', createdAt: 2 },
  ];
  await env.DASH_KV.put('sites', JSON.stringify(sites));
  await env.DASH_KV.put('events', JSON.stringify([
    { t: 300, siteId: 'siteB', name: '站B', type: 'down', detail: '' },
    { t: 200, siteId: 'siteA', name: '站A', type: 'down', detail: '' },
    { t: 100, siteId: 'siteA', name: '站A', type: 'up', detail: '' },
  ]));
  await deleteSiteData(env, 'siteA');
  const events = JSON.parse(await env.DASH_KV.get('events'));
  chk('删站后 events 只剩他站事件', events.length === 1 && events[0].siteId === 'siteB', JSON.stringify(events));
  const pub = await publicData(env);
  chk('publicData 时间线无已删站点', pub.events.every(e => e.siteId !== 'siteA'), JSON.stringify(pub.events));
}

// ①b 无该站事件时不多写 events（省 KV 写）
{
  const env = makeEnv();
  await env.DASH_KV.put('events', JSON.stringify([{ t: 1, siteId: 'siteB', name: '站B', type: 'up', detail: '' }]));
  const before = env.DASH_KV.puts;
  await deleteSiteData(env, 'siteA');
  chk('无该站事件时不回写 events', env.DASH_KV.puts === before, `puts ${before} -> ${env.DASH_KV.puts}`);
}

// ② 会话键哈希
{
  const env = makeEnv();
  await setupAdmin(env, 'boss', 'pw-test-123');
  const token = await createSession(env, 'boss');
  const expectKey = 'session:' + createHash('sha256').update(token).digest('hex');
  chk('会话以哈希键落库', env.DASH_KV.map.has(expectKey), [...env.DASH_KV.map.keys()].join(','));
  chk('KV 键里不含令牌原文', ![...env.DASH_KV.map.keys()].some(k => k.includes(token)));
  const req = new Request('https://dash.test/', { headers: { cookie: `dash_session=${token}` } });
  chk('Cookie 原文照常校验出用户', (await getSessionUser(env, req)) === 'boss');
  await destroySession(env, req);
  chk('退出后会话键已删', !env.DASH_KV.map.has(expectKey));
  chk('退出后校验为 null', (await getSessionUser(env, req)) === null);
}

console.log(`\nTOTAL pass=${pass} fail=${failN}`);
process.exit(failN ? 1 : 0);
