// auth.js — 站长初始化 / 登录 / 会话 / 登录限流
// 模式照 ym 系列：未初始化时任何人可走 /api/setup 初始化（敞口只在未初始化时存在），
// 初始化后 setup 关闭；若部署时设了环境变量 SETUP_TOKEN，初始化还需带对口令。
// 密码只存加盐哈希：现行 PBKDF2-SHA256 10 万轮（admin.pwv = 2）；
// 旧版单轮 SHA-256（无 pwv）仍可登录，登录成功后自动升级重哈希。
// 会话 Cookie 7 天且 KV 侧同步设 TTL；admin 带 ver（初始化时随机生成），
// 会话里存同一 ver——重设站长账号后 ver 变，旧会话全体失效。
// 登录失败锁定按来源 IP 分开计数（进程内存，见下方 C-21 说明），
// 别人输错密码锁不住站长自己。
// KV 键：admin {username,salt,hash,pwv,iter,ver,createdAt}、session:<sha256(token)> {username,exp,ver}
// 会话键只存令牌的 SHA-256（Cookie 里仍放原文）：KV 读面一旦泄露，
// 键名不再是可直接复用的令牌本体（与 ym-blog 的 token_hash 做法一致）。
// 改键后存量会话查不到、自动失效，站长重登一次即可。

import { kvGetJSONStrict, kvPutJSON } from './store.js';

export const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const MAX_FAILS = 5;

function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function randHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return hex(a.buffer);
}
// 旧版口令哈希（单轮 SHA-256）：仅用于校验存量 admin 并在登录成功后升级
export async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(`${salt}:${password}`);
  return hex(await crypto.subtle.digest('SHA-256', data));
}
const PBKDF2_ITER = 100000;
// L2：迭代数夹在 10k–200k——admin 记录里的 iter 若被改成天文数字，
// 登录校验照单全收会把一次登录拖成 DoS；在这里统一夹取，调用方
// 传什么都不会越界。
export function clampIter(iter) {
  const n = Number(iter) || PBKDF2_ITER;
  return Math.min(200000, Math.max(10000, Math.floor(n)));
}
export async function hashPasswordV2(password, salt, iter = PBKDF2_ITER) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: clampIter(iter) }, key, 256);
  return hex(bits);
}
// 定长比较，避免计时侧信道（长度不同直接 false）
export function safeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// 管理员读取必须严格：读失败若当成「还没有管理员」，初始化入口
// 就可能对访客敞开、甚至覆盖掉已有站长账号
export const getAdmin = (env) => kvGetJSONStrict(env, 'admin', null);

export async function setupAdmin(env, username, password) {
  const salt = randHex(16);
  const admin = {
    username, salt, hash: await hashPasswordV2(password, salt),
    pwv: 2, iter: PBKDF2_ITER, ver: randHex(6), createdAt: Date.now(),
  };
  await kvPutJSON(env, 'admin', admin);
  return admin;
}

// ---- 登录失败锁定：按来源 IP 分开计数 ----
// 【C-21 修复】计数改存进程内存（按 isolate），不再写 KV。旧版每失败
// 一次写 1 笔 login_guard:<ip>，换着 IP 失败约 1000 次就能烧光全账号
// 1000 次/天的免费写额度。锁定语义与旧版一致：同 IP 失败攒到
// MAX_FAILS 次锁 LOCK_MS，第 5 次当次仍按普通失败返回、锁定从下一次
// 尝试起生效；条目闲置超过 LOCK_MS 视为过期（对应旧版 KV 的 TTL）。
// 已知取舍：内存计数在 isolate 冷启动/回收时清零，是尽力而为——对
// 单人站点挡爆破足够，且限流器再也烧不掉写额度（与 ym-nav /
// ym-cf-panel 的同款改法一致）。旧 KV 键 login_guard:* 不再读写，
// 存量键随原 TTL 自然过期，无需清理。
const guardMap = new Map(); // ip -> { fails, lockUntil, updatedAt }
function memGuard(ip) {
  const now = Date.now();
  const g = guardMap.get(ip || 'unknown');
  if (!g) return { fails: 0, lockUntil: 0, updatedAt: 0 };
  if (g.lockUntil && g.lockUntil > now) return g; // 锁定中
  if (now - (g.updatedAt || 0) > LOCK_MS) return { fails: 0, lockUntil: 0, updatedAt: 0 }; // 闲置过期
  return g;
}
export async function isLocked(env, ip) {
  const g = memGuard(ip);
  return g.lockUntil && g.lockUntil > Date.now() ? g.lockUntil : 0;
}
async function noteFail(env, ip) {
  const g = memGuard(ip);
  g.fails = (g.fails || 0) + 1;
  if (g.fails >= MAX_FAILS) { g.lockUntil = Date.now() + LOCK_MS; g.fails = 0; }
  g.updatedAt = Date.now();
  guardMap.set(ip || 'unknown', g);
  if (guardMap.size > 1000) {
    // H3：旧版只删「已过期」条目——15 分钟窗口内狂换 IP 时条目都没
    // 过期、一个删不掉，表无界增长。现先删过期条目，还超就按
    // updatedAt 从最旧开始淘汰，直到回到上限内。
    const now = Date.now();
    for (const [k, v] of guardMap) {
      if ((!v.lockUntil || v.lockUntil <= now) && now - (v.updatedAt || 0) > LOCK_MS) guardMap.delete(k);
    }
    if (guardMap.size > 1000) {
      const byOld = [...guardMap.entries()].sort((a, b) => (a[1].updatedAt || 0) - (b[1].updatedAt || 0));
      for (const [k] of byOld) {
        if (guardMap.size <= 1000) break;
        guardMap.delete(k);
      }
    }
  }
}
// L3：初始化口令试错也走同一套内存限流（不写 KV，口径同 C-21）
export const noteGuardFail = noteFail;
async function clearFails(env, ip) {
  guardMap.delete(ip || 'unknown');
}

// 校验账号密码。返回 {ok} 或 {ok:false, locked:<ms epoch>} 或 {ok:false}
export async function verifyLogin(env, username, password, ip) {
  const lockUntil = await isLocked(env, ip);
  if (lockUntil) return { ok: false, locked: lockUntil };
  const admin = await getAdmin(env);
  if (!admin) return { ok: false };
  let ok = false;
  if (username === admin.username) {
    if (admin.pwv === 2) {
      ok = safeEq(await hashPasswordV2(password, admin.salt, admin.iter || PBKDF2_ITER), admin.hash);
    } else {
      ok = safeEq(await hashPassword(password, admin.salt), admin.hash);
      if (ok) {
        // 旧版单轮哈希：登录成功顺手升级为 PBKDF2（盐不变，ver 不变，老会话不受影响）
        admin.hash = await hashPasswordV2(password, admin.salt);
        admin.pwv = 2; admin.iter = PBKDF2_ITER;
        await kvPutJSON(env, 'admin', admin);
      }
    }
  }
  if (ok) { await clearFails(env, ip); return { ok: true }; }
  await noteFail(env, ip); // 第 5 次失败当次仍按普通失败返回，锁定从下一次尝试起生效（入口处判定）
  return { ok: false };
}

// 会话键 = session:<sha256(token)>：键名不落令牌本体（见文件头说明）
async function sessionKey(token) {
  return `session:${hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)))}`;
}

export async function createSession(env, username) {
  const token = randHex(32);
  const admin = await getAdmin(env);
  const value = JSON.stringify({ username, exp: Date.now() + SESSION_TTL_MS, ver: (admin && admin.ver) || null });
  await env.DASH_KV.put(await sessionKey(token), value, { expirationTtl: Math.ceil(SESSION_TTL_MS / 1000) });
  return token;
}
export function sessionCookie(token) {
  return `dash_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`;
}
export function clearCookie() {
  return 'dash_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}
function tokenFromRequest(request) {
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)dash_session=([a-f0-9]{64})/);
  return m ? m[1] : null;
}
export async function getSessionUser(env, request) {
  const token = tokenFromRequest(request);
  if (!token) return null;
  const key = await sessionKey(token);
  const raw = await env.DASH_KV.get(key);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw);
    if (!s.exp || s.exp < Date.now()) { await env.DASH_KV.delete(key); return null; }
    // M3：admin 记录不存在（被删键重置密码的恢复路径进行中）→
    // 旧会话一律失效并顺手删掉。旧版 admin 为 null 时直接放行会话，
    // 与 README「重新初始化后旧会话自动失效」的承诺不符（删键后、
    // 重设前这段时间旧会话还能进后台）。
    // 站长账号被重设过（admin.ver 变了）→ 旧会话同样失效；
    // 存量 admin 没有 ver、或会话本身是升级前签发的（无 ver），不追溯
    const admin = await getAdmin(env);
    if (!admin) {
      await env.DASH_KV.delete(key);
      return null;
    }
    if (admin.ver && s.ver && s.ver !== admin.ver) {
      await env.DASH_KV.delete(key);
      return null;
    }
    return s.username;
  } catch { return null; }
}
export async function destroySession(env, request) {
  const token = tokenFromRequest(request);
  if (!token) return;
  // 先确认会话真实存在再删：拿伪造 Cookie 反复打退出接口，
  // 不能变成无意义的 KV 删除消耗
  const key = await sessionKey(token);
  const raw = await env.DASH_KV.get(key);
  if (raw != null) await env.DASH_KV.delete(key);
}
