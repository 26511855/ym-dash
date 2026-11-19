// build/worker-entry.js — 「_worker.js 高级模式包」的构建入口（本文件不要直接部署）
//
// 为什么需要它：Cloudflare 控制台的「上传资产 / 拖拽」部署**不会编译 functions/
// 文件夹**（官方文档明示），把普通部署包直传上去会得到一个页面能开、但全部
// 接口都坏死的站。官方确认根目录的单个 `_worker.js` 在拖拽上传下受支持，所以
// 打包时用 esbuild 把原路由处理函数合成一个 _worker.js，原源码一字不改。
//
// 构建命令（release-pack 工作流里执行，本地复现也是这一条）：
//   esbuild build/worker-entry.js --bundle --format=esm \
//     --platform=neutral --target=es2022 --outfile=_worker.js
//
// 路由语义与 functions 文件路由对齐：原版只有 functions/api/[[path]].js 一个
// 入口，/api 与 /api/* 全部进 _lib/router.js 的 handle（路径尾斜杠由 router
// 自己归一化，入口把原始请求原样递过去即可）；其余路径走 env.ASSETS.fetch，
// 资产未命中、无扩展名且是 GET/HEAD 时按单页回退口径回 /index.html
// （L10 起带扩展名的 404 如实回 404）。本仓没有 _headers 文件，
// 安全头由本入口统一补（M9）。
// 注：worker/ 目录是另一个独立的探活 Worker，不在本入口职责内（打包时它仍
// 作为普通文件随包附带，与原部署包一致，部署探活时单独用）。

import { handle } from '../functions/_lib/router.js';

// M9：基础安全头（与 router.js 的 json() 同口径）。CSP 只上
// frame-ancestors——前端大量内联 onclick，上 script-src 会弄坏页面。
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};
function withSecurity(resp) {
  const headers = new Headers(resp.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) if (!headers.has(k)) headers.set(k, v);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

async function serveAsset(request, env, url) {
  let resp = await env.ASSETS.fetch(request);
  // L10：只对无扩展名的路径回退 index.html（单页应用路由）；带扩展名
  // 的 404（/robots.txt、/favicon.ico、拼错的静态文件）如实回 404，
  // 旧版一律回 200+首页会把坏链接伪装成正常页面。
  const lastSeg = url.pathname.split('/').pop() || '';
  const extensionless = !lastSeg.includes('.');
  if (resp.status === 404 && extensionless && (request.method === 'GET' || request.method === 'HEAD')) {
    const idx = await env.ASSETS.fetch(new Request(new URL('/index.html', url.origin)));
    if (idx.ok) {
      resp = new Response(request.method === 'HEAD' ? null : idx.body, {
        status: 200,
        headers: idx.headers,
      });
    }
  }
  return withSecurity(resp);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      return withSecurity(await handle({
        request,
        env,
        params: {},
        waitUntil: ctx.waitUntil.bind(ctx),
        next: () => serveAsset(request, env, url),
      }));
    }
    return serveAsset(request, env, url);
  },
};
