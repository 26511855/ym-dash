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
// 资产未命中且是 GET/HEAD 时按 Pages 在无 404.html 时的单页回退口径回
// /index.html（原版线上即如此）。本仓没有 _headers 文件，资产响应不补头。
// 注：worker/ 目录是另一个独立的探活 Worker，不在本入口职责内（打包时它仍
// 作为普通文件随包附带，与原部署包一致，部署探活时单独用）。

import { handle } from '../functions/_lib/router.js';

async function serveAsset(request, env, url) {
  let resp = await env.ASSETS.fetch(request);
  if (resp.status === 404 && (request.method === 'GET' || request.method === 'HEAD')) {
    const idx = await env.ASSETS.fetch(new Request(new URL('/index.html', url.origin)));
    if (idx.ok) {
      resp = new Response(request.method === 'HEAD' ? null : idx.body, {
        status: 200,
        headers: idx.headers,
      });
    }
  }
  return resp;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      return handle({
        request,
        env,
        params: {},
        waitUntil: ctx.waitUntil.bind(ctx),
        next: () => serveAsset(request, env, url),
      });
    }
    return serveAsset(request, env, url);
  },
};
