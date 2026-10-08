// 내 컴퓨터나 일반 서버에서 돌리는 방법: node server/node.js
// public 폴더의 파일을 보여 주고 /api 요청을 받는다. 기록은 data.json 파일에 저장된다.
// 환경 변수: PORT(기본 8787), SECRET(없으면 secret.txt를 만들어 씀), DEV_IDS, DEV_SETUP_CODE, DATA_FILE
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { handle } from './core.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pub = path.join(root, 'public');
const PORT = Number(process.env.PORT) || 8787;
const DATA = process.env.DATA_FILE || path.join(root, 'data.json');

let secret = process.env.SECRET;
if (!secret) {
  const f = path.join(root, 'secret.txt');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  secret = fs.readFileSync(f, 'utf8').trim();
}
const env = { SECRET: secret, DEV_IDS: process.env.DEV_IDS || '', DEV_SETUP_CODE: process.env.DEV_SETUP_CODE || '' };

// 파일에 저장하는 간단한 KV
let db = {};
try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch (_) { db = {}; }
let timer = null;
const flush = () => {
  timer = null;
  const tmp = DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA);
};
const kv = {
  async get(k) { const e = db[k]; if (!e) return null; if (e.exp && e.exp < Date.now()) { delete db[k]; return null; } return e.v; },
  async put(k, v, o) { db[k] = { v: String(v), exp: o && o.expirationTtl ? Date.now() + o.expirationTtl * 1000 : 0 }; if (!timer) timer = setTimeout(flush, 300); },
  async delete(k) { delete db[k]; if (!timer) timer = setTimeout(flush, 300); },
};
process.on('SIGINT', () => { if (timer) flush(); process.exit(0); });
process.on('SIGTERM', () => { if (timer) flush(); process.exit(0); });

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.ico': 'image/x-icon', '.svg': 'image/svg+xml' };

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
    if (url.pathname.startsWith('/api')) {
      const chunks = [];
      for await (const c of req) { chunks.push(c); if (chunks.reduce((a, b) => a + b.length, 0) > 2500000) { res.writeHead(413); res.end(); return; } }
      const request = new Request(url, { method: req.method, headers: req.headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) });
      const r = await handle(request, env, kv);
      const h = {}; r.headers.forEach((v, k) => { h[k] = v; });
      res.writeHead(r.status, h); res.end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    let rel = decodeURIComponent(url.pathname); if (rel === '/') rel = '/index.html';
    const file = path.join(pub, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
    if (!file.startsWith(pub) || !fs.existsSync(file) || fs.statSync(file).isDirectory() || path.basename(file).startsWith('_')) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Content-Type-Options': 'nosniff' });
    fs.createReadStream(file).pipe(res);
  } catch (_) { res.writeHead(500); res.end('Server error'); }
});
server.listen(PORT, () => console.log('http://localhost:' + PORT));
