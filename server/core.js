// 전자음악 노선도 서버: 계정, 기록 저장, 개발자 편집 공유.
// 웹 표준(Request, Response, crypto.subtle)만 써서 Cloudflare Pages Functions와 Node 18 이상에서 똑같이 돈다.
// 저장소는 kv 객체(get, put, delete)로 받는다. Cloudflare에서는 KV 바인딩을, Node에서는 파일 저장소를 넘긴다.

const te = new TextEncoder();
const td = new TextDecoder();
const ITER = 100000; // Cloudflare Workers가 허용하는 PBKDF2 반복 횟수의 최대치
const TOKEN_SEC = 30 * 24 * 3600;
const MAX_BODY = 2200000;
const MAX_PROGRESS = 300000;
const MAX_EDITS = 2000000;
const ID_RE = /^[A-Za-z0-9_.\-가-힣]{2,20}$/;
const EDIT_KEYS = ['n', 'k', 'y', 'd', 'bt', 't0', 't1', 'vid', 'm0', 'm1', 'm2', 'mv', 'ms'];

const b64 = (buf) => { let s = ''; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); };
const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
const b64u = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (str) => unb64(str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4));

function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function pbkdf2(pw, salt, iters) {
  const k = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iters }, k, 256));
}

const hmacKey = (secret) => crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

async function signToken(env, payload) {
  const body = b64u(te.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env.SECRET), te.encode(body));
  return body + '.' + b64u(sig);
}

async function readToken(env, token) {
  try {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env.SECRET), unb64u(sig), te.encode(body));
    if (!ok) return null;
    const p = JSON.parse(td.decode(unb64u(body)));
    if (!p || !p.e || p.e * 1000 < Date.now()) return null;
    return p;
  } catch (_) { return null; }
}

function out(status, obj, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    }, extra || {}),
  });
}

class HttpError extends Error { constructor(status, error, message) { super(message || error); this.status = status; this.error = error; } }

async function readBody(request) {
  const t = await request.text();
  if (t.length > MAX_BODY) throw new HttpError(413, 'too_large', '보낸 내용이 너무 큽니다.');
  try { const j = JSON.parse(t || '{}'); return j && typeof j === 'object' ? j : {}; }
  catch (_) { throw new HttpError(400, 'bad_json', '내용을 읽을 수 없습니다.'); }
}

const norm = (id) => String(id == null ? '' : id).normalize('NFC').trim();
const keyOf = (id) => norm(id).toLowerCase();
const devIds = (env) => String(env.DEV_IDS || '').split(',').map((x) => keyOf(x)).filter(Boolean);
const ipOf = (request) => (request.headers.get('CF-Connecting-IP') || (request.headers.get('X-Forwarded-For') || '').split(',')[0] || 'unknown').trim();

async function countOf(kv, k) { return Number(await kv.get(k)) || 0; }
async function bump(kv, k, ttl) { await kv.put(k, String(await countOf(kv, k) + 1), { expirationTtl: ttl }); }

async function makeUser(id, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(pw, salt, ITER);
  return { id, salt: b64(salt), hash: b64(hash), it: ITER, dev: false, ver: 1, created: Date.now() };
}

async function checkPw(user, pw) {
  const h = await pbkdf2(String(pw || ''), unb64(user.salt), user.it || ITER);
  return same(h, unb64(user.hash));
}

async function loadUser(kv, k) {
  const t = await kv.get('u:' + k);
  return t ? JSON.parse(t) : null;
}

async function loadProgress(kv, k) {
  const t = await kv.get('p:' + k);
  return t ? JSON.parse(t) : null;
}

function plainObject(x) { return x && typeof x === 'object' && !Array.isArray(x); }

function cleanEdits(edits) {
  if (!plainObject(edits)) throw new HttpError(400, 'bad_edits', '편집 내용의 모양이 맞지 않습니다.');
  const out2 = {};
  for (const id of Object.keys(edits)) {
    if (!/^[a-z0-9_]{1,60}$/.test(id) || !plainObject(edits[id])) continue;
    const e = {};
    for (const f of EDIT_KEYS) {
      const v = edits[id][f];
      if (v === undefined || v === null) continue;
      if (typeof v === 'string') e[f] = v.slice(0, 4000);
      else if (typeof v === 'number' && isFinite(v)) e[f] = v;
    }
    if (Object.keys(e).length) out2[id] = e;
  }
  return out2;
}

export async function handle(request, env, kv) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
  const method = request.method.toUpperCase();
  try {
    const ready = !!env.SECRET && String(env.SECRET).length >= 16;
    if (path === 'ping' && method === 'GET') return out(200, { ok: true, service: 'interchange', v: 1, ready });
    if (!ready) return out(500, { error: 'server_config', message: '서버 설정이 끝나지 않았습니다. SECRET 환경 변수(16자 이상)가 필요합니다.' });

    const authed = async () => {
      const h = request.headers.get('Authorization') || '';
      const p = await readToken(env, h.replace(/^Bearer\s+/i, ''));
      if (!p) throw new HttpError(401, 'unauthorized', '다시 로그인해 주세요.');
      const user = await loadUser(kv, p.i);
      if (!user || user.ver !== p.v) throw new HttpError(401, 'unauthorized', '다시 로그인해 주세요.');
      const master = devIds(env).includes(p.i);
      return { k: p.i, user, master, dev: master || user.dev === true, exp: p.e };
    };
    const issue = (user, k) => signToken(env, { i: k, v: user.ver, e: Math.floor(Date.now() / 1000) + TOKEN_SEC });

    // 가입
    if (path === 'register' && method === 'POST') {
      const b = await readBody(request);
      const id = norm(b.id), k = keyOf(id), pw = String(b.password || '');
      if (!ID_RE.test(id)) throw new HttpError(400, 'bad_id', '아이디는 2~20자의 영문, 숫자, 점, 밑줄, 하이픈, 한글로 적어 주세요.');
      if (pw.length < 8 || pw.length > 64) throw new HttpError(400, 'bad_password', '비밀번호는 8~64자로 적어 주세요.');
      const ip = ipOf(request);
      if (await countOf(kv, 'rl:r:' + ip) >= 10) throw new HttpError(429, 'rate', '잠시 뒤에 다시 시도해 주세요.');
      if (devIds(env).includes(k)) {
        const code = String(b.code || '');
        if (!env.DEV_SETUP_CODE || !same(te.encode(code), te.encode(String(env.DEV_SETUP_CODE)))) {
          throw new HttpError(403, 'setup_code_required', '이 아이디는 예약되어 있습니다. 설정 코드를 함께 적어 주세요.');
        }
      }
      if (await kv.get('u:' + k)) throw new HttpError(409, 'exists', '이미 있는 아이디입니다.');
      await bump(kv, 'rl:r:' + ip, 3600);
      const user = await makeUser(id, pw);
      await kv.put('u:' + k, JSON.stringify(user));
      let prog = null;
      if (plainObject(b.progress)) {
        const text = JSON.stringify(b.progress);
        if (text.length <= MAX_PROGRESS) { prog = { updatedAt: Date.now(), data: b.progress }; await kv.put('p:' + k, JSON.stringify(prog)); }
      }
      const master = devIds(env).includes(k);
      return out(200, { token: await issue(user, k), id: user.id, dev: master, master, progress: prog ? prog.data : null, updatedAt: prog ? prog.updatedAt : 0 });
    }

    // 로그인
    if (path === 'login' && method === 'POST') {
      const b = await readBody(request);
      const id = norm(b.id), k = keyOf(id), ip = ipOf(request);
      if (await countOf(kv, 'rl:l:' + k + ':' + ip) >= 8 || await countOf(kv, 'rl:g:' + k) >= 30 || await countOf(kv, 'rl:i:' + ip) >= 40) throw new HttpError(429, 'rate', '시도가 너무 많습니다. 15분 뒤에 다시 해 주세요.');
      const user = ID_RE.test(id) ? await loadUser(kv, k) : null;
      let ok = false;
      if (user) ok = await checkPw(user, b.password);
      else await pbkdf2(String(b.password || ''), new Uint8Array(16), ITER); // 아이디가 없어도 걸리는 시간을 비슷하게 맞춘다
      if (!ok) {
        await bump(kv, 'rl:l:' + k + ':' + ip, 900); await bump(kv, 'rl:g:' + k, 900); await bump(kv, 'rl:i:' + ip, 900);
        throw new HttpError(401, 'bad_login', '아이디나 비밀번호가 맞지 않습니다.');
      }
      await kv.delete('rl:l:' + k + ':' + ip);
      const prog = await loadProgress(kv, k);
      const master = devIds(env).includes(k);
      return out(200, { token: await issue(user, k), id: user.id, dev: master || user.dev === true, master, progress: prog ? prog.data : null, updatedAt: prog ? prog.updatedAt : 0 });
    }

    // 내 정보와 기록
    if (path === 'me' && method === 'GET') {
      const a = await authed();
      const prog = await loadProgress(kv, a.k);
      const renew = a.exp - Math.floor(Date.now() / 1000) < TOKEN_SEC / 2 ? { token: await issue(a.user, a.k) } : {};
      return out(200, Object.assign({ id: a.user.id, dev: a.dev, master: a.master, progress: prog ? prog.data : null, updatedAt: prog ? prog.updatedAt : 0 }, renew));
    }

    if (path === 'progress' && method === 'PUT') {
      const a = await authed();
      const b = await readBody(request);
      if (!plainObject(b.data)) throw new HttpError(400, 'bad_data', '기록의 모양이 맞지 않습니다.');
      const text = JSON.stringify(b.data);
      if (text.length > MAX_PROGRESS) throw new HttpError(413, 'too_large', '기록이 너무 큽니다.');
      const cur = await loadProgress(kv, a.k);
      if (cur && Number(b.base) !== cur.updatedAt) return out(409, { error: 'conflict', message: '다른 기기에서 먼저 저장했습니다.', updatedAt: cur.updatedAt, data: cur.data });
      const updatedAt = Math.max(Date.now(), (cur ? cur.updatedAt : 0) + 1);
      await kv.put('p:' + a.k, JSON.stringify({ updatedAt, data: b.data }));
      return out(200, { ok: true, updatedAt });
    }

    // 비밀번호, 모든 기기 로그아웃, 계정 삭제
    if (path === 'password' && method === 'POST') {
      const a = await authed();
      const b = await readBody(request);
      if (!(await checkPw(a.user, b.old))) throw new HttpError(403, 'bad_login', '지금 비밀번호가 맞지 않습니다.');
      const pw = String(b.password || '');
      if (pw.length < 8 || pw.length > 64) throw new HttpError(400, 'bad_password', '새 비밀번호는 8~64자로 적어 주세요.');
      const fresh = await makeUser(a.user.id, pw);
      const user = Object.assign({}, a.user, { salt: fresh.salt, hash: fresh.hash, it: fresh.it, ver: a.user.ver + 1 });
      await kv.put('u:' + a.k, JSON.stringify(user));
      return out(200, { ok: true, token: await issue(user, a.k) });
    }

    if (path === 'logout-all' && method === 'POST') {
      const a = await authed();
      const user = Object.assign({}, a.user, { ver: a.user.ver + 1 });
      await kv.put('u:' + a.k, JSON.stringify(user));
      return out(200, { ok: true, token: await issue(user, a.k) });
    }

    if (path === 'delete' && method === 'POST') {
      const a = await authed();
      const b = await readBody(request);
      if (!(await checkPw(a.user, b.password))) throw new HttpError(403, 'bad_login', '비밀번호가 맞지 않습니다.');
      if (a.master) throw new HttpError(403, 'master', '개발자 대표 계정은 여기서 지울 수 없습니다.');
      await kv.delete('u:' + a.k); await kv.delete('p:' + a.k);
      const list = JSON.parse((await kv.get('devs')) || '[]').filter((x) => x !== a.k);
      await kv.put('devs', JSON.stringify(list));
      return out(200, { ok: true });
    }

    // 의견과 오류 신고
    if (path === 'feedback' && method === 'POST') {
      const b = await readBody(request);
      const text = String(b.text || '').trim().slice(0, 1000);
      if (text.length < 3) throw new HttpError(400, 'empty', '내용을 3자 이상 적어 주세요.');
      const ip = ipOf(request);
      if (await countOf(kv, 'rl:f:' + ip) >= 5) throw new HttpError(429, 'rate', '잠시 뒤에 다시 보내 주세요.');
      let who = '';
      const h = request.headers.get('Authorization') || '';
      if (h) { const p = await readToken(env, h.replace(/^Bearer\s+/i, '')); if (p) { const u = await loadUser(kv, p.i); who = u ? u.id : p.i; } }
      await bump(kv, 'rl:f:' + ip, 3600);
      const list = JSON.parse((await kv.get('fb')) || '[]');
      list.push({ t: Date.now(), id: who, text, ctx: String(b.ctx || '').slice(0, 300) });
      await kv.put('fb', JSON.stringify(list.slice(-300)));
      return out(200, { ok: true });
    }

    // 개발자가 고친 내용을 모두에게 보여 주기
    if (path === 'edits' && method === 'GET') {
      const e = JSON.parse((await kv.get('edits')) || 'null') || { rev: 0, edits: {} };
      return out(200, e, { 'Cache-Control': 'public, max-age=20' });
    }

    if (path === 'edits' && method === 'PUT') {
      const a = await authed();
      if (!a.dev) throw new HttpError(403, 'forbidden', '개발자만 할 수 있습니다.');
      const b = await readBody(request);
      const edits = cleanEdits(b.edits);
      const text = JSON.stringify(edits);
      if (text.length > MAX_EDITS) throw new HttpError(413, 'too_large', '편집 내용이 너무 큽니다.');
      const rev = Date.now();
      await kv.put('edits', JSON.stringify({ rev, by: a.user.id, edits }));
      return out(200, { ok: true, rev, count: Object.keys(edits).length });
    }

    // 개발자 권한 관리(대표 계정만)
    if (path.startsWith('dev/')) {
      const a = await authed();
      if (!a.master) throw new HttpError(403, 'forbidden', '개발자 대표 계정만 할 수 있습니다.');
      const b = method === 'POST' ? await readBody(request) : {};
      if (path === 'dev/feedback' && method === 'GET') {
        return out(200, { items: JSON.parse((await kv.get('fb')) || '[]').slice(-100).reverse() });
      }
      if (path === 'dev/feedback-delete' && method === 'POST') {
        const t = Number(b.t);
        const list = JSON.parse((await kv.get('fb')) || '[]').filter((x) => b.all === true ? false : x.t !== t);
        await kv.put('fb', JSON.stringify(list));
        return out(200, { ok: true, left: list.length });
      }
      if (path === 'dev/list' && method === 'GET') {
        return out(200, { masters: devIds(env), devs: JSON.parse((await kv.get('devs')) || '[]') });
      }
      if (path === 'dev/grant' && method === 'POST') {
        const k = keyOf(b.id);
        const user = ID_RE.test(norm(b.id)) ? await loadUser(kv, k) : null;
        if (!user) throw new HttpError(404, 'no_user', '그 아이디의 계정이 아직 없습니다.');
        if (devIds(env).includes(k)) throw new HttpError(400, 'master', '이미 대표 계정입니다.');
        user.dev = b.dev !== false;
        await kv.put('u:' + k, JSON.stringify(user));
        let list = JSON.parse((await kv.get('devs')) || '[]').filter((x) => x !== k);
        if (user.dev) list.push(k);
        await kv.put('devs', JSON.stringify(list));
        return out(200, { ok: true, devs: list });
      }
      if (path === 'dev/reset' && method === 'POST') {
        const k = keyOf(b.id);
        const user = ID_RE.test(norm(b.id)) ? await loadUser(kv, k) : null;
        if (!user) throw new HttpError(404, 'no_user', '그 아이디의 계정이 없습니다.');
        const pw = String(b.password || '');
        if (pw.length < 8 || pw.length > 64) throw new HttpError(400, 'bad_password', '새 비밀번호는 8~64자로 적어 주세요.');
        const fresh = await makeUser(user.id, pw);
        await kv.put('u:' + k, JSON.stringify(Object.assign({}, user, { salt: fresh.salt, hash: fresh.hash, it: fresh.it, ver: user.ver + 1 })));
        return out(200, { ok: true });
      }
    }

    return out(404, { error: 'not_found', message: '없는 주소입니다.' });
  } catch (e) {
    if (e instanceof HttpError) return out(e.status, { error: e.error, message: e.message });
    return out(500, { error: 'server', message: '서버에서 문제가 생겼습니다.' });
  }
}
