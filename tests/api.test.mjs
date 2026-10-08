// node tests/api.test.mjs  — 서버 규칙이 지켜지는지 확인한다.
import { handle } from '../server/core.js';
import { createHmac } from 'node:crypto';

const store = new Map();
const kv = {
  async get(k) { const e = store.get(k); if (!e) return null; if (e.exp && e.exp < Date.now()) { store.delete(k); return null; } return e.v; },
  async put(k, v, o) { store.set(k, { v: String(v), exp: o && o.expirationTtl ? Date.now() + o.expirationTtl * 1000 : 0 }); },
  async delete(k) { store.delete(k); },
};
const env = { SECRET: 'test-secret-0123456789abcdef', DEV_IDS: 'dev.KSJ', DEV_SETUP_CODE: 'setup-code-1' };
let fail = 0, n = 0;
const ok = (c, name) => { n++; if (!c) { fail++; console.log('FAIL', name); } else console.log('PASS', name); };
async function call(method, path, body, token, ip) {
  const headers = { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip || '1.1.1.1' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const r = await handle(new Request('http://x/api/' + path, { method, headers, body: body ? JSON.stringify(body) : undefined }), env, kv);
  return { s: r.status, j: await r.json() };
}

let r = await call('GET', 'ping');
ok(r.s === 200 && r.j.service === 'interchange' && r.j.ready, 'ping');
r = await handle(new Request('http://x/api/login', { method: 'POST', body: '{}' }), { SECRET: 'short' }, kv);
ok(r.status === 500, 'SECRET이 짧으면 거부');
r = await call('POST', 'register', { id: 'a', password: 'longenough1' }); ok(r.s === 400 && r.j.error === 'bad_id', '짧은 아이디 거부');
r = await call('POST', 'register', { id: 'user one', password: 'longenough1' }); ok(r.s === 400, '띄어쓰기 아이디 거부');
r = await call('POST', 'register', { id: 'minsu', password: 'short' }); ok(r.s === 400 && r.j.error === 'bad_password', '짧은 비밀번호 거부');
r = await call('POST', 'register', { id: 'dev.KSJ', password: 'master-pass-1' }); ok(r.s === 403 && r.j.error === 'setup_code_required', '예약 아이디는 코드 없이 가입 불가');
r = await call('POST', 'register', { id: 'DEV.ksj', password: 'master-pass-1', code: 'wrong' }); ok(r.s === 403, '대소문자만 바꿔도 예약 아이디 보호');
r = await call('POST', 'register', { id: 'dev.KSJ', password: 'master-pass-1', code: 'setup-code-1' }); ok(r.s === 200 && r.j.master && r.j.dev, '코드가 맞으면 대표 계정 가입');
const master = r.j.token;
r = await call('POST', 'register', { id: 'minsu', password: 'longenough1', progress: { xp: 40, seen: ['house'] } }); ok(r.s === 200 && !r.j.dev && r.j.progress.xp === 40, '일반 가입과 손님 기록 이어받기');
const minsu = r.j.token;
r = await call('POST', 'register', { id: 'MinSu', password: 'longenough1' }); ok(r.s === 409, '아이디는 대소문자 구분 없이 하나');
r = await call('POST', 'login', { id: 'minsu', password: 'wrongwrong' }); ok(r.s === 401, '틀린 비밀번호');
r = await call('POST', 'login', { id: 'nobody', password: 'wrongwrong' }); ok(r.s === 401 && r.j.error === 'bad_login', '없는 아이디도 같은 오류');
r = await call('POST', 'login', { id: 'minsu', password: 'longenough1' }); ok(r.s === 200 && r.j.progress.seen[0] === 'house', '로그인과 기록 받기');
r = await call('GET', 'me', null, minsu); ok(r.s === 200 && r.j.id === 'minsu' && r.j.updatedAt > 0, '내 정보');
r = await call('GET', 'me'); ok(r.s === 401, '토큰 없이 거부');
r = await call('GET', 'me', null, minsu + 'x'); ok(r.s === 401, '위조 토큰 거부');

// 기록 저장과 충돌
const base0 = (await call('GET', 'me', null, minsu)).j.updatedAt;
r = await call('PUT', 'progress', { data: { xp: 90 }, base: base0 }, minsu); ok(r.s === 200 && r.j.updatedAt > base0, '기록 저장');
r = await call('PUT', 'progress', { data: { xp: 5 }, base: base0 }, minsu); ok(r.s === 409 && r.j.data.xp === 90, '오래된 기준이면 충돌로 돌려보냄');
r = await call('PUT', 'progress', { data: [1, 2], base: 0 }, minsu); ok(r.s === 400, '기록은 객체만');
r = await call('PUT', 'progress', { data: { big: 'x'.repeat(310000) }, base: 0 }, minsu); ok(r.s === 413, '기록 크기 제한');

// 개발자 편집
r = await call('GET', 'edits'); ok(r.s === 200 && r.j.rev === 0, '편집 공유는 로그인 없이 읽기');
r = await call('PUT', 'edits', { edits: { house: { d: '새 설명' } } }, minsu); ok(r.s === 403, '일반 계정은 편집 공유 불가');
r = await call('PUT', 'edits', { edits: { house: { d: '새 설명', evil: '<x>', vid: 'abcdefghijk' }, 'BAD ID': { d: 'x' } } }, master);
ok(r.s === 200 && r.j.count === 1, '대표 계정은 편집 공유, 잘못된 항목은 걸러짐');
r = await call('GET', 'edits'); ok(r.j.edits.house.d === '새 설명' && !r.j.edits.house.evil, '허용된 칸만 저장');
r = await call('PUT', 'edits', { edits: { house: { m0: '지금 곡', m1: '작가', mv: 'https://youtu.be/abcdefghijk', ms: 'https://example.com' } } }, master); ok(r.s === 200 && r.j.count === 1, '현대 예시 칸도 편집 공유');
r = await call('GET', 'edits'); ok(r.j.edits.house.m0 === '지금 곡' && r.j.edits.house.mv.includes('abcdefghijk'), '현대 예시 칸 저장');

// 개발자 권한
r = await call('POST', 'dev/grant', { id: 'minsu' }, minsu); ok(r.s === 403, '일반 계정은 권한 부여 불가');
r = await call('POST', 'dev/grant', { id: 'ghost' }, master); ok(r.s === 404, '없는 계정에는 권한 부여 불가');
r = await call('POST', 'dev/grant', { id: 'minsu' }, master); ok(r.s === 200 && r.j.devs.includes('minsu'), '권한 부여');
r = await call('GET', 'me', null, minsu); ok(r.j.dev === true && r.j.master === false, '권한이 바로 적용');
r = await call('PUT', 'edits', { edits: { house: { d: '민수가 고침' } } }, minsu); ok(r.s === 200, '권한을 받은 계정은 편집 공유 가능');
r = await call('POST', 'dev/grant', { id: 'minsu', dev: false }, master); ok(r.s === 200 && !r.j.devs.includes('minsu'), '권한 거두기');
r = await call('PUT', 'edits', { edits: {} }, minsu); ok(r.s === 403, '거둔 뒤에는 불가');

// 의견 보내기
r = await call('POST', 'feedback', { text: 'a' }, null, '5.5.5.5'); ok(r.s === 400, '너무 짧은 의견 거부');
r = await call('POST', 'feedback', { text: '지도가 안 돌아가요', ctx: 'v0.83' }, null, '5.5.5.5'); ok(r.s === 200, '손님도 의견 보내기');
r = await call('POST', 'feedback', { text: '로그인한 의견입니다' }, master, '5.5.5.6'); ok(r.s === 200, '로그인하고 의견 보내기');
let fl; for (let i = 0; i < 6; i++) fl = await call('POST', 'feedback', { text: '반복 ' + i }, null, '5.5.5.7'); ok(fl.s === 429, '의견 보내기 횟수 제한');
r = await call('GET', 'dev/feedback', null, minsu); ok(r.s === 403, '일반 계정은 의견 목록 못 봄');
r = await call('GET', 'dev/feedback', null, master); ok(r.s === 200 && r.j.items.length >= 7 && r.j.items.some((x) => x.id === 'dev.KSJ'), '대표 계정은 의견 목록 보기');
const one = r.j.items[0].t;
r = await call('POST', 'dev/feedback-delete', { t: one }, master); ok(r.s === 200, '의견 하나 지우기');
r = await call('POST', 'dev/feedback-delete', { all: true }, master); ok(r.s === 200 && r.j.left === 0, '의견 모두 지우기');

// 비밀번호와 로그아웃
r = await call('POST', 'password', { old: 'bad', password: 'brandnew-pass' }, minsu); ok(r.s === 403, '지금 비밀번호가 틀리면 변경 불가');
r = await call('POST', 'password', { old: 'longenough1', password: 'brandnew-pass' }, minsu); ok(r.s === 200 && r.j.token, '비밀번호 변경');
const minsu2 = r.j.token;
r = await call('GET', 'me', null, minsu); ok(r.s === 401, '비밀번호를 바꾸면 이전 토큰은 무효');
r = await call('GET', 'me', null, minsu2); ok(r.s === 200, '새 토큰은 유효');
r = await call('POST', 'login', { id: 'minsu', password: 'longenough1' }); ok(r.s === 401, '이전 비밀번호로는 로그인 불가');
r = await call('POST', 'logout-all', {}, minsu2); const minsu3 = r.j.token; ok(r.s === 200, '모든 기기 로그아웃');
r = await call('GET', 'me', null, minsu2); ok(r.s === 401, '로그아웃된 토큰 무효');
r = await call('POST', 'dev/reset', { id: 'minsu', password: 'reset-by-master' }, master); ok(r.s === 200, '대표 계정이 비밀번호 재설정');
r = await call('POST', 'login', { id: 'minsu', password: 'reset-by-master' }); ok(r.s === 200, '재설정한 비밀번호로 로그인');

// 로그인 시도 제한
let last;
for (let i = 0; i < 9; i++) last = await call('POST', 'login', { id: 'minsu', password: 'nope-nope-' + i }, null, '9.9.9.9');
ok(last.s === 429, '같은 접속 주소에서 틀린 로그인이 쌓이면 잠금');
r = await call('POST', 'login', { id: 'minsu', password: 'reset-by-master' }, null, '9.9.9.9'); ok(r.s === 429, '잠긴 접속 주소는 맞는 비밀번호도 거부');
r = await call('POST', 'login', { id: 'minsu', password: 'reset-by-master' }, null, '8.8.8.8'); ok(r.s === 200, '다른 접속 주소에서는 잠기지 않음(남이 내 계정을 잠글 수 없음)');
for (let i = 0; i < 31; i++) last = await call('POST', 'login', { id: 'dev.KSJ', password: 'nope-nope-' + i }, null, '7.7.' + Math.floor(i / 200) + '.' + (i % 200));
ok(last.s === 429, '접속 주소를 바꿔 가며 한 아이디를 계속 두드리면 아이디 전체가 잠금');
r = await call('POST', 'login', { id: 'dev.KSJ', password: 'master-pass-1' }, null, '6.6.6.6'); ok(r.s === 429, '아이디 전체가 잠긴 동안은 맞는 비밀번호도 거부');

// 로그인 표 갱신
r = await call('POST', 'login', { id: 'minsu', password: 'reset-by-master' }, null, '5.4.3.2'); ok(r.s === 200, '갱신 시험용 로그인');
const fresh = r.j.token; const pl = JSON.parse(Buffer.from(fresh.split('.')[0], 'base64url').toString());
const sign = (o) => { const body = Buffer.from(JSON.stringify(o)).toString('base64url'); return body + '.' + createHmac('sha256', env.SECRET).update(body).digest('base64url'); };
r = await call('GET', 'me', null, fresh); ok(r.s === 200 && !r.j.token, '새로 받은 표는 갱신하지 않음');
const old = sign({ i: pl.i, v: pl.v, e: Math.floor(Date.now() / 1000) + 3600 });
r = await call('GET', 'me', null, old); ok(r.s === 200 && typeof r.j.token === 'string', '만료가 가까운 표는 새 표를 받음');
r = await call('GET', 'me', null, r.j.token); ok(r.s === 200, '갱신된 표로 계속 로그인');
const dead = sign({ i: pl.i, v: pl.v, e: Math.floor(Date.now() / 1000) - 10 });
r = await call('GET', 'me', null, dead); ok(r.s === 401, '만료된 표는 거부');

// 삭제
r = await call('POST', 'delete', { password: 'master-pass-1' }, master); ok(r.s === 403 && r.j.error === 'master', '대표 계정은 삭제 불가');
const ana = (await call('POST', 'register', { id: 'ana', password: 'ana-password-1' }, null, '2.2.2.2')).j.token;
r = await call('POST', 'delete', { password: 'wrong' }, ana); ok(r.s === 403, '삭제는 비밀번호 확인');
r = await call('POST', 'delete', { password: 'ana-password-1' }, ana); ok(r.s === 200, '계정 삭제');
r = await call('GET', 'me', null, ana); ok(r.s === 401, '삭제한 계정의 토큰 무효');
r = await call('GET', 'nothing'); ok(r.s === 404, '없는 주소');
r = await handle(new Request('http://x/api/register', { method: 'POST', headers: { 'CF-Connecting-IP': '3.3.3.3' }, body: '{not json' }), env, kv); ok(r.status === 400, '깨진 JSON');

console.log(`\n${n - fail}/${n} 통과`);
process.exit(fail ? 1 : 0);
