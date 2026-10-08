// Cloudflare Pages Functions: /api 로 오는 모든 요청을 받는다.
// 대시보드에서 KV 네임스페이스를 KV라는 이름으로 연결하고, SECRET과 DEV_IDS, DEV_SETUP_CODE 환경 변수를 넣어 준다.
import { handle } from '../../server/core.js';

export async function onRequest(context) {
  return handle(context.request, context.env, context.env.KV);
}
