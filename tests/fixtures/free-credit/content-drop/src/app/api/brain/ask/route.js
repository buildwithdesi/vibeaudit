import { requireAuthedApiFromReq } from '@/lib/api-auth';
import { checkKeyedRateLimit } from '@/lib/rate-limit';
import { ask } from '@/lib/gemini';

export async function POST(req) {
  const auth = await requireAuthedApiFromReq(req, 'session');
  if (!auth.ok) return auth.response;
  await checkKeyedRateLimit('brain-ask', auth.userId);
  return ask(req);
}
