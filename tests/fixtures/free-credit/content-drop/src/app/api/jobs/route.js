import { requireAuthedApiFromReq } from '@/lib/api-auth';
import { checkKeyedRateLimit } from '@/lib/rate-limit';
import { runJob } from '@/lib/gemini';

export async function POST(req) {
  const auth = await requireAuthedApiFromReq(req, 'engine');
  if (!auth.ok) return auth.response;
  await checkKeyedRateLimit('user-upload', auth.userId);
  return runJob(auth.userId);
}
