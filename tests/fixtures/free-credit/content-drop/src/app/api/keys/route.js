import { requireAuthedApiFromReq } from '@/lib/api-auth';

export async function POST(req) {
  const auth = await requireAuthedApiFromReq(req, 'engine');
  if (!auth.ok) return auth.response;
  return createApiKey({ userId: auth.userId });
}
