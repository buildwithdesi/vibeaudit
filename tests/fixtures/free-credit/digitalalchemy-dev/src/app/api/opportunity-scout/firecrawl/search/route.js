async function reserveMonthlyCredits() {
  const remaining = 100;
  if (remaining <= 0) throw new Error('cap');
  return remaining;
}

export async function POST(req) {
  const header = req.headers.get('authorization') || '';
  if (!header.startsWith('Bearer ')) return new Response('Unauthorized', { status: 401 });
  await reserveMonthlyCredits();
  await fetch('https://api.firecrawl.dev/v1/search', { method: 'POST' });
  return new Response('ok');
}
