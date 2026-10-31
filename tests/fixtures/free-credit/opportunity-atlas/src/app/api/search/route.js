import { Redis } from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);
const DISPOSABLE_DOMAINS = new Set(['mailinator.com']);

function normalizeEmail(raw) {
  const lower = raw.toLowerCase();
  const parts = lower.split('@');
  const local = parts[0].split('+')[0].replace(/\./g, '');
  const domain = parts[1];
  if (DISPOSABLE_DOMAINS.has(domain)) return '';
  return `${local}@${domain}`;
}

async function reserveCredits() {
  return true;
}

async function checkKeyedRateLimit(bucket, userId) {
  return redis.get(`${bucket}:${userId}`);
}

async function getUser() {
  return {
    id: 'owner',
    primaryEmailAddress: {
      emailAddress: 'owner@example.com',
      verification: { status: 'verified' },
    },
  };
}

export async function POST(req) {
  const user = await getUser(req);
  const email = user.primaryEmailAddress;
  if (email?.verification?.status !== 'verified') return new Response('no', { status: 401 });
  if (normalizeEmail(email.emailAddress) !== process.env.ATLAS_ALLOWED_EMAIL.toLowerCase()) {
    return new Response('no', { status: 401 });
  }
  await checkKeyedRateLimit('search', user.id);
  await reserveCredits(user.id, 100);
  await fetch('https://api.firecrawl.dev/v1/search', { method: 'POST' });
  return new Response('ok');
}
