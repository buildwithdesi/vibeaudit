const buckets = globalThis.__freeCreditBuckets ?? new Map();
globalThis.__freeCreditBuckets = buckets;

export async function checkKeyedRateLimit(bucket, userId) {
  const key = `${bucket}:${userId}`;
  const hits = buckets.get(key) ?? [];
  hits.push(Date.now());
  buckets.set(key, hits);
  return hits.length <= 10;
}
