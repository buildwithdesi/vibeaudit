import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

const isPublic = createRouteMatcher([
  '/api/webhooks(.*)',
  '/api/health',
]);

export default clerkMiddleware((auth, req) => {
  if (isPublic(req)) return undefined;
  return auth.protect();
});
