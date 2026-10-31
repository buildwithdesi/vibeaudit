export function Widget() {
  const clerk = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
  const admin = process.env.NEXT_PUBLIC_ADMIN_EMAIL;
  return clerk || admin || 'widget';
}
