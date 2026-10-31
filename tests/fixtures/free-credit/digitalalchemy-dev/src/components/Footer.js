export function Footer() {
  const admin = process.env.NEXT_PUBLIC_ADMIN_EMAIL;
  return admin || 'footer';
}
