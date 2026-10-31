const ADMIN_EMAILS = ['owner@example.com'];

export function primaryEmail(user) {
  return user.primaryEmailAddress?.emailAddress
    ?? user.emailAddresses?.[0]?.emailAddress
    ?? null;
}

export function isAdmin(user) {
  const email = primaryEmail(user)?.toLowerCase();
  return ADMIN_EMAILS.includes(email);
}

export function onAllowlist(user, allowlist) {
  const email = primaryEmail(user)?.toLowerCase();
  return allowlist.includes(email);
}
