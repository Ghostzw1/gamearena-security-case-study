// Excerpt from GameArena (private source), snapshot 2026-11-25.
// SSRF prevention: only real push services are ever called.
// Imports may point to files that are not part of this repository.

// Web Push settings shared by the phone and the server.

/**
 * VAPID public key (safe to publish: phones use it to check pushes really
 * come from us). Its private half is VAPID_PRIVATE_KEY, server-only.
 */
export const VAPID_PUBLIC_KEY = "<public VAPID key>";

/**
 * Push services we will ever send to (Chrome/Android, Firefox, Windows,
 * Apple). Same rule as the database CHECK: anything else would let someone
 * make our server POST to any address (SSRF).
 */
const PUSH_ENDPOINT =
  /^https:\/\/(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9-]+\.notify\.windows\.com|web\.push\.apple\.com|[a-z0-9-]+\.push\.apple\.com)\/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$/;

export function isAllowedPushEndpoint(endpoint: unknown): endpoint is string {
  return typeof endpoint === "string" && endpoint.length <= 1000 && PUSH_ENDPOINT.test(endpoint);
}

export const PUSH_KEY = /^[A-Za-z0-9_-]{80,100}={0,2}$/;
export const PUSH_AUTH = /^[A-Za-z0-9_-]{16,30}={0,2}$/;
