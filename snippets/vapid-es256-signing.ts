// Excerpt from GameArena (private source), snapshot 2026-11-25.
// Signing Web Push requests (VAPID JWT, ES256) with Node built-in crypto, no extra package.
// Imports may point to files that are not part of this repository.

import "server-only";

import { createPrivateKey, sign } from "node:crypto";

import { VAPID_PUBLIC_KEY, isAllowedPushEndpoint } from "@/lib/push/config";
import { getSiteUrl } from "@/lib/site";

const b64url = (data: Buffer | string) => Buffer.from(data).toString("base64url");

/**
 * The "VAPID" header proves to Google/Apple/Mozilla that a push comes from
 * us: a short-lived token (JWT) signed with our private key (ES256), using
 * only Node's built-in crypto.
 */
export function vapidAuthorization(endpoint: string, privateKeyPkcs8: string, now = Date.now()): string {
  const site = getSiteUrl();
  const header = b64url(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = b64url(
    JSON.stringify({
      aud: new URL(endpoint).origin,
      exp: Math.floor(now / 1000) + 12 * 3600,
      sub: site.startsWith("https://") ? site : "https://gamearena-beige.vercel.app",
    }),
  );
  const key = createPrivateKey({ key: Buffer.from(privateKeyPkcs8, "base64url"), format: "der", type: "pkcs8" });
  const signature = sign("sha256", Buffer.from(`${header}.${claims}`), { key, dsaEncoding: "ieee-p1363" });
  return `vapid t=${header}.${claims}.${b64url(signature)}, k=${VAPID_PUBLIC_KEY}`;
}

export type PushOutcome = "sent" | "gone" | "failed";

/**
 * Sends an EMPTY push (no data inside), so nothing about the player passes
 * through Google/Apple. The phone wakes up and asks our site what to show.
 */
export async function sendEmptyPush(endpoint: string, privateKeyPkcs8: string): Promise<PushOutcome> {
  if (!isAllowedPushEndpoint(endpoint)) return "failed";
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: vapidAuthorization(endpoint, privateKeyPkcs8),
        TTL: String(20 * 3600),
        Urgency: "normal",
        "Content-Length": "0",
      },
      signal: AbortSignal.timeout(5000),
    });
    if (res.status === 404 || res.status === 410) return "gone";
    return res.ok ? "sent" : "failed";
  } catch {
    return "failed";
  }
}
