// Excerpt from GameArena (private source), snapshot 2026-11-25.
// Privacy-preserving rate limits: HMAC-SHA256 of the client IP, never the raw IP.
// Imports may point to files that are not part of this repository.

import "server-only";

import { createHmac } from "node:crypto";
import { headers } from "next/headers";

/**
 * The visitor's IP address, as reported by Vercel's edge network.
 * Vercel overwrites these headers, so a visitor can't fake them there.
 * (Running locally they come from your own machine.)
 */
async function getClientIp(): Promise<string | null> {
  const h = await headers();
  const realIp = h.get("x-real-ip")?.trim();
  if (realIp) return realIp;
  const forwarded = h.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded || null;
}

/**
 * A keyed hash of the IP. We store this, never the raw IP, so the database
 * can count "sign-ups from the same place" without knowing who you are.
 * Without the secret the hash can't be reversed by guessing IPs.
 */
export async function getClientIpHash(secret: string): Promise<string | null> {
  const ip = await getClientIp();
  if (!ip) return null;
  return createHmac("sha256", secret).update(ip).digest("hex");
}
