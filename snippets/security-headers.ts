// Excerpt from GameArena (private source), snapshot 2026-11-25.
// HTTP security headers + Content-Security-Policy (from next.config.ts).
// Imports may point to files that are not part of this repository.

import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === "development";
// Vercel preview deployments load Vercel's feedback toolbar from vercel.live.
const isVercelPreview = process.env.VERCEL_ENV === "preview";
const vercelLive = isVercelPreview ? " https://vercel.live" : "";

// Live chat connects straight from the phone to our Supabase project
// (HTTPS for data, WSS for live updates). Only that one address is allowed.
function supabaseHttpOrigin(): string {
  try {
    return ` ${new URL(process.env.NEXT_PUBLIC_SUPABASE_URL ?? "").origin}`;
  } catch {
    return "";
  }
}

function supabaseOrigins(): string {
  try {
    const url = new URL(process.env.NEXT_PUBLIC_SUPABASE_URL ?? "");
    return ` ${url.origin} wss://${url.host}`;
  } catch {
    return "";
  }
}

/**
 * Content Security Policy: tells the browser which sources it may load
 * scripts, styles, images etc. from. If someone ever manages to inject
 * HTML into a page, the browser still refuses to load their scripts from
 * other sites or send data to them.
 *
 * 'unsafe-inline' for scripts is needed because Next.js puts small inline
 * scripts in static pages. The stricter nonce-based CSP would force every
 * page to render on each request (slower, costs more). See SECURITY.md.
 */
const contentSecurityPolicy = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}${vercelLive}`,
  `style-src 'self' 'unsafe-inline'${vercelLive}`,
  // Chat photos/videos: short-lived signed links from our own Supabase project.
  `img-src 'self' data: blob:${supabaseHttpOrigin()}${isVercelPreview ? " https://vercel.live https://vercel.com" : ""}`,
  `media-src 'self' blob:${supabaseHttpOrigin()}`,
  `font-src 'self'${isVercelPreview ? " https://vercel.live https://assets.vercel.com" : ""}`,
  `connect-src 'self'${supabaseOrigins()}${isVercelPreview ? " https://vercel.live wss://ws-us3.pusher.com" : ""}`,
  `frame-src ${isVercelPreview ? "https://vercel.live" : "'none'"}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "manifest-src 'self'",
  ...(isDev ? [] : ["upgrade-insecure-requests"]),
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: contentSecurityPolicy },
  // Only ever talk to us over HTTPS (2 years).
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  // Don't guess file types (stops a "picture" being run as a script).
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Nobody may show our pages inside a frame (clickjacking).
  { key: "X-Frame-Options", value: "DENY" },
  // Don't leak full URLs to other sites.
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Turn off phone features we don't use.
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  },
  // Other sites' windows can't reach into ours.
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];
