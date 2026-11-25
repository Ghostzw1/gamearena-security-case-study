// Excerpt from GameArena (private source), snapshot 2026-11-25.
// Daily job: constant-time secret check, no service-role key.
// Imports may point to files that are not part of this repository.

import { createHash, timingSafeEqual } from "node:crypto";

import { createClient } from "@supabase/supabase-js";

import { sendEmptyPush, type PushOutcome } from "@/lib/push/send";
import { SUPABASE_ANON_KEY, SUPABASE_URL, isSupabaseConfigured } from "@/lib/supabase/public-config";
import type { Database } from "@/types/supabase";

/** Compares secrets in constant time (hashing first makes the lengths equal). */
function sameSecret(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * Daily job (vercel.json → crons). Vercel calls it with
 * "Authorization: Bearer <CRON_SECRET>". It asks the database which phones
 * to remind (players not registered for the open tournament), sends each an
 * empty push, and forgets phones that are gone.
 */
export async function GET(request: Request) {
  // Trim: a value pasted into Vercel can pick up a trailing newline.
  const secret = process.env.CRON_SECRET?.trim();
  const vapidKey = process.env.VAPID_PRIVATE_KEY?.trim();
  if (!secret || !vapidKey || !isSupabaseConfigured) {
    return Response.json({ error: "not_configured" }, { status: 503 });
  }
  if (!sameSecret((request.headers.get("authorization") ?? "").trim(), `Bearer ${secret}`)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  // No service-role key: the database functions check the secret themselves.
  const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } });
  const { data, error } = await supabase.rpc("due_push_reminders", { cron_secret: secret });
  if (error) {
    console.error("due_push_reminders failed", error.code);
    return Response.json({ error: "database" }, { status: 500 });
  }

  const endpoints = (data ?? []).map((row) => row.push_endpoint);
  const counts: Record<PushOutcome, number> = { sent: 0, gone: 0, failed: 0 };
  for (let i = 0; i < endpoints.length; i += 10) {
    const batch = endpoints.slice(i, i + 10);
    const results = await Promise.all(batch.map((endpoint) => sendEmptyPush(endpoint, vapidKey)));
    for (const [j, outcome] of results.entries()) {
      counts[outcome]++;
      if (outcome === "gone") {
        await supabase.rpc("forget_push_subscription", { cron_secret: secret, gone_endpoint: batch[j] });
      }
    }
  }
  return Response.json(counts);
}
