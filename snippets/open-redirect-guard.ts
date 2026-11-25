// Excerpt from GameArena (private source), snapshot 2026-11-25.
// Open-redirect protection for ?next= after sign-in.
// Imports may point to files that are not part of this repository.

export function safeNextPath(raw: unknown): string {
  if (typeof raw !== "string") return "/";
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "/";
  return raw.slice(0, 200);
}
