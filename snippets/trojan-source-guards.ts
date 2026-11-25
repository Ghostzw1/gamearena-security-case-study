// Excerpt from GameArena (private source), snapshot 2026-11-25.
// Rejecting invisible / text-direction characters (Trojan Source).
// Imports may point to files that are not part of this repository.

// Shared text checks for server actions.

/** Zero-width and text-direction characters (used to disguise text). */
export const INVISIBLE_OR_BIDI = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/u;

/** Control characters (newlines included: strip them first where allowed). */
export const CONTROL_CHARS = /\p{Cc}/u;
