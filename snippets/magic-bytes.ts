// Excerpt from GameArena (private source), snapshot 2026-11-25.
// Secure file upload: check what a file really is from its first bytes.
// Imports may point to files that are not part of this repository.

import "server-only";

/**
 * What a file REALLY is, from its first bytes ("magic bytes"), not from its
 * name or the type the phone claims. A renamed script stays a script.
 */
export function sniffMedia(bytes: Uint8Array): "jpg" | "png" | "gif" | "webp" | "iso-video" | "webm" | null {
  const at = (i: number) => bytes[i] ?? -1;
  const ascii = (from: number, to: number) => String.fromCharCode(...bytes.slice(from, to));
  if (at(0) === 0xff && at(1) === 0xd8 && at(2) === 0xff) return "jpg";
  if (at(0) === 0x89 && ascii(1, 4) === "PNG" && at(4) === 0x0d && at(5) === 0x0a && at(6) === 0x1a && at(7) === 0x0a) return "png";
  if (ascii(0, 4) === "GIF8") return "gif";
  if (ascii(0, 4) === "RIFF" && ascii(8, 12) === "WEBP") return "webp";
  if (ascii(4, 8) === "ftyp") return "iso-video"; // MP4 and MOV
  if (at(0) === 0x1a && at(1) === 0x45 && at(2) === 0xdf && at(3) === 0xa3) return "webm";
  return null;
}

/** Does the file's content match its extension? */
export function matchesExtension(sniffed: ReturnType<typeof sniffMedia>, ext: string): boolean {
  if (sniffed === null) return false;
  if (sniffed === "iso-video") return ext === "mp4" || ext === "mov";
  return sniffed === ext;
}
