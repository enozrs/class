// Text sanitization helpers. The frontend never uses innerHTML, but the
// Worker must not trust the client — sanitize everything before storage.

const TAG_RE = /<[^>]*>/g;
// Strip ASCII control characters except \t, \n, \r. Also strip DEL.
const CTRL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/**
 * Sanitize a chat message. Strips HTML tags and control characters, trims
 * whitespace, and hard-caps the length.
 */
export function sanitizeText(input: unknown, maxLength: number): string {
  if (typeof input !== 'string') return '';
  let s = input.replace(TAG_RE, '');
  s = s.replace(CTRL_RE, '');
  s = s.trim();
  if (s.length > maxLength) s = s.slice(0, maxLength);
  return s;
}

/**
 * Sanitize a display name. Same as sanitizeText but also flattens newlines
 * to spaces so a name can never introduce layout breaks.
 */
export function sanitizeName(input: unknown, maxLength = 50): string {
  const s = sanitizeText(input, maxLength).replace(/[\r\n\t]+/g, ' ');
  return s.trim();
}