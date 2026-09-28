// GitHub Contents API client for reading + committing JSON files that live
// in the same repo Cloudflare Pages auto-deploys from. Only Contents:Read+Write
// scope is required on the token.

export interface Env {
  CHAT_BUCKET: R2Bucket;
  GITHUB_TOKEN: string;
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
  GITHUB_BRANCH: string;
  ADMIN_SECRET: string;
  ALLOWED_ORIGIN: string;
}

export class GitHubConflictError extends Error {}

/**
 * UTF-8-safe base64 encode. `btoa(JSON.stringify(...))` throws on any
 * non-Latin1 character (e.g. Devanagari names, emoji in lesson titles).
 * Always route through TextEncoder → binary string → btoa.
 */
function utf8ToBase64(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function base64ToUtf8(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

const GH_HEADERS = (token: string): Record<string, string> => ({
  Authorization: `Bearer ${token}`,
  Accept: 'application/vnd.github+json',
  'User-Agent': 'live-classroom-worker',
  'X-GitHub-Api-Version': '2022-11-28',
});

/**
 * Fetch a file's parsed JSON content and the blob SHA required for updates.
 */
export async function getFile(
  env: Env,
  path: string,
): Promise<{ content: any; sha: string }> {
  const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${path}?ref=${env.GITHUB_BRANCH}`;
  const res = await fetch(url, { headers: GH_HEADERS(env.GITHUB_TOKEN) });
  if (!res.ok) {
    throw new Error(`GitHub getFile ${path} failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { content: string; sha: string; encoding: string };
  if (json.encoding !== 'base64') {
    throw new Error(`Unexpected encoding for ${path}: ${json.encoding}`);
  }
  const decoded = base64ToUtf8(json.content.replace(/\n/g, ''));
  return { content: JSON.parse(decoded), sha: json.sha };
}

/**
 * Commit new JSON content to the given path, using the SHA from getFile to
 * avoid clobbering a concurrent edit. Throws GitHubConflictError on 409/422
 * so the caller can retry with a fresh SHA.
 */
export async function putFile(
  env: Env,
  path: string,
  content: any,
  sha: string,
  commitMessage: string,
): Promise<void> {
  const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${path}`;
  const body = {
    message: commitMessage,
    content: utf8ToBase64(JSON.stringify(content, null, 2) + '\n'),
    sha,
    branch: env.GITHUB_BRANCH,
  };
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      ...GH_HEADERS(env.GITHUB_TOKEN),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (res.status === 409 || res.status === 422) {
    throw new GitHubConflictError(`SHA mismatch on ${path}`);
  }
  if (!res.ok) {
    throw new Error(`GitHub putFile ${path} failed: ${res.status} ${await res.text()}`);
  }
}

/**
 * Read-modify-write with one retry on SHA conflict. On a second conflict,
 * throws GitHubConflictError up to the caller.
 */
export async function readModifyWrite<T>(
  env: Env,
  path: string,
  modifier: (current: T) => { next: T; commitMessage: string },
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    const { content, sha } = await getFile(env, path);
    const { next, commitMessage } = modifier(content as T);
    try {
      await putFile(env, path, next, sha, commitMessage);
      return next;
    } catch (err) {
      lastErr = err;
      if (err instanceof GitHubConflictError && attempt === 0) continue;
      throw err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error('readModifyWrite: failed');
}