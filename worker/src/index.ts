import {
  getFile,
  readModifyWrite,
  GitHubConflictError,
  type Env,
} from './lib/github';
import { readChat, appendChatMessage } from './lib/d1chat';
import { sanitizeText, sanitizeName } from './lib/sanitize';

interface AccessKeyRecord {
  access_key: string;
  student_name: string;
  whatsapp_number: string;
  payment_method: 'eSewa' | 'Bank Transfer' | 'Cash' | 'Other';
  amount_paid: number;
  batch_name: string;
  start_date: string;
  end_date: string;
  status: 'active' | 'revoked';
  created_at: string;
}

interface ScheduleEntry {
  id: string;
  batch_name: string;
  title: string;
  youtube_video_id: string;
  scheduled_start_time: string;
  is_active: boolean;
  created_at: string;
}

const ACCESS_KEYS_PATH = 'site/data/access-keys.json';
const SCHEDULE_PATH = 'site/data/schedule.json';
const PAYMENT_METHODS = ['eSewa', 'Bank Transfer', 'Cash', 'Other'] as const;
const MEET_PREFIX = 'xxxgooglemeet:';
const MEET_END = 'xxxgooglemeet-end';

// ===== Utilities =====

function corsHeaders(env: Env): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function jsonResponse(data: unknown, status: number, env: Env): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(env),
    },
  });
}

function errorResponse(message: string, status: number, env: Env): Response {
  return jsonResponse({ ok: false, error: message }, status, env);
}

function isAdmin(request: Request, env: Env): boolean {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  const provided = m[1];
  const expected = env.ADMIN_SECRET;
  if (provided.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < provided.length; i++) {
    diff |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

// ===== Access key generation =====
// Format: <BatchPrefix>-<GROUP4>-<GROUP4> e.g. "B4-K3M9-7QXZ"
// Alphabet excludes 0/O/1/I/L to avoid transcription errors.

const KEY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

function randomGroup(len: number): string {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < len; i++) {
    out += KEY_ALPHABET[bytes[i] % KEY_ALPHABET.length];
  }
  return out;
}

function batchPrefix(batchName: string): string {
  const parts = batchName.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return 'XX';
  const first = parts[0].toUpperCase().replace(/[^A-Z]/g, '');
  const second = parts[1] ? parts[1].replace(/[^0-9]/g, '') : '';
  const prefix = ((first.charAt(0) || 'X') + second).slice(0, 4);
  return prefix || 'XX';
}

function generateAccessKey(batchName: string): string {
  return `${batchPrefix(batchName)}-${randomGroup(4)}-${randomGroup(4)}`;
}

// ===== Date validation =====
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isValidDateString(s: string): boolean {
  if (!DATE_RE.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d.getTime());
}

class NotFoundError extends Error {}

// ===== Chat: read (public, cacheable) =====
async function handleChatRead(env: Env): Promise<Response> {
  const doc = await readChat(env.DB);
  // CRITICAL: public + s-maxage=1 makes Cloudflare's edge cache the response
  // for 1 second. This is what collapses 200 concurrent pollers onto ~1 D1
  // read per second. Requires the Worker to be on a CUSTOM DOMAIN — the
  // *.workers.dev subdomain is not cached by Cloudflare.
  return new Response(JSON.stringify(doc), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=1, s-maxage=1',
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
      Vary: 'Origin',
    },
  });
}

// ===== Chat: send (public, validated, write) =====
async function handleChatSend(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, env);
  }

  const accessKey =
    typeof body.access_key === 'string'
      ? body.access_key.trim().toUpperCase()
      : '';
  const studentName = sanitizeName(body.student_name, 50);
  const rawMessage = typeof body.message === 'string' ? body.message : '';
  const message = sanitizeText(rawMessage, 300);

  if (!accessKey) return errorResponse('Missing access_key', 400, env);
  if (!studentName) return errorResponse('Missing student_name', 400, env);
  if (!message) return errorResponse('Message cannot be empty', 400, env);
  if (rawMessage.length > 300) {
    return errorResponse('Message exceeds 300 characters', 400, env);
  }

  // Validate the access key against the current committed file.
  const { content: keys } = await getFile(env, ACCESS_KEYS_PATH);
  if (!Array.isArray(keys)) {
    return errorResponse('Access key store corrupted', 500, env);
  }

  const record = (keys as AccessKeyRecord[]).find(
    (k) =>
      typeof k.access_key === 'string' &&
      k.access_key.toUpperCase() === accessKey,
  );
  if (!record) return errorResponse('Access key not found', 403, env);
  if (record.status !== 'active') {
    return errorResponse('Access key revoked', 403, env);
  }

  const today = new Date().toISOString().slice(0, 10);
  if (today < record.start_date) {
    return errorResponse('Access period not started', 403, env);
  }
  if (today > record.end_date) {
    return errorResponse('Access key expired', 403, env);
  }

  await appendChatMessage(env.DB, {
    student_name: studentName,
    message,
    created_at: Date.now(),
  });
  return jsonResponse({ ok: true }, 200, env);
}

// ===== Chat: admin broadcast (Meet relay) =====
async function handleBroadcast(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, env);
  }

  const action = body.action === 'end' ? 'end' : 'start';
  let message: string;

  if (action === 'end') {
    message = MEET_END;
  } else {
    const url = typeof body.url === 'string' ? body.url.trim() : '';
    if (!/^https:\/\/meet\.google\.com\/[A-Za-z0-9-]+$/.test(url)) {
      return errorResponse('Invalid Google Meet URL', 400, env);
    }
    message = MEET_PREFIX + url;
  }

  await appendChatMessage(env.DB, {
    student_name: 'System',
    message,
    created_at: Date.now(),
  });
  return jsonResponse({ ok: true }, 200, env);
}

// ===== Admin: access keys =====
async function handleCreateAccessKey(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, env);
  }

  const studentName = sanitizeName(body.student_name, 80);
  const whatsapp = sanitizeText(body.whatsapp_number, 30);
  const paymentMethod = sanitizeText(body.payment_method, 30);
  const amount = Number(body.amount_paid);
  const batch = sanitizeName(body.batch_name, 50);
  const startDate = String(body.start_date || '');
  const endDate = String(body.end_date || '');

  if (!studentName) return errorResponse('student_name is required', 400, env);
  if (!whatsapp) return errorResponse('whatsapp_number is required', 400, env);
  if (!batch) return errorResponse('batch_name is required', 400, env);
  if (!PAYMENT_METHODS.includes(paymentMethod as any)) {
    return errorResponse('Invalid payment_method', 400, env);
  }
  if (!Number.isFinite(amount) || amount < 0) {
    return errorResponse('Invalid amount_paid', 400, env);
  }
  if (!isValidDateString(startDate)) {
    return errorResponse('Invalid start_date', 400, env);
  }
  if (!isValidDateString(endDate)) {
    return errorResponse('Invalid end_date', 400, env);
  }
  if (endDate < startDate) {
    return errorResponse('end_date must be after start_date', 400, env);
  }

  const newRecord: AccessKeyRecord = {
    access_key: generateAccessKey(batch),
    student_name: studentName,
    whatsapp_number: whatsapp,
    payment_method: paymentMethod as AccessKeyRecord['payment_method'],
    amount_paid: amount,
    batch_name: batch,
    start_date: startDate,
    end_date: endDate,
    status: 'active',
    created_at: new Date().toISOString(),
  };

  try {
    await readModifyWrite<AccessKeyRecord[]>(
      env,
      ACCESS_KEYS_PATH,
      (current) => {
        const list = Array.isArray(current) ? current : [];
        let key = newRecord.access_key;
        let guard = 0;
        while (list.some((k) => k.access_key === key) && guard < 10) {
          key = generateAccessKey(batch);
          guard++;
        }
        if (guard >= 10) {
          throw new Error('Could not generate unique access key');
        }
        newRecord.access_key = key;
        return {
          next: [...list, newRecord],
          commitMessage: `Approve access key for ${newRecord.student_name}`,
        };
      },
    );
  } catch (err) {
    if (err instanceof GitHubConflictError) {
      return errorResponse(
        'Conflict — someone else just wrote the file. Try again.',
        409,
        env,
      );
    }
    throw err;
  }

  return jsonResponse({ access_key: newRecord.access_key }, 200, env);
}

async function handleGetAccessKeys(env: Env): Promise<Response> {
  const { content } = await getFile(env, ACCESS_KEYS_PATH);
  return jsonResponse(content, 200, env);
}

async function handleRevokeAccessKey(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, env);
  }
  const key =
    typeof body.access_key === 'string'
      ? body.access_key.trim().toUpperCase()
      : '';
  if (!key) return errorResponse('Missing access_key', 400, env);

  try {
    await readModifyWrite<AccessKeyRecord[]>(
      env,
      ACCESS_KEYS_PATH,
      (current) => {
        const list = Array.isArray(current) ? current : [];
        const idx = list.findIndex(
          (k) =>
            typeof k.access_key === 'string' &&
            k.access_key.toUpperCase() === key,
        );
        if (idx === -1) throw new NotFoundError('Access key not found');
        const updated = list.map((k, i) =>
          i === idx ? { ...k, status: 'revoked' as const } : k,
        );
        return {
          next: updated,
          commitMessage: `Revoke access key ${key}`,
        };
      },
    );
  } catch (err) {
    if (err instanceof NotFoundError) {
      return errorResponse(err.message, 404, env);
    }
    if (err instanceof GitHubConflictError) {
      return errorResponse(
        'Conflict — someone else just wrote the file. Try again.',
        409,
        env,
      );
    }
    throw err;
  }
  return jsonResponse({ ok: true }, 200, env);
}

// ===== Admin: schedule =====
async function handleCreateSchedule(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, env);
  }

  const batch = sanitizeName(body.batch_name, 50);
  const title = sanitizeText(body.title, 200);
  const videoId = sanitizeText(body.youtube_video_id, 30);
  const startTimeRaw = String(body.scheduled_start_time || '');

  if (!batch) return errorResponse('batch_name is required', 400, env);
  if (!title) return errorResponse('title is required', 400, env);
  if (!/^[A-Za-z0-9_-]{11}$/.test(videoId)) {
    return errorResponse('Invalid YouTube video ID', 400, env);
  }
  const startTime = new Date(startTimeRaw);
  if (isNaN(startTime.getTime())) {
    return errorResponse('Invalid scheduled_start_time', 400, env);
  }

  const id = `lesson-${Date.now()}`;
  const entry: ScheduleEntry = {
    id,
    batch_name: batch,
    title,
    youtube_video_id: videoId,
    scheduled_start_time: startTime.toISOString(),
    is_active: false,
    created_at: new Date().toISOString(),
  };

  try {
    await readModifyWrite<ScheduleEntry[]>(env, SCHEDULE_PATH, (current) => {
      const list = Array.isArray(current) ? current : [];
      return {
        next: [...list, entry],
        commitMessage: `Add lesson ${id}`,
      };
    });
  } catch (err) {
    if (err instanceof GitHubConflictError) {
      return errorResponse(
        'Conflict — someone else just wrote the file. Try again.',
        409,
        env,
      );
    }
    throw err;
  }
  return jsonResponse({ id }, 200, env);
}

async function handleGetSchedule(env: Env): Promise<Response> {
  const { content } = await getFile(env, SCHEDULE_PATH);
  return jsonResponse(content, 200, env);
}

async function handleActivateSchedule(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, env);
  }
  const id = typeof body.id === 'string' ? body.id.trim() : '';
  if (!id) return errorResponse('Missing id', 400, env);

  try {
    await readModifyWrite<ScheduleEntry[]>(env, SCHEDULE_PATH, (current) => {
      const list = Array.isArray(current) ? current : [];
      let found = false;
      const updated = list.map((entry) => {
        if (entry.id === id) {
          found = true;
          return { ...entry, is_active: true };
        }
        return { ...entry, is_active: false };
      });
      if (!found) throw new NotFoundError('Lesson not found');
      return {
        next: updated,
        commitMessage: `Activate ${id}`,
      };
    });
  } catch (err) {
    if (err instanceof NotFoundError) {
      return errorResponse(err.message, 404, env);
    }
    if (err instanceof GitHubConflictError) {
      return errorResponse(
        'Conflict — someone else just wrote the file. Try again.',
        409,
        env,
      );
    }
    throw err;
  }
  return jsonResponse({ ok: true }, 200, env);
}

// ===== Router =====

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    try {
      // ----- Public routes -----
      if (path === '/api/chat' && method === 'GET') {
        return await handleChatRead(env);
      }
      if (path === '/api/chat/send' && method === 'POST') {
        return await handleChatSend(request, env);
      }

      // ----- Admin routes -----
      if (path.startsWith('/api/admin/')) {
        if (!isAdmin(request, env)) {
          return errorResponse('Unauthorized', 401, env);
        }
        if (path === '/api/admin/chat/broadcast' && method === 'POST') {
          return await handleBroadcast(request, env);
        }
        if (path === '/api/admin/access-keys' && method === 'POST') {
          return await handleCreateAccessKey(request, env);
        }
        if (path === '/api/admin/access-keys' && method === 'GET') {
          return await handleGetAccessKeys(env);
        }
        if (path === '/api/admin/access-keys/revoke' && method === 'POST') {
          return await handleRevokeAccessKey(request, env);
        }
        if (path === '/api/admin/schedule' && method === 'POST') {
          return await handleCreateSchedule(request, env);
        }
        if (path === '/api/admin/schedule' && method === 'GET') {
          return await handleGetSchedule(env);
        }
        if (path === '/api/admin/schedule/activate' && method === 'POST') {
          return await handleActivateSchedule(request, env);
        }
      }

      return errorResponse('Not found', 404, env);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Unhandled error:', msg);
      return errorResponse(`Server error: ${msg}`, 500, env);
    }
  },
};