// R2 conditional read/write helpers for the ephemeral chat document.
// chat.json shape: { messages: [{ student_name, message, created_at }, ...] }
// Capped at the last 20 entries, oldest dropped first.

export interface ChatMessage {
  student_name: string;
  message: string;
  created_at: number;
}

export interface ChatDoc {
  messages: ChatMessage[];
}

const CHAT_KEY = 'chat.json';
const MAX_MESSAGES = 20;
const MAX_WRITE_ATTEMPTS = 3;

// Short cache TTL collapses simultaneous polling students onto a single
// origin read while still feeling close-to-live. This is the load-bearing
// cost optimization — do not raise it without understanding the trade-off.
const CACHE_CONTROL = 'public, max-age=2';

export async function readChat(
  bucket: R2Bucket,
): Promise<{ doc: ChatDoc; etag: string | null }> {
  const obj = await bucket.get(CHAT_KEY);
  if (!obj) return { doc: { messages: [] }, etag: null };
  const text = await obj.text();
  let doc: ChatDoc;
  try {
    doc = JSON.parse(text) as ChatDoc;
  } catch {
    doc = { messages: [] };
  }
  if (!Array.isArray(doc.messages)) doc.messages = [];
  return { doc, etag: obj.etag };
}

/**
 * Append a message and trim to MAX_MESSAGES, using an etag conditional write.
 * On precondition failure (another message landed first), re-fetch and retry
 * the whole cycle. Throws after MAX_WRITE_ATTEMPTS to let the caller return
 * a 409 to the client.
 */
export async function appendChatMessage(
  bucket: R2Bucket,
  msg: ChatMessage,
): Promise<void> {
  for (let attempt = 0; attempt < MAX_WRITE_ATTEMPTS; attempt++) {
    const { doc, etag } = await readChat(bucket);
    const messages = [...doc.messages, msg].slice(-MAX_MESSAGES);
    const body = JSON.stringify({ messages });

    const opts: R2PutOptions = {
      httpMetadata: {
        contentType: 'application/json',
        cacheControl: CACHE_CONTROL,
      },
    };
    // If the object exists, require an etag match. If it doesn't exist yet,
    // require that it still doesn't exist (`If-None-Match: *`).
    if (etag) {
      opts.onlyIf = { etagMatches: etag };
    } else {
      opts.onlyIf = { etagDoesNotMatch: '*' };
    }

    const res = await bucket.put(CHAT_KEY, body, opts);
    if (res !== null) return; // success
    // res === null means the precondition failed; loop and retry.
  }
  throw new Error('Chat write conflict: exhausted retries');
}