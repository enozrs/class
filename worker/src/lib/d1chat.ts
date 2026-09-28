// D1 chat helpers. Same external contract as the old R2 version:
// read returns { messages: [...] } (chronological, capped at 20),
// append inserts and trims atomically.
//
// No etag conditional write is needed — D1's batch() runs statements
// in a single transaction, so insert + trim are atomic.

export interface ChatMessage {
  id?: number;
  student_name: string;
  message: string;
  created_at: number;
}

export interface ChatDoc {
  messages: ChatMessage[];
}

const MAX_MESSAGES = 20;

/**
 * Read the last MAX_MESSAGES messages in chronological order.
 * (SQL is DESC LIMIT for index efficiency; we reverse in JS.)
 */
export async function readChat(db: D1Database): Promise<ChatDoc> {
  const result = await db
    .prepare(
      'SELECT id, student_name, message, created_at FROM messages ORDER BY created_at DESC, id DESC LIMIT ?',
    )
    .bind(MAX_MESSAGES)
    .all<ChatMessage>();

  const rows = (result.results || []) as ChatMessage[];
  // Reverse so the array is chronological (oldest first) for the client.
  return { messages: rows.reverse() };
}

/**
 * Insert a new message and trim to the last MAX_MESSAGES rows, atomically.
 * Uses D1.batch() which runs both statements in one transaction.
 */
export async function appendChatMessage(
  db: D1Database,
  msg: ChatMessage,
): Promise<void> {
  const insert = db
    .prepare(
      'INSERT INTO messages (student_name, message, created_at) VALUES (?, ?, ?)',
    )
    .bind(msg.student_name, msg.message, msg.created_at);

  const trim = db
    .prepare(
      'DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY created_at DESC, id DESC LIMIT ?)',
    )
    .bind(MAX_MESSAGES);

  await db.batch([insert, trim]);
}