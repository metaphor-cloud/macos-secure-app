import { NOTES_PATH } from "@secure-app/shared/request";
import { notifyTablesChanged } from "../lib/hub";
import { sendPush } from "../lib/push";
import { log } from "../log";
import type { Handler } from "../routes";

/**
 * The example business API: a shared list of notes. Replace it with your own.
 * It shows the three shapes an app usually needs: a list, a write that tells
 * every open app to refetch (and pushes a hint to the other Macs), and a file
 * download.
 */

const TITLE_MAX = 120;
const BODY_MAX = 10_000;
const LIST_LIMIT = 200;

interface NoteRow {
  id: string;
  title: string;
  body: string;
  author_email: string;
  created_at: string;
}

const note = (r: NoteRow) => ({ id: r.id, title: r.title, body: r.body, authorEmail: r.author_email, createdAt: r.created_at });

/** GET /api/notes: the newest notes first. */
export const listNotes: Handler = async ({ env }) => {
  const rows = await env.DB.prepare("SELECT id, title, body, author_email, created_at FROM notes ORDER BY created_at DESC, id LIMIT ?")
    .bind(LIST_LIMIT)
    .all<NoteRow>();
  return Response.json({ notes: rows.results.map(note) });
};

/** POST /api/notes {title, body}. */
export const createNote: Handler = async ({ request, env, ctx, identity }) => {
  const keyRef = identity.keyId.slice(0, 12);
  let input: { title?: unknown; body?: unknown };
  try {
    input = await request.json();
  } catch {
    log("warn", "note refused", { reason: "bad_json", keyRef });
    return Response.json({ error: "Bad request" }, { status: 400 });
  }
  const title = typeof input.title === "string" ? input.title.trim() : "";
  const body = input.body === undefined ? "" : input.body;
  if (title.length < 1 || title.length > TITLE_MAX || typeof body !== "string" || body.length > BODY_MAX) {
    log("warn", "note refused", { reason: "invalid_note", keyRef });
    return Response.json({ error: `A title of 1 to ${TITLE_MAX} characters and a body of up to ${BODY_MAX} are required` }, { status: 400 });
  }
  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO notes (id, title, body, author_sub, author_email) VALUES (?, ?, ?, ?, ?)")
    .bind(id, title, body, identity.sub, identity.email)
    .run();
  const row = await env.DB.prepare("SELECT id, title, body, author_email, created_at FROM notes WHERE id = ?").bind(id).first<NoteRow>();
  log("info", "note created", { noteId: id, keyRef });
  await notifyTablesChanged(env, ["notes"]);
  // The lock screen says that something happened, never what it says.
  ctx.waitUntil(sendPush(env, { event: "note_created", body: "A note was added.", path: "#/notes", exceptKeyId: identity.keyId, context: { noteId: id } }));
  return Response.json({ note: note(row!) }, { status: 201, headers: { Location: `${NOTES_PATH}/${id}` } });
};

/** GET /api/notes/:id/export: the note as a Markdown file, to exercise the app's download path. */
export const exportNote: Handler = async ({ env, params, identity }) => {
  const row = await env.DB.prepare("SELECT id, title, body, author_email, created_at FROM notes WHERE id = ?").bind(params.id).first<NoteRow>();
  if (!row) {
    log("warn", "note export refused", { reason: "note_not_found", noteId: params.id.slice(0, 64), keyRef: identity.keyId.slice(0, 12) });
    return Response.json({ error: "No note with that id" }, { status: 404 });
  }
  const text = `# ${row.title}\n\n${row.body}\n\n(${row.author_email}, ${row.created_at} UTC)\n`;
  return new Response(text, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": `attachment; filename="note-${row.id}.md"`,
      "Cache-Control": "no-store",
    },
  });
};
