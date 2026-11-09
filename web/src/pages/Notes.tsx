import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, openFile } from "../native";

interface Note {
  id: string;
  title: string;
  body: string;
  authorEmail: string;
  createdAt: string;
}

export function NotesPage({ changes }: { changes: { tables: string[]; n: number } }) {
  const [notes, setNotes] = useState<Note[] | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const res = await api<{ notes: Note[] }>("GET", "/api/notes");
    if (res.ok) setNotes(res.data.notes);
    else setError(`Couldn't load notes (${res.status})`);
  }, []);

  useEffect(() => {
    load().catch((e: unknown) => setError(String(e)));
  }, [load]);

  // The live socket says which tables changed; the page refetches through the signed API.
  useEffect(() => {
    if (changes.tables.includes("notes")) load().catch((e: unknown) => setError(String(e)));
  }, [changes, load]);

  async function create(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ error?: string }>("POST", "/api/notes", { title, body });
      if (!res.ok) {
        setError(res.data?.error ?? `Couldn't save the note (${res.status})`);
        return;
      }
      setTitle("");
      setBody("");
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Notes</h1>
      <form onSubmit={create} className="card">
        <label>
          Title
          <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={120} required />
        </label>
        <label>
          Note
          <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={3} maxLength={10000} />
        </label>
        <button type="submit" disabled={busy || title.trim() === ""}>
          Add note
        </button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      {notes === null ? (
        <p>Loading</p>
      ) : notes.length === 0 ? (
        <p>No notes yet.</p>
      ) : (
        <ul className="list">
          {notes.map((n) => (
            <li key={n.id} className="card">
              <div className="row">
                <strong>{n.title}</strong>
                <button type="button" onClick={() => openFile(`/api/notes/${n.id}/export`, `note-${n.id}.md`).catch((e: unknown) => setError(String(e)))}>
                  Export
                </button>
              </div>
              {n.body && <p>{n.body}</p>}
              <small>
                {n.authorEmail}, {n.createdAt} UTC
              </small>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
