import { useEffect, useState } from "react";
import type { NavGroup } from "@secure-app/shared/bridge";
import { identity as loadIdentity, insideApp, onEvent, reportPage, setLive, signOut, type Identity } from "./native";
import { DevicesPage } from "./pages/Devices";
import { NotesPage } from "./pages/Notes";

const NAV: NavGroup[] = [
  {
    title: "Secure App",
    items: [
      { title: "Notes", path: "#/notes" },
      { title: "Devices", path: "#/devices" },
    ],
  },
];

type Route = "notes" | "devices";

function routeFromHash(): Route {
  return window.location.hash === "#/devices" ? "devices" : "notes";
}

const TITLES: Record<Route, string> = { notes: "Notes", devices: "Devices" };

export function App() {
  const [route, setRoute] = useState<Route>(routeFromHash);
  const [me, setMe] = useState<Identity | null>(null);
  const [connected, setConnected] = useState(false);
  const [locked, setLocked] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Bumped when the live socket says something changed, so pages refetch.
  const [changes, setChanges] = useState<{ tables: string[]; n: number }>({ tables: [], n: 0 });

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (!insideApp()) return;
    const off = onEvent((event) => {
      if (event.type === "liveState") setConnected(event.connected);
      else if (event.type === "session") setLocked(event.state !== "unlocked");
      else if (event.type === "live") {
        const data = event.data as { type?: string; tables?: string[] } | null;
        if (data?.type === "changed" && Array.isArray(data.tables)) setChanges((c) => ({ tables: data.tables!, n: c.n + 1 }));
      }
    });
    loadIdentity().then(setMe, (e: unknown) => setError(String(e)));
    setLive(true).catch((e: unknown) => setError(String(e)));
    return () => {
      off();
      setLive(false).catch(() => {});
    };
  }, []);

  useEffect(() => {
    if (insideApp()) reportPage(`#/${route}`, TITLES[route], 0, NAV).catch(() => {});
  }, [route]);

  if (!insideApp()) {
    return (
      <main className="page">
        <h1>Open this in the Secure App</h1>
        <p>This page only works inside the Mac app. It has no network of its own.</p>
      </main>
    );
  }

  if (locked) {
    return (
      <main className="page">
        <h1>Locked</h1>
        <p>Unlock the app to carry on.</p>
      </main>
    );
  }

  return (
    <div className="shell">
      <header className="bar">
        <nav>
          {NAV[0].items.map((item) => (
            <a key={item.path} href={item.path} aria-current={item.path === `#/${route}` ? "page" : undefined}>
              {item.title}
            </a>
          ))}
        </nav>
        <div className="who">
          <span className={connected ? "live on" : "live off"} role="status">
            {connected ? "Live" : "Offline"}
          </span>
          {me && (
            <span title={me.email}>
              {me.name || me.email} on {me.deviceLabel}
            </span>
          )}
          <button type="button" onClick={() => signOut().catch((e: unknown) => setError(String(e)))}>
            Sign out
          </button>
        </div>
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      <main className="page">
        {route === "notes" ? <NotesPage changes={changes} /> : <DevicesPage thisKeyId={me?.keyId ?? null} />}
      </main>
    </div>
  );
}
