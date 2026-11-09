import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api } from "../native";

interface Device {
  keyId: string;
  email: string;
  deviceLabel: string;
  environment: string;
  enrolledAt: string;
  lastUsedAt: string | null;
  active: boolean;
  revokedAt: string | null;
  revokedBy: string | null;
  revokedReason: string | null;
}

export function DevicesPage({ thisKeyId }: { thisKeyId: string | null }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [reason, setReason] = useState("");

  const load = useCallback(async () => {
    const res = await api<{ keys: Device[] }>("GET", "/api/devices");
    if (res.ok) setDevices(res.data.keys);
    else setError(`Couldn't load devices (${res.status})`);
  }, []);

  useEffect(() => {
    load().catch((e: unknown) => setError(String(e)));
  }, [load]);

  async function revoke(event: FormEvent, keyId: string) {
    event.preventDefault();
    setError(null);
    try {
      const res = await api<{ error?: string }>("POST", "/api/devices/revoke", { keyId, reason });
      if (!res.ok) {
        setError(res.data?.error ?? `Couldn't revoke (${res.status})`);
        return;
      }
      setRevoking(null);
      setReason("");
      await load();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section>
      <h1>Devices</h1>
      <p>Anyone in the group can revoke any device. A revoked Mac is refused on its next request.</p>
      {error && <p className="error" role="alert">{error}</p>}
      {devices === null ? (
        <p>Loading</p>
      ) : (
        <ul className="list">
          {devices.map((d) => (
            <li key={d.keyId} className={d.active ? "card" : "card revoked"}>
              <div className="row">
                <strong>
                  {d.deviceLabel}
                  {d.keyId === thisKeyId ? " (this Mac)" : ""}
                </strong>
                {d.active && revoking !== d.keyId && (
                  <button type="button" onClick={() => setRevoking(d.keyId)}>
                    Revoke
                  </button>
                )}
              </div>
              <small>
                {d.email}, added {d.enrolledAt} UTC, {d.lastUsedAt ? `last used ${d.lastUsedAt} UTC` : "never used"}
                {d.environment === "development" ? ", development build" : ""}
              </small>
              {!d.active && (
                <small>
                  Revoked {d.revokedAt} UTC by {d.revokedBy}: {d.revokedReason}
                </small>
              )}
              {revoking === d.keyId && (
                <form onSubmit={(e) => revoke(e, d.keyId)} className="row">
                  <input placeholder="Why" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} required />
                  <button type="submit" disabled={reason.trim() === ""}>
                    Revoke this device
                  </button>
                  <button type="button" onClick={() => setRevoking(null)}>
                    Cancel
                  </button>
                </form>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
