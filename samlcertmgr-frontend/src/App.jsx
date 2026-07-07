import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api.js";

export default function App() {
  const [me, setMe] = useState(null);
  const [environments, setEnvironments] = useState([]);
  const [env, setEnv] = useState("");
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [warnOnly, setWarnOnly] = useState(false);
  const [dialogFor, setDialogFor] = useState(null);

  useEffect(() => {
    api.me().then(setMe).catch(() => {});
    api.environments().then((envs) => {
      setEnvironments(envs);
      if (envs.length) setEnv(envs[0]);
    }).catch((e) => setError(String(e.message || e)));
  }, []);

  const load = (which) => {
    if (!which) return;
    setLoading(true);
    setError("");
    api.entities(which)
      .then(setRows)
      .catch((e) => setError(String(e.message || e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(env); /* eslint-disable-next-line */ }, [env]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return rows.filter((r) => {
      if (warnOnly && !(r.expiringSoon || r.expired)) return false;
      if (!q) return true;
      return [r.entityId, r.signingSubjectCn, r.signingIssuerCn, r.role]
        .filter(Boolean).some((s) => s.toLowerCase().includes(q));
    });
  }, [rows, filter, warnOnly]);

  const warnCount = rows.filter((r) => r.expiringSoon || r.expired).length;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">SAML Certificate Manager</div>
        <div className="spacer" />
        <label className="envpick">
          Environment&nbsp;
          <select value={env} onChange={(e) => setEnv(e.target.value)}>
            {environments.map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        {me && <span className="who">{me.name || me.email}</span>}
        <a className="logout" href="/api/logout">Sign out</a>
      </header>

      <div className="controls">
        <input
          className="search"
          placeholder="Filter by entity ID, subject, issuer, role…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <label className="chk">
          <input type="checkbox" checked={warnOnly} onChange={(e) => setWarnOnly(e.target.checked)} />
          &nbsp;Expiring / expired only
        </label>
        <button className="refresh" onClick={() => load(env)} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
        <div className="counts">
          <span>{rows.length} partnerships</span>
          <span className={warnCount ? "warn" : ""}>{warnCount} need attention</span>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      <table className="grid">
        <thead>
          <tr>
            <th>Entity ID</th>
            <th>Role</th>
            <th>Signing cert subject</th>
            <th>Issuer</th>
            <th>Expires</th>
            <th className="num">Days left</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((r) => (
            <tr key={r.entityId} className={rowClass(r)}>
              <td className="mono" title={r.entityId}>{r.entityId}</td>
              <td>{r.role}</td>
              <td>{r.signingSubjectCn || (r.parseError ? "—" : "(no signing cert)")}</td>
              <td>{r.signingIssuerCn || "—"}</td>
              <td>{r.expires || "—"}</td>
              <td className="num">{r.daysToExpiry == null ? "—" : r.daysToExpiry}</td>
              <td>
                <button className="link" onClick={() => setDialogFor(r)}>Replace cert</button>
              </td>
            </tr>
          ))}
          {!filtered.length && !loading && (
            <tr><td colSpan={7} className="empty">No matching entities.</td></tr>
          )}
        </tbody>
      </table>

      {dialogFor && (
        <ReplaceCertDialog
          env={env}
          entity={dialogFor}
          onClose={() => setDialogFor(null)}
          onDone={() => { setDialogFor(null); load(env); }}
        />
      )}
    </div>
  );
}

function rowClass(r) {
  if (r.expired) return "expired";
  if (r.expiringSoon) return "soon";
  return "";
}

function ReplaceCertDialog({ env, entity, onClose, onDone }) {
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState(null);

  const submit = () => {
    if (!file) { setErr("Choose a certificate file (PEM or DER)."); return; }
    setBusy(true);
    setErr("");
    api.replaceCert(env, entity.entityId, file)
      .then((res) => { setResult(res); if (res.success) setTimeout(onDone, 1200); })
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Replace signing certificate</h3>
        <p className="mono small">{entity.entityId}</p>
        <p className="small muted">
          Current signing cert expires <b>{entity.expires || "—"}</b>
          {entity.signingCertCount > 1 && (
            <> · {entity.signingCertCount} signing certs present — the earliest-expiring one is replaced</>
          )}
        </p>
        <p className="small caution">
          AIC recreates the entity's certificates on update; any manual cert edits in
          AIC for this entity will be overwritten. This targets <b>{env}</b>.
        </p>

        <input type="file" accept=".pem,.cer,.crt,.der,.txt"
               onChange={(e) => setFile(e.target.files[0] || null)} />

        {err && <div className="error">{err}</div>}
        {result && (
          <div className={result.success ? "ok" : "error"}>
            {result.message}
            {result.success && (
              <div className="small">
                New subject: {result.newSubjectCn} · expires {result.newExpires} · txid {result.txid}
              </div>
            )}
          </div>
        )}

        <div className="modal-actions">
          <button onClick={onClose} disabled={busy}>Cancel</button>
          <button className="primary" onClick={submit} disabled={busy || !!result?.success}>
            {busy ? "Updating…" : "Replace & push to AIC"}
          </button>
        </div>
      </div>
    </div>
  );
}
