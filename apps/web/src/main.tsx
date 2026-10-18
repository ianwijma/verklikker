import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import YAML from "yaml";
import { npmSpec } from "../../../packages/contracts/index.js";
import "./style.css";
type Run = {
  id: string;
  state: string;
  capture_health: string;
  created_at: string;
  spec: any;
  reason?: string;
  manifest?: any;
};
const terminal = [
  "completed",
  "failed",
  "cancelled",
  "interrupted",
  "timed_out",
  "limit_reached",
];
const bytes = (n: number) =>
  n > 1024 ** 3
    ? `${(n / 1024 ** 3).toFixed(1)} GiB`
    : n > 1024 ** 2
      ? `${(n / 1024 ** 2).toFixed(1)} MiB`
      : `${Math.round(n / 1024)} KiB`;
const time = (s: string) =>
  new Date(s).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
let csrf = "";
async function api(
  path: string,
  body?: unknown,
  method = body ? "POST" : "GET",
) {
  const response = await fetch(path, {
    method,
    headers: body
      ? { "content-type": "application/json", "x-csrf-token": csrf }
      : { "x-csrf-token": csrf },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? "Request failed");
  return data;
}
function Badge({ value }: { value: string }) {
  return <span className={`badge ${value}`}>{value.replaceAll("_", " ")}</span>;
}
function ProcessTree({ events }: { events: any[] }) {
  const nodes = new Map<
    string,
    { id: string; parent?: string; name: string; pid: unknown }
  >();
  for (const e of events)
    if (e.processId)
      nodes.set(e.processId, {
        id: e.processId,
        parent: e.parentId,
        name: e.data?.processName ?? e.kind,
        pid: e.data?.processId,
      });
  function branch(
    id: string,
    visited: Set<string>,
    depth: number,
  ): React.ReactNode {
    if (visited.has(id) || depth > 32) return null;
    const n = nodes.get(id)!;
    const seen = new Set([...visited, id]);
    return (
      <li key={id}>
        <code>{n.name}</code>{" "}
        <span className="muted">
          PID {String(n.pid ?? "?")} · entity {id}
        </span>
        <ul>
          {[...nodes.values()]
            .filter((c) => c.parent === id && c.id !== id)
            .map((c) => branch(c.id, seen, depth + 1))}
        </ul>
      </li>
    );
  }
  const roots = [...nodes.values()].filter(
    (n) => !n.parent || !nodes.has(n.parent) || n.parent === n.id,
  );
  return (
    <div className="panel details">
      <h3>Observed process tree</h3>
      <p className="muted">
        Built from loaded events. Unknown parents remain roots; load more
        timeline events to expand the tree.
      </p>
      <ul className="process-tree">
        {roots.map((n) => branch(n.id, new Set(), 0))}
      </ul>
      {!nodes.size && (
        <div className="empty">No process events have been indexed yet.</div>
      )}
    </div>
  );
}
function App() {
  const [me, setMe] = useState<any>(undefined),
    [runs, setRuns] = useState<Run[]>([]),
    [selected, setSelected] = useState<Run>(),
    [page, setPage] = useState("runs"),
    [error, setError] = useState(""),
    [creating, setCreating] = useState(false);
  const [spec, setSpec] = useState(YAML.stringify(npmSpec("is-number@7.0.0"))),
    [pkg, setPkg] = useState(""),
    [pending, setPending] = useState(false),
    [events, setEvents] = useState<any[]>([]),
    [files, setFiles] = useState<any[]>([]),
    [tab, setTab] = useState("timeline"),
    [kind, setKind] = useState(""),
    [keys, setKeys] = useState<any[]>([]),
    [newKey, setNewKey] = useState("");
  async function refresh() {
    const data = await api("/v1/me");
    csrf = data.csrf ?? "";
    setMe(data.tenant);
    const list = await api("/v1/runs");
    setRuns(list);
    setSelected((previous) =>
      previous
        ? (list.find((r: Run) => r.id === previous.id) ?? previous)
        : undefined,
    );
  }
  useEffect(() => {
    refresh().catch(() => setMe(null));
    const timer = setInterval(() => {
      refresh().catch(() => setMe(null));
    }, 5000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (page === "keys" && me)
      api("/v1/keys")
        .then(setKeys)
        .catch((e) => setError(e.message));
  }, [page, me?.id]);
  useEffect(() => {
    setEvents([]);
    setFiles([]);
    if (!selected) return;
    let valid = true,
      busy = false,
      after = 0;
    const id = selected.id;
    async function poll() {
      if (busy) return;
      busy = true;
      try {
        const [e, f] = await Promise.all([
          api(
            `/v1/runs/${id}/events?limit=500&after=${after}${kind ? "&kind=" + encodeURIComponent(kind) : ""}`,
          ),
          api(`/v1/runs/${id}/artifacts`),
        ]);
        if (valid) {
          if (e.length) {
            after = e.at(-1).sequence;
            setEvents((old) => [...old, ...e].slice(-5000));
          }
          setFiles(f);
        }
      } catch (e: any) {
        if (valid) setError(e.message);
      } finally {
        busy = false;
      }
    }
    void poll();
    const timer = setInterval(() => {
      void poll();
    }, 5000);
    return () => {
      valid = false;
      clearInterval(timer);
    };
  }, [selected?.id, kind]);
  async function submit() {
    setPending(true);
    setError("");
    try {
      const result = await api("/v1/runs", { spec: YAML.parse(spec) });
      setCreating(false);
      await refresh();
      setSelected(result);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setPending(false);
    }
  }
  async function upload(file: File) {
    if (file.size > 64 * 1024 * 1024) {
      setError("Inputs must be at most 64 MiB");
      return;
    }
    setPending(true);
    try {
      const data = await new Promise<string>((ok, fail) => {
        const reader = new FileReader();
        reader.onload = () => ok(String(reader.result).split(",")[1]);
        reader.onerror = fail;
        reader.readAsDataURL(file);
      });
      const result = await api("/v1/inputs", { name: file.name, data });
      const config = YAML.parse(spec);
      config.inputs = [
        ...(config.inputs ?? []),
        {
          artifactId: result.id,
          path: "/work/" + file.name.replace(/[^a-zA-Z0-9_.-]/g, "_"),
          executable: false,
        },
      ];
      setSpec(YAML.stringify(config));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setPending(false);
    }
  }
  const active = runs.filter((r) => !terminal.includes(r.state)).length;
  return (
    <div className="shell">
      <aside>
        <a className="brand" href="/">
          <span className="brand-icon">◉</span> verklikker
          <span className="version">v1</span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <button
          className={page === "runs" ? "nav active" : "nav"}
          onClick={() => {
            setPage("runs");
            setSelected(undefined);
          }}
        >
          ◎ Investigations <span>{runs.length}</span>
        </button>
        <button
          className={page === "keys" ? "nav active" : "nav"}
          onClick={() => {
            setPage("keys");
            setSelected(undefined);
          }}
        >
          ⌘ API access
        </button>
        <div className="sidebar-bottom">
          <span className="small-dot" /> Evidence capture platform
          <p>Observe. Preserve. Investigate.</p>
          <div className="account">{me?.name ?? "Not signed in"}</div>
          {me && (
            <button
              className="text-button"
              onClick={() =>
                api("/v1/logout", {}).then(() => location.reload())
              }
            >
              Sign out
            </button>
          )}
        </div>
      </aside>
      <main>
        <header>
          <div className="crumb">
            WORKSPACE <span>/</span>{" "}
            {page === "keys" ? "API ACCESS" : "INVESTIGATIONS"}
          </div>
          <span className="workspace-label">
            {me?.name ?? "Your investigation workspace"}
          </span>
        </header>
        {error && (
          <div className="error" role="alert">
            {error}
            <button aria-label="Dismiss error" onClick={() => setError("")}>
              ×
            </button>
          </div>
        )}
        {me === undefined ? (
          <div className="empty">Connecting to your workspace…</div>
        ) : me === null ? (
          <section className="welcome">
            <div className="eyebrow">VISIBILITY STARTS HERE</div>
            <h1>
              See what software
              <br />
              actually does.
            </h1>
            <p>
              Execute untrusted packages in disposable virtual machines.
              <br />
              Keep the processes, file activity, and network evidence.
            </p>
            <a className="primary" href="/auth/login">
              Sign in to your workspace ↗
            </a>
            <div className="welcome-line">
              ISOLATED EXECUTION <span>·</span> RICH EVIDENCE <span>·</span>{" "}
              YOUR INFRASTRUCTURE
            </div>
          </section>
        ) : page === "keys" ? (
          <section>
            <div className="title-row">
              <div>
                <div className="eyebrow">AUTOMATION & INTEGRATIONS</div>
                <h1>API access</h1>
                <p>Connect your CLI and CI jobs to this workspace.</p>
              </div>
              <button
                className="primary"
                onClick={async () => {
                  try {
                    const key = await api("/v1/keys", {
                      name: "CLI / CI",
                      scopes: ["runs:read", "runs:write", "artifacts:read"],
                    });
                    setNewKey(key.token);
                    setKeys(await api("/v1/keys"));
                  } catch (e: any) {
                    setError(e.message);
                  }
                }}
              >
                + Create API key
              </button>
            </div>
            {newKey && (
              <div className="key-box">
                <strong>Copy this key now. It is shown once.</strong>
                <code>{newKey}</code>
                <button onClick={() => navigator.clipboard.writeText(newKey)}>
                  Copy key
                </button>
              </div>
            )}
            <div className="panel">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.id}>
                      <td>{k.name}</td>
                      <td>{time(k.created_at)}</td>
                      <td>{k.revoked_at ? "Revoked" : "Active"}</td>
                      <td>
                        {!k.revoked_at && (
                          <button
                            onClick={() =>
                              api("/v1/keys/" + k.id, undefined, "DELETE")
                                .then(() => api("/v1/keys"))
                                .then(setKeys)
                                .catch((e) => setError(e.message))
                            }
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!keys.length && <div className="empty">No API keys yet.</div>}
            </div>
            <div className="hint">
              <code>
                VERKLIKKER_TOKEN=… npm run cli -- submit investigation.yaml
              </code>
            </div>
          </section>
        ) : selected ? (
          <section>
            <button className="back" onClick={() => setSelected(undefined)}>
              ← All investigations
            </button>
            <div className="title-row">
              <div>
                <div className="eyebrow">RUN {selected.id.slice(0, 8)}</div>
                <h1>{selected.spec.label}</h1>
                <p className="mono">{selected.spec.argv.join(" ")}</p>
              </div>
              {!terminal.includes(selected.state) && (
                <button
                  onClick={() =>
                    api(`/v1/runs/${selected.id}/cancel`, {})
                      .then(refresh)
                      .catch((e) => setError(e.message))
                  }
                >
                  Cancel run
                </button>
              )}
            </div>
            <div className="run-status">
              <div>
                Execution <Badge value={selected.state} />
              </div>
              <div>
                Capture <Badge value={selected.capture_health} />
              </div>
              <div>
                Image <code>{selected.spec.image}</code>
              </div>
            </div>
            {selected.reason && <div className="notice">{selected.reason}</div>}
            <div className="tabs">
              {[
                "timeline",
                "processes",
                "files",
                "network",
                "artifacts",
                "coverage",
              ].map((t) => (
                <button
                  className={tab === t ? "chosen" : ""}
                  key={t}
                  onClick={() => setTab(t)}
                >
                  {t}
                </button>
              ))}
            </div>
            {tab === "processes" ? (
              <ProcessTree events={events} />
            ) : tab === "coverage" ? (
              <div className="panel details">
                <h3>Capture coverage</h3>
                <p>
                  Execution success and evidence completeness are tracked
                  separately.
                </p>
                <ul>
                  {(
                    selected.manifest?.coverage?.gaps ?? [
                      "Coverage is finalized when the run ends.",
                    ]
                  ).map((g: string) => (
                    <li key={g}>{g}</li>
                  ))}
                </ul>
                <p>
                  Dropped events:{" "}
                  {selected.manifest?.coverage?.dropped ?? "Pending"}
                </p>
              </div>
            ) : tab === "artifacts" ? (
              <div className="panel">
                <table>
                  <thead>
                    <tr>
                      <th>Artifact</th>
                      <th>Type</th>
                      <th>Size</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((f) => (
                      <tr key={f.id}>
                        <td className="mono">{f.name}</td>
                        <td>{f.kind}</td>
                        <td>{bytes(Number(f.size))}</td>
                        <td>
                          <button
                            onClick={() =>
                              api(`/v1/artifacts/${f.id}/download`)
                                .then(({ url }) =>
                                  window.open(url, "_blank", "noopener"),
                                )
                                .catch((e) => setError(e.message))
                            }
                          >
                            Download ↓
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!files.length && (
                  <div className="empty">
                    Evidence artifacts will appear as capture progresses.
                  </div>
                )}
              </div>
            ) : (
              <div className="panel">
                <div className="panel-toolbar">
                  <strong>
                    {tab === "timeline"
                      ? "Event timeline"
                      : tab === "processes"
                        ? "Process activity"
                        : tab === "files"
                          ? "File activity"
                          : "Network activity"}
                  </strong>
                  <input
                    aria-label="Filter event name"
                    placeholder="Filter exact event name…"
                    value={kind}
                    onChange={(e) => setKind(e.target.value)}
                  />
                </div>
                <div className="event-list">
                  {events
                    .filter(
                      (e) =>
                        tab === "timeline" ||
                        (tab === "processes"
                          ? /exec|fork|exit|process/.test(e.kind)
                          : tab === "files"
                            ? /file|read|write|open|unlink|rename/.test(e.kind)
                            : /net|dns|http|connect|socket/.test(e.kind)),
                    )
                    .map((e) => (
                      <details className="event" key={e.sequence}>
                        <summary>
                          <span className="event-time">
                            {time(e.receivedAt)}
                          </span>
                          <span className="event-kind">{e.kind}</span>
                          <span className="mono muted">
                            {e.processId ?? e.source}
                          </span>
                          <span>⌄</span>
                        </summary>
                        <pre>{JSON.stringify(e.data, null, 2)}</pre>
                      </details>
                    ))}
                  {!events.length && (
                    <div className="empty">
                      No indexed events are available yet.
                      <p>Capture chunks appear here as they are uploaded.</p>
                    </div>
                  )}
                </div>
                {events.length > 0 && (
                  <button
                    className="load"
                    onClick={() =>
                      api(
                        `/v1/runs/${selected.id}/events?after=${events.at(-1).sequence}&limit=100${kind ? "&kind=" + encodeURIComponent(kind) : ""}`,
                      )
                        .then((next) => setEvents([...events, ...next]))
                        .catch((e) => setError(e.message))
                    }
                  >
                    Load more events
                  </button>
                )}
              </div>
            )}
          </section>
        ) : (
          <section>
            <div className="title-row">
              <div>
                <div className="eyebrow">OBSERVE THE UNEXPECTED</div>
                <h1>Investigations</h1>
                <p>
                  A clear record of what runs, what changes, and what connects.
                </p>
              </div>
              <button className="primary" onClick={() => setCreating(true)}>
                + New investigation
              </button>
            </div>
            <div className="stats">
              <div>
                <span>RUNS IN THIS VIEW</span>
                <strong>{runs.length.toString().padStart(2, "0")}</strong>
                <small>Latest 200 investigations</small>
              </div>
              <div>
                <span>ACTIVE / TENANT CAPACITY</span>
                <strong>
                  {me.active} <em>/ {me.concurrency}</em>
                </strong>
                <small>{active} queued or executing</small>
              </div>
              <div>
                <span>EVIDENCE STORAGE</span>
                <strong>{bytes(Number(me.storage_used))}</strong>
                <small>
                  {bytes(Number(me.storage_reserved))} reserved ·{" "}
                  {bytes(Number(me.storage_limit))} limit
                </small>
              </div>
            </div>
            <div className="panel">
              <div className="panel-toolbar">
                <strong>
                  Run history <span className="count">{runs.length}</span>
                </strong>
                <span className="muted">
                  <span className="small-dot" /> Updates every 5 seconds
                </span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Investigation</th>
                    <th>Execution</th>
                    <th>Capture</th>
                    <th>Started</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <button
                          className="run-link"
                          onClick={() => {
                            setSelected(r);
                            setTab("timeline");
                          }}
                        >
                          {r.spec.label}
                        </button>
                        <div className="table-sub mono">
                          {r.id.slice(0, 8)} · {r.spec.image}
                        </div>
                      </td>
                      <td>
                        <Badge value={r.state} />
                      </td>
                      <td>
                        <Badge value={r.capture_health} />
                      </td>
                      <td>{time(r.created_at)}</td>
                      <td>
                        <button
                          aria-label={`Open ${r.spec.label}`}
                          className="arrow"
                          onClick={() => setSelected(r)}
                        >
                          ↗
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!runs.length && (
                <div className="empty">
                  <div className="empty-icon">◎</div>
                  <h3>Your first investigation starts here.</h3>
                  <p>
                    Choose an image and a command. We’ll preserve the evidence.
                  </p>
                  <button onClick={() => setCreating(true)}>
                    Create an investigation
                  </button>
                </div>
              )}
            </div>
            <p className="footnote">
              Captured behavior is evidence for investigation. It is not a
              package safety verdict.
            </p>
          </section>
        )}
      </main>
      {creating && (
        <div className="modal-backdrop">
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-title"
          >
            <div className="title-row">
              <div>
                <div className="eyebrow">NEW RUN</div>
                <h2 id="create-title">Create an investigation</h2>
              </div>
              <button aria-label="Close" onClick={() => setCreating(false)}>
                ×
              </button>
            </div>
            <label>
              Npm preset
              <div className="input-row">
                <input
                  placeholder="package@version"
                  value={pkg}
                  onChange={(e) => setPkg(e.target.value)}
                />
                <button
                  onClick={() => {
                    try {
                      setSpec(YAML.stringify(npmSpec(pkg)));
                    } catch (e: any) {
                      setError(e.message);
                    }
                  }}
                >
                  Use preset
                </button>
              </div>
            </label>
            <label>
              Run specification <span className="muted">YAML</span>
              <textarea
                value={spec}
                onChange={(e) => setSpec(e.target.value)}
                spellCheck={false}
              />
            </label>
            <label className="file-input">
              Attach an input file{" "}
              <input
                type="file"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void upload(f);
                }}
              />
            </label>
            <div className="modal-footer">
              <span className="muted">
                A fresh virtual machine is created for this run.
              </span>
              <button disabled={pending} className="primary" onClick={submit}>
                {pending ? "Preparing…" : "Start investigation ↗"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
