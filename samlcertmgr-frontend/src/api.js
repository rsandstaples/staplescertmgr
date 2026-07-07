// Thin API layer over the BFF. Auth is a session cookie set by the Dropwizard
// backend after the Entra login, so requests just need credentials + the CSRF
// header on writes. Every backend path lives under /api/* (server.rootPath).

const LOGIN_URL = "/api/oauth2/authorization/azure";

function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function handle(res) {
  if (res.status === 401) {
    // Session missing/expired — bounce through Entra.
    window.location.href = LOGIN_URL;
    throw new Error("redirecting to login");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${text ? " — " + text : ""}`);
  }
  return res.status === 204 ? null : res.json();
}

export async function getJson(path) {
  return handle(await fetch(path, { credentials: "same-origin" }));
}

export async function postForm(path, formData) {
  return handle(
    await fetch(path, {
      method: "POST",
      body: formData,
      credentials: "same-origin",
      headers: { "X-XSRF-TOKEN": csrfToken() },
    })
  );
}

export const api = {
  me: () => getJson("/api/me"),
  environments: () => getJson("/api/environments"),
  entities: (env) => getJson(`/api/${encodeURIComponent(env)}/entities`),
  replaceCert: (env, entityId, file) => {
    const fd = new FormData();
    fd.append("entityId", entityId);
    fd.append("cert", file);
    return postForm(`/api/${encodeURIComponent(env)}/replace-signing-cert`, fd);
  },
};
