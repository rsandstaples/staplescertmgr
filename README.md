# SAML Certificate Manager (`samlcertmgr`)

A web console for managing SAML signing-certificate expiration across our
AIC instances (UAT / Staging / Prod). Lists every partnership with its
signing cert's subject, issuer, and expiry (flagged at 60 days / red once
expired), and lets an admin upload a replacement, splicing it into the
entity's metadata and re-importing to AIC with `updateType=UPDATE_CERTIFICATES`.

Status as of 2026-07-08: reads (login, environment listing, cert expiry
table) are working end-to-end against real AIC Prod. **Cert replacement
(the write path) has not been tested yet** — next up, against UAT first.

## Layout

```
samlcertmgr/                    (groupId com.staples.iam.aic.samlcertmgr, parent v0.5-SNAPSHOT)
├── samlcertmgr-frontend/       React SPA (Vite). Builds into target/classes/webapp.
├── samlcertmgr-backend/        Dropwizard app: Entra OIDC login, AIC client, cert-splice logic.
│                               Also holds the poached classes (see below).
└── samlcertmgr-distro/         Packaging only — bundles the backend jar + config.yaml
                                 + the built UI into one tar.gz. Azure deployment
                                 mechanism still being worked out (see "Azure" below).
```

## The single most important thing learned this session: AIC's metadata API

This took three wrong guesses to nail down, so it's worth spelling out
clearly rather than trusting anyone's memory of it in six months.

**AIC exposes (at least) two different, non-overlapping representations of a
SAML entity, and only one of them has the actual metadata document:**

1. **The REST config API** — `/realm-config/saml2?_queryFilter=true` (listing)
   and `/realm-config/saml2/{location}/{_id}` (single entity, where `_id` is
   `base64url(entityId)`). This returns a **decomposed, structured**
   representation of the entity's *behavior* — NameID format, SSO service
   bindings, signing toggles nested under `identityProvider.assertionContent`,
   etc. **There is no metadata XML and no certificate here, at any field
   name, at any `_fields` value.** This was the first two things tried and
   both were dead ends — not a bug, just the wrong resource for this question.

2. **`exportmetadata.jsp`** (a legacy AM SAML2 JSP, not part of the REST API
   at all — different base path, `/am/saml2/jsp/exportmetadata.jsp`, not
   `/am/json/...`). Scoped to one entity via `&entityid=<entityId>&realm=<realm>`.
   **This is where the actual `<EntityDescriptor>` document lives, certs
   included.** It's also the same surface `IdpPushToAIC.entityExists()`
   already read from (realm-wide, no `entityid` param, just a substring
   check) and the same shape `IdpPushToAIC.importEntity()` writes back
   through via `standardMetadata` — so the read and write sides of this app
   were consistent with each other from the start; the REST config API was
   simply never the right place to look for metadata.

**Practical upshot for `AicEntityReader`:** query the REST API only for the
lean list of `entityId`/`location`/`roles` (cheap, paged), then fetch each
entity's real metadata XML from `exportmetadata.jsp?entityid=...` and fold
it into a synthetic JSON node under a `"metadata"` key. `SamlMetadataService`
needed **zero changes** once this was in place — it already expected exactly
that shape, because it was modeled on `SamlEntityViewer`'s assumptions from
day one. The bug was entirely in what `AicEntityReader` was asking AIC for,
not in anything downstream.

**Still open**: this was reverse-engineered by trial and error against real
Prod data, not from documentation — there's an open Ping support case this is
worth feeding back into, both to get an authoritative answer and to confirm
nothing about `exportmetadata.jsp`'s `entityid` scoping behaves differently
for entities this testing didn't happen to hit (e.g. hosted vs. remote, or
entities with multiple signing certs already mid-rollover).

## Auth: Entra ID login

Confidential client (server-side code exchange), **not** an SPA registration
— the React frontend never talks to Entra directly, only the Dropwizard
backend does (`ClientSecretBasic` in `OidcAuthClient`). Steps to stand up a
new App Registration:

1. **App registrations → New registration.** Single-tenant. Redirect URI
   platform type **"Web"** (not "Single-page application" — Entra will
   refuse the client-secret exchange if registered under SPA), URI:
   `http://localhost:8080/api/login/oauth2/code/azure` for local dev
   (`.../api/...` because `server.rootPath: /api/*` puts every backend
   endpoint — API, login, callback, logout — under that prefix).
2. **Certificates & secrets → New client secret.** Copy the value
   immediately; it's never shown again.
3. **Access gating — two options**, both supported by the same config keys
   (`entra.groupClaimName` / `entra.authGroupId` — generic claim-name +
   expected-value check, no code difference between them):
   - **App Role** (self-service, no extra Entra directory role needed): App
     roles → create one → assign yourself via **Enterprise applications**
     (not App registrations — same app, different blade, easy to get lost
     looking for this under the wrong one) → Users and groups. Set
     `groupClaimName: roles`, `authGroupId: <the role's Value>`.
   - **Existing security group**: requires **Token configuration → Add
     groups claim** on the App Registration (group membership does *not*
     appear in the token by default, unlike app roles) — check Security
     groups, ID token column. Set `groupClaimName: groups`,
     `authGroupId: <group's Object ID>`. Simpler if the group already exists,
     but be aware it's not a dedicated gate — anyone added to that group for
     unrelated reasons gets console access too.
   - **Admin consent**: new App Registrations commonly hit a Microsoft
     "Approval required" screen (`User.Read`/`offline_access`, added by
     Azure by default) before *anyone* can log in — one-time, tenant admin
     action, not per-user.
4. **Sanity check**: decode a token at **jwt.ms** and confirm the expected
   claim/value actually shows up before assuming the app config is wrong.

## Config reference (`config.yaml`)

Beyond the obvious `entra`/`aic` blocks, a few knobs worth knowing about:

- **`localSecretsDir`** — when set, AIC JWKs are read from
  `<localSecretsDir>/<jwkSecretName>.json` instead of Key Vault. Meant for
  local dev before Key Vault access exists — e.g. reusing the same JWK file
  the migration CLI already has on disk for UAT. Leave `keyVaultUri` blank
  when using this.
- **`postLoginRedirect`** — where the browser lands after login. Defaults to
  `/` (this app's own bundled SPA). Set to `http://localhost:5173/` for local
  dev when running the frontend separately via `npm run dev` — the SESSION
  cookie is host-scoped, not port-scoped, so it's still sent once the
  browser lands back on the Vite dev server.
- **`aicScope`** — defaults to `fr:am:*`.
- **`cookieSecure`** — `false` only for plain-`http://localhost` dev.

## Local development

**Node/npm on a locked-down Windows laptop**: if `npm run dev` fails with
`SyntaxError: Unexpected token {` pointing at `internal/modules/cjs/loader.js`,
that's an ancient system Node (installed by IT, ahead of anything user-scoped
on `PATH`, can't be removed without admin) getting picked up instead of a
newer user-installed one — Vite 5 needs Node 18+. `npm.cmd`'s shim always
calls the `node.exe` sitting next to it, but `npm run dev` then hands off to
`vite.cmd`, which does its *own* fresh `node` lookup — so fixing `npm`'s
resolution alone isn't enough; `PATH` itself needs the right Node's folder
prepended for the whole process tree. See `dev.bat`/`install.bat` for the
working version of this (`set PATH=<new-node-dir>;%PATH%` before calling
`npm`).

**Cert diagnostics**: `AicEntityReader`/`SamlMetadataService` both carry a
one-shot diagnostic log (`AtomicBoolean`-gated, fires once per app run, not
once per entity) that dumps field names and a snippet of whatever AIC
actually returned, the first time something doesn't parse as expected. Cheap
to leave in; safe to strip out once this feels stable.

**Default environment**: the frontend defaults the environment picker to
**`prod`** (deliberately requested, not an oversight) — worth knowing since
this is a cert-*replacement* tool and Prod being the default means it's one
click away for anyone who doesn't deliberately check the dropdown first.

## Poached from saml-migration

Rather than depending on the whole `saml-migration` project for three
classes, `samlcertmgr-backend/src/main/java/com/staples/siam/aic/management/samlcertmgr/importer/`
holds plain copies of exactly what's needed:

- **`ImportConfig`** — copied verbatim (self-contained builder).
- **`TokenProvider`** — copied verbatim (one-method interface), lives in
  `.../auth/` alongside this app's own session/OIDC auth classes (different
  concern, same package as originally structured).
- **`IdpPushToAIC`** — copied and trimmed: the original's second constructor
  (for `InteractiveTokenProvider`, the SSO-cookie/admin-login path used by
  the migration CLI's interactive mode) was dropped — this console only ever
  runs as the service account.

**No dependency link back to `saml-migration`** — if that project's
`IdpPushToAIC` or the AIC grant logic changes, this copy won't inherit it.
Worth a comment in `saml-migration`'s own `IdpPushToAIC` pointing here.

## Azure

Not yet provisioned. Two requests sent to cloud engineering:

1. **Preferred**: a small shared platform (`rg-siam-tools` resource group,
   one user-assigned managed identity, one shared Key Vault, one App Service
   Plan) sized to host this and future small internal tools without a new
   resource request each time — narrow permissions requested alongside it
   (`Contributor` on just that RG, `Managed Identity Operator` on just the
   one identity — deliberately not `User Access Administrator`, which is
   broader than needed).
2. **Fallback**: dedicated resources for just this app, if the shared
   request is denied.

Confirmed along the way: no Contributor/Owner rights in any of `corp-prod`,
`dotcom-prod`, or `dotcom-nonprod` — App Registration creation works
tenant-wide regardless (a default, not a granted role); security group
creation does not (`Insufficient privileges`).

**Target hosting**: Azure App Service, Linux, Java SE 17 — Dropwizard is an
explicitly supported "embedded server" stack there. Startup command:
`java -jar samlcertmgr.jar server config.yaml`; `WEBSITES_PORT=8080`;
managed identity → Key Vault Secrets User; App settings cover everything
`config.yaml` references via `${VAR}` substitution.

**Outbound IPs**: if AIC's admin/federation endpoints ever turn out to be
IP-allowlisted, `az webapp show --query outboundIpAddresses` gives the fixed
set to hand to whoever manages that on the Ping/AIC side. Not yet confirmed
whether AIC actually restricts by source IP.

## Build

```bash
mvn clean package
```

Produces `samlcertmgr-distro/target/samlcertmgr-dist-0.5-SNAPSHOT.tar.gz`
containing the backend jar, `config.yaml`, the built UI, and a start script.

For local dev: run `ScmServer` directly (e.g. from Eclipse) against
`config.yaml`, and separately `cd samlcertmgr-frontend && dev.bat` (or
`npm run dev` if your Node/npm resolution is already correct) — Vite proxies
`/api` to the running backend on `:8080`.