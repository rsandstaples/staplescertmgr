# SAML Certificate Console

A web console for managing SAML signing-certificate expiration across your
three AIC instances (UAT / Staging / Prod). Lists every partnership with its
signing cert's subject and expiry (flagged at 60 days), and lets an admin
upload a replacement, splicing it into the entity's metadata and re-importing
to AIC with `updateType=UPDATE_CERTIFICATES`.

Full architecture, auth-flow walkthrough, and Azure setup checklist live in
[`backend/`](backend) — nothing about those changed by going multi-module,
just where the files sit.

## Layout

```
saml-cert-console-parent/    (this dir — parent POM, shared dependencyManagement)
├── frontend/                React SPA (Vite). Builds into its own
│                            target/classes/assets, packaged as a plain jar —
│                            no unpack/assembly step, backend just depends on it.
├── backend/                 Dropwizard app: Entra OIDC login, AIC client,
│                            cert-splice logic. Also holds the poached classes
│                            (see below).
└── distro/                  Packaging only. Bundles backend's shaded jar +
                             config.yml + a start script into a tar.gz.
                             Azure deployment mechanism (App Service vs.
                             container vs. something else) still TBD —
                             this just gets you one clean artifact to hand
                             to whichever path you land on.
```

## Poached from saml-migration

Rather than depending on the whole `saml-migration` project for three classes,
`backend/src/main/java/com/staples/siam/saml/migration/importer/` holds plain
copies of exactly what's needed, kept in their original package so nothing
else had to change:

- **`ImportConfig`** — copied verbatim (self-contained builder).
- **`TokenProvider`** — copied verbatim (one-method interface).
- **`IdpPushToAIC`** — copied and trimmed: the original's second constructor
  (for `InteractiveTokenProvider`, the SSO-cookie/admin-login path used by the
  migration CLI's interactive mode) was dropped, along with the branch in
  `applyAuth` that used it. This console only ever runs as the service
  account — avoiding that MFA-gated interactive login is the whole reason it
  exists — so there was no reason to drag `InteractiveTokenProvider` along
  just to satisfy an unused constructor.

If `saml-migration` changes any of these three in ways that matter here
(e.g. a fix to the AIC grant), that fix needs to be manually ported into the
poached copy — there's no dependency link to catch drift automatically. Worth
a code-comment or a note in `saml-migration`'s own README pointing here, so a
future change to those classes doesn't quietly go stale on this side.

## Build

```bash
mvn -pl frontend,backend,distro -am package
```

Produces `distro/target/saml-cert-console-1.0.0-SNAPSHOT.tar.gz` containing
`saml-cert-console.jar`, `config.yml`, and `start.sh`.

For local dev: `cd backend && java -jar target/saml-cert-console.jar server config.yml`,
and separately `cd frontend && npm run dev` (proxies `/api` to the running backend).# samlcertmgr

For managing SAML certs in AIC