package com.staples.siam.aic.management.samlcertmgr;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.staples.siam.aic.management.samlcertmgr.config.AicEnvironmentConfig;
import com.staples.siam.aic.management.samlcertmgr.config.EntraConfig;

import io.dropwizard.core.Configuration;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScmConfig extends Configuration {
    @Valid
    @NotNull
    @JsonProperty("entra")
    private EntraConfig entra;

    /**
     * Key Vault URI to load AIC JWKs from. Optional — only required when
     * {@link #localSecretsDir} is unset. Lets local dev/testing proceed
     * before a Key Vault has actually been provisioned.
     */
    @JsonProperty("keyVaultUri")
    private String keyVaultUri;

    /**
     * When set, AIC JWKs are read from this directory instead of Key Vault —
     * one file per environment, named {@code <jwkSecretName>.json} (matching
     * each AicEnvironmentConfig's jwkSecretName), containing the raw JWK JSON.
     * Meant for local development only, before Key Vault access exists;
     * leave unset (or omit entirely) once Key Vault is available.
     */
    @JsonProperty("localJwkDir")
    private String localJwkDir;

    /** false only for local http://localhost development. */
    @JsonProperty("cookieSecure")
    private boolean cookieSecure = true;

    /** Scope requested on the AIC service-account JWT-bearer grant. */
    @NotEmpty
    @JsonProperty("aicScope")
    private String aicScope = "fr:am:*";

    /** Keyed by short env id used in URLs, e.g. "uat" / "staging" / "prod". */
    @NotEmpty
    @JsonProperty("aic")
    private Map<String, AicEnvironmentConfig> aic = new LinkedHashMap<>();

    /**
     * Where to send the browser after a successful login. Defaults to "/" (the
     * app's own AssetsBundle-served SPA). Override to point at the Vite dev
     * server (e.g. "http://localhost:5173/") when running the frontend
     * separately with `npm run dev` — the SESSION cookie is host-scoped, not
     * port-scoped, so it's still sent once the browser lands there.
     */
    @JsonProperty("postLoginRedirect")
    private String postLoginRedirect = "/";

    /** Case-insensitive lookup with a clear error rather than an NPE deep in a client. */
    public AicEnvironmentConfig requireAicEnv(String key) {
        AicEnvironmentConfig cfg = key == null ? null : aic.get(key.toLowerCase());
        if (cfg == null) {
            throw new jakarta.ws.rs.NotFoundException("Unknown AIC environment: " + key);
        }
        return cfg;
    }
}