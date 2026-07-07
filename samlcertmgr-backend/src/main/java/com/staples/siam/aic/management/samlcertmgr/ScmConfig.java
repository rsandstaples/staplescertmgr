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

public class ScmConfig extends Configuration {
    @Valid
    @NotNull
    @JsonProperty("entra")
    private EntraConfig entra;

    @NotEmpty
    @JsonProperty("keyVaultUri")
    private String keyVaultUri;

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

    public EntraConfig getEntra() {
        return entra;
    }

    public void setEntra(EntraConfig entra) {
        this.entra = entra;
    }

    public String getKeyVaultUri() {
        return keyVaultUri;
    }

    public void setKeyVaultUri(String keyVaultUri) {
        this.keyVaultUri = keyVaultUri;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    public String getAicScope() {
        return aicScope;
    }

    public void setAicScope(String aicScope) {
        this.aicScope = aicScope;
    }

    public Map<String, AicEnvironmentConfig> getAic() {
        return aic;
    }

    public void setAic(Map<String, AicEnvironmentConfig> aic) {
        this.aic = aic;
    }

    /** Case-insensitive lookup with a clear error rather than an NPE deep in a client. */
    public AicEnvironmentConfig requireAicEnv(String key) {
        AicEnvironmentConfig cfg = key == null ? null : aic.get(key.toLowerCase());
        if (cfg == null) {
            throw new jakarta.ws.rs.NotFoundException("Unknown AIC environment: " + key);
        }
        return cfg;
    }
}
