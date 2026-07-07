package com.staples.siam.aic.management.samlcertmgr.config;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotEmpty;

/** Mirrors what ImportConfig/IdpPushToAIC already understand — one of these per AIC instance. */
public class AicEnvironmentConfig {

    @NotEmpty
    private String label;
    @NotEmpty
    private String tenantFqdn;
    @NotEmpty
    private String realm;
    @NotEmpty
    private String serviceAccountId;
    @NotEmpty
    private String jwkSecretName;

    @JsonProperty
    public String getLabel() {
        return label;
    }

    @JsonProperty
    public void setLabel(String v) {
        label = v;
    }

    @JsonProperty
    public String getTenantFqdn() {
        return tenantFqdn;
    }

    @JsonProperty
    public void setTenantFqdn(String v) {
        tenantFqdn = v;
    }

    @JsonProperty
    public String getRealm() {
        return realm;
    }

    @JsonProperty
    public void setRealm(String v) {
        realm = v;
    }

    @JsonProperty
    public String getServiceAccountId() {
        return serviceAccountId;
    }

    @JsonProperty
    public void setServiceAccountId(String v) {
        serviceAccountId = v;
    }

    @JsonProperty
    public String getJwkSecretName() {
        return jwkSecretName;
    }

    @JsonProperty
    public void setJwkSecretName(String v) {
        jwkSecretName = v;
    }

    /** Root-realm token endpoint — NOT realm-scoped, per the working AIC integration. */
    public String tokenEndpointUrl() {
        return tenantFqdn + "/am/oauth2/access_token";
    }

    public String amRealmBaseUrl() {
        return tenantFqdn + "/am/json/realms/root/realms/" + realm;
    }
}