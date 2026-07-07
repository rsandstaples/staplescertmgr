package com.staples.siam.aic.management.samlcertmgr.config;

import java.net.URI;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotEmpty;

public class EntraConfig {

    @NotEmpty
    private String tenantId;
    @NotEmpty
    private String clientId;
    @NotEmpty
    private String clientSecret;
    @NotEmpty
    private String redirectUri;
    @NotEmpty
    private String groupClaimName = "groups";
    @NotEmpty
    private String authGroupId;

    @JsonProperty
    public String getTenantId() {
        return tenantId;
    }

    @JsonProperty
    public void setTenantId(String v) {
        tenantId = v;
    }

    @JsonProperty
    public String getClientId() {
        return clientId;
    }

    @JsonProperty
    public void setClientId(String v) {
        clientId = v;
    }

    @JsonProperty
    public String getClientSecret() {
        return clientSecret;
    }

    @JsonProperty
    public void setClientSecret(String v) {
        clientSecret = v;
    }

    @JsonProperty
    public String getRedirectUri() {
        return redirectUri;
    }

    @JsonProperty
    public void setRedirectUri(String v) {
        redirectUri = v;
    }

    @JsonProperty
    public String getGroupClaimName() {
        return groupClaimName;
    }

    @JsonProperty
    public void setGroupClaimName(String v) {
        groupClaimName = v;
    }

    @JsonProperty
    public String getAuthGroupId() {
        return authGroupId;
    }

    @JsonProperty
    public void setAuthGroupId(String v) {
        authGroupId = v;
    }

    // ── Entra v2 endpoints, derived from tenantId ──────────────────────────

    public URI authorizationEndpoint() {
        return URI.create("https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/authorize");
    }

    public URI tokenEndpoint() {
        return URI.create("https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token");
    }

    public URI jwksEndpoint() {
        return URI.create("https://login.microsoftonline.com/" + tenantId + "/discovery/v2.0/keys");
    }

    public String issuer() {
        return "https://login.microsoftonline.com/" + tenantId + "/v2.0";
    }
}