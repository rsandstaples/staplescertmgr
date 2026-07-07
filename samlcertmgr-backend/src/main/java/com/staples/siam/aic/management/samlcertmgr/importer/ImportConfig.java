package com.staples.siam.aic.management.samlcertmgr.importer;

import java.nio.file.Path;

import lombok.Builder;
import lombok.Getter;

/**
 * Poached from saml-migration (not depended-on) — copied verbatim since it's
 * self-contained (just a builder + a couple of URL-assembly helpers). Only
 * {@code tenantFqdn}, {@code realm}, and {@code serviceAccountId} are actually
 * populated by this console (via AicCredentialService.pushClient); the rest
 * of the fields exist because the class is a straight copy, not because the
 * console uses them.
 */
@Builder
@Getter
public class ImportConfig {
    public enum ImportScope {
        METADATA("metadata"),
        EXT_CONFIG("extconfig"),
        BOTH("both");

        private final String cliValue;

        ImportScope(String cliValue) {
            this.cliValue = cliValue;
        }

        public String cliValue() {
            return cliValue;
        }

        public boolean includesMetadata() {
            return this == METADATA || this == BOTH;
        }

        public boolean includesExtConfig() {
            return this == EXT_CONFIG || this == BOTH;
        }
    }

    String tenantFqdn;
    String realm;

    /**
     * Service-account ID (UUID) obtained from Tenant Settings → Service Accounts.
     * Used as both __iss__ and sub in the JWT.
     */
    String serviceAccountId;

    Path privateKeyJwkPath;

    /** Directory containing the reconstructed *.xml metadata files. */
    Path metadataDir;

    /** Directory containing output files. */
    Path outputDir;

    /** When true, print what would happen but make no API calls. */
    boolean dryRun;

    /**
     * When true, updates the certs for providers that already exist in AIC.
     * Note: the AIC API deletes + recreates on updateCerts; any manual changes will be lost.
     */
    boolean updateCerts;

    /**
     * Preflight existence check for entity IDs in AIC
     */
    boolean preflight;

    /** Milliseconds to pause between successive API calls (throttle). */
    long delayMs;

    /** Maximum consecutive failures before the run aborts early. 0 = no abort */
    int maxConsecutiveFailures;

    @Builder.Default
    int maxRetries = 2;

    Path reportPath;

    /**
     * Base URL for IDM REST API calls — used for SBA_IDP_CONFIG managed object creation.
     * e.g. https://openam-mycompany-prod.forgerock.io/openidm
     */
    String idmBaseUrl;

    /** Controls whether metadata, extended config, or both are imported. */
    ImportScope importScope;

    /** For AIC log queries */
    String apiKey;
    String apiSecret;

    /**
     * Alternate AIC tenant for cert registration (e.g. the dev environment).
     * When null, cert registration targets the main {@link #tenantFqdn}.
     */
    String certTenantFqdn;

    /**
     * Service-account ID used for cert registration.
     * When null, falls back to {@link #serviceAccountId}.
     */
    String certServiceAccountId;

    /**
     * Path to the JWK private key used for cert registration.
     * When null, falls back to {@link #privateKeyJwkPath}.
     */
    Path certPrivateKeyJwkPath;

    /** Builds the full AM REST base URL for the configured realm. */
    public String amRealmBaseUrl() {
        return tenantFqdn + "/am/json/realms/root/realms/" + realm;
    }

    /** The importEntity action endpoint for remote SAML2 providers. */
    public String importEntityUrl() {
        return amRealmBaseUrl() + "/realm-config/saml2/remote?_action=importEntity";
    }

    /** The token endpoint for the service-account JWT bearer grant. */
    public String tokenEndpointUrl() {
        return tenantFqdn + "/am/oauth2/access_token";
    }

    /** The base URL for IDM managed object operations, with trailing slash normalised. */
    public String idmManagedBaseUrl() {
        if (idmBaseUrl == null)
            return null;
        String base = idmBaseUrl.endsWith("/")
                ? idmBaseUrl.substring(0, idmBaseUrl.length() - 1)
                : idmBaseUrl;
        return base + "/managed";
    }

    // ── Cert-environment helpers ──────────────────────────────────────────────

    /**
     * Returns true when separate cert-registration credentials have been
     * configured. When false, cert registration uses the main account.
     */
    public boolean hasCertEnvironment() {
        return certTenantFqdn != null && certServiceAccountId != null && certPrivateKeyJwkPath != null;
    }

    /**
     * Tenant FQDN to use for cert registration.
     * Falls back to {@link #tenantFqdn} when no cert environment is configured.
     */
    public String effectiveCertTenantFqdn() {
        return certTenantFqdn != null ? certTenantFqdn : tenantFqdn;
    }

    /**
     * Service-account ID to use for cert registration.
     * Falls back to {@link #serviceAccountId} when no cert environment is configured.
     */
    public String effectiveCertServiceAccountId() {
        return certServiceAccountId != null ? certServiceAccountId : serviceAccountId;
    }

    /**
     * Private key path to use for cert registration.
     * Falls back to {@link #privateKeyJwkPath} when no cert environment is configured.
     */
    public Path effectiveCertPrivateKeyJwkPath() {
        return certPrivateKeyJwkPath != null ? certPrivateKeyJwkPath : privateKeyJwkPath;
    }

    /** Token endpoint URL for the cert-registration environment. */
    public String certTokenEndpointUrl() {
        return effectiveCertTenantFqdn() + "/am/oauth2/access_token";
    }
}