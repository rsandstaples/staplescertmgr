package com.staples.siam.aic.management.samlcertmgr.aic;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

import com.azure.security.keyvault.secrets.SecretClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;
import com.staples.siam.aic.management.samlcertmgr.ScmConfig;
import com.staples.siam.aic.management.samlcertmgr.auth.TokenProvider;
import com.staples.siam.aic.management.samlcertmgr.config.AicEnvironmentConfig;
import com.staples.siam.aic.management.samlcertmgr.importer.IdpPushToAIC;
import com.staples.siam.aic.management.samlcertmgr.importer.ImportConfig;

/**
 * Central place that turns an environment key (uat / staging / prod) into the
 * objects needed to talk to that AIC instance.
 *
 * <p>
 * The private JWK for each environment is normally pulled from Azure Key
 * Vault via the app's managed identity and never written to disk. Token
 * providers are cached per environment (they in turn cache the bearer
 * token), so the JWK is fetched once per environment per process lifetime.
 *
 * <p>
 * Before Key Vault access exists (e.g. local development, or waiting on a
 * pending Azure resource request), set {@code localSecretsDir} in config —
 * JWKs are then read from {@code <localSecretsDir>/<jwkSecretName>.json}
 * instead, and {@code secretClient} can be null.
 */
public class AicCredentialService {

    private final ScmConfig    config;
    private final SecretClient secretClient;               // may be null when localSecretsDir is set
    private final ObjectMapper mapper = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    private final ConcurrentHashMap<String, TokenProvider> providers = new ConcurrentHashMap<>();

    public AicCredentialService(ScmConfig config, SecretClient secretClient) {
        this.config = config;
        this.secretClient = secretClient;
    }

    public AicEnvironmentConfig environment(String envKey) {
        return config.requireAicEnv(envKey);
    }

    /** Lazily builds (and caches) the token provider for an environment. */
    public TokenProvider tokenProvider(String envKey) {
        String canonical = canonicalKey(envKey);
        return providers.computeIfAbsent(canonical, k -> {
            AicEnvironmentConfig env = config.requireAicEnv(k);
            RSAKey               jwk = loadJwk(env.getJwkSecretName());
            return new AicTokenProvider(URI.create(env.tokenEndpointUrl()),
                    env.getServiceAccountId(), jwk, config.getAicScope(), http, mapper);
        });
    }

    /** A push client (importEntity, entityExists, CoT) for the given environment. */
    public IdpPushToAIC pushClient(String envKey) {
        AicEnvironmentConfig env = config.requireAicEnv(envKey);
        ImportConfig         cfg = ImportConfig.builder()
                .tenantFqdn(env.getTenantFqdn())
                .realm(env.getRealm())
                .serviceAccountId(env.getServiceAccountId())
                .build();
        return new IdpPushToAIC(cfg, tokenProvider(envKey), http, mapper);
    }

    /** A read client that lists all SAML entities for the given environment. */
    public AicEntityReader reader(String envKey) {
        return new AicEntityReader(config.requireAicEnv(envKey), tokenProvider(envKey), http, mapper);
    }

    private RSAKey loadJwk(String secretName) {
        String localDir = config.getLocalSecretsDir();
        if (localDir != null && !localDir.isBlank()) {
            return loadJwkFromLocalFile(localDir, secretName);
        }
        return loadJwkFromKeyVault(secretName);
    }

    private RSAKey loadJwkFromLocalFile(String localDir, String secretName) {
        Path path = Path.of(localDir, secretName + ".json");
        try {
            return RSAKey.parse(Files.readString(path));
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load/parse AIC JWK from local file '" + path
                            + "' (localSecretsDir mode — this is meant for local dev before Key Vault exists)",
                    e);
        }
    }

    private RSAKey loadJwkFromKeyVault(String secretName) {
        if (secretClient == null) {
            throw new IllegalStateException(
                    "No Key Vault client configured and localSecretsDir is unset — cannot load JWK '"
                            + secretName + "'. Set one of the two in config.");
        }
        try {
            String jwkJson = secretClient.getSecret(secretName).getValue();
            return RSAKey.parse(jwkJson);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load/parse AIC JWK from Key Vault secret '" + secretName + "'", e);
        }
    }

    private String canonicalKey(String envKey) {
        return config.getAic().keySet().stream()
                .filter(k -> k.equalsIgnoreCase(envKey))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown AIC environment: " + envKey));
    }
}