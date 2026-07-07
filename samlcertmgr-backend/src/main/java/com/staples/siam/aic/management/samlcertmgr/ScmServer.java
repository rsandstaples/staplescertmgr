package com.staples.siam.aic.management.samlcertmgr;

import java.util.EnumSet;

import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.azure.security.keyvault.secrets.SecretClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.staples.siam.aic.management.samlcertmgr.aic.AicCredentialService;
import com.staples.siam.aic.management.samlcertmgr.auth.AuthUser;
import com.staples.siam.aic.management.samlcertmgr.auth.CookieSessionAuthFilter;
import com.staples.siam.aic.management.samlcertmgr.auth.JsonUnauthorizedHandler;
import com.staples.siam.aic.management.samlcertmgr.auth.OidcAuthClient;
import com.staples.siam.aic.management.samlcertmgr.auth.PendingAuthStore;
import com.staples.siam.aic.management.samlcertmgr.auth.SessionAuthenticator;
import com.staples.siam.aic.management.samlcertmgr.auth.SessionStore;
import com.staples.siam.aic.management.samlcertmgr.config.AzureClients;
import com.staples.siam.aic.management.samlcertmgr.dropwizard.SpaFallbackFilter;
import com.staples.siam.aic.management.samlcertmgr.saml.SamlMetadataService;
import com.staples.siam.aic.management.samlcertmgr.web.AuthResource;
import com.staples.siam.aic.management.samlcertmgr.web.EntityResource;

import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.PermitAllAuthorizer;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.forms.MultiPartBundle;
import io.dropwizard.lifecycle.Managed;
import jakarta.servlet.DispatcherType;

public class ScmServer extends Application<ScmConfig> {
    private static final Logger logger = LoggerFactory.getLogger(ScmServer.class);

    @Override
    public void initialize(Bootstrap<ScmConfig> bootstrap) {
        // Registers the MultiPartFeature needed for @FormDataParam on the cert upload.
        bootstrap.addBundle(new MultiPartBundle());

        bootstrap.addBundle(
                new AssetsBundle(
                        "/webapp",
                        "/",
                        "index.html"));
    }

    @Override
    public void run(ScmConfig config, Environment env) throws Exception {

        // Object Mapper
        ObjectMapper mapper = env.getObjectMapper();
        mapper.findAndRegisterModules();
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        // Manage lifecycle
        env.lifecycle().manage(new Managed() {
            @Override
            public void start() {
            }

            @Override
            public void stop() throws Exception {
                // oauthService.close();
            }
        });

        // OOTB resources
        env.jersey().register(RolesAllowedDynamicFeature.class);

        // Custom resources
        // SPA fallback
        env.servlets()
                .addFilter("spa-fallback", new SpaFallbackFilter())
                .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, "/*");

        // ── AIC integration ────────────────────────────────────────────────
        // secretClient stays null when running against localSecretsDir (local
        // dev, before Key Vault access exists) — AicCredentialService handles
        // that case itself.
        String keyVaultUri = config.getKeyVaultUri();
        SecretClient secretClient = (keyVaultUri != null && !keyVaultUri.isBlank())
                ? AzureClients.secretClient(keyVaultUri)
                : null;
        AicCredentialService aicCredentialService = new AicCredentialService(config, secretClient);
        SamlMetadataService samlMetadataService = new SamlMetadataService();

        // ── Auth: Entra OIDC login + cookie session ────────────────────────
        OidcAuthClient oidcAuthClient = new OidcAuthClient(config.getEntra());
        SessionStore sessionStore = new SessionStore();
        PendingAuthStore pendingAuthStore = new PendingAuthStore();

        env.jersey().register(new AuthDynamicFeature(
                new CookieSessionAuthFilter.Builder()
                        .setAuthenticator(new SessionAuthenticator(sessionStore))
                        .setAuthorizer(new PermitAllAuthorizer<>())
                        .setUnauthorizedHandler(new JsonUnauthorizedHandler())
                        .setPrefix("Session")
                        .buildAuthFilter()));
        env.jersey().register(new AuthValueFactoryProvider.Binder<>(AuthUser.class));

        env.jersey().register(new AuthResource(
                oidcAuthClient, pendingAuthStore, sessionStore, config.isCookieSecure()));
        env.jersey().register(new EntityResource(config, aicCredentialService, samlMetadataService));

        // Jersey Registrations
        env.jersey().register(new AbstractBinder() {
            @Override
            protected void configure() {
                // bind(adminBillingService).to(AdminBillingService.class);
            }
        });

        logBuildInfo();
    }

    private void logBuildInfo() {
        try (var in = getClass().getClassLoader().getResourceAsStream("build.properties")) {
            if (in != null) {
                var props = new java.util.Properties();
                props.load(in);
                logger.info("SAML Cert Manager Version {} Build {}",
                        props.getProperty("app.version", "unknown"),
                        props.getProperty("build.number", "unknown"));
            }
        } catch (Exception e) {
            logger.warn("Could not read build.properties", e);
        }
    }

    public static void main(String[] args) throws Exception {
        new ScmServer().run(args);
    }
}