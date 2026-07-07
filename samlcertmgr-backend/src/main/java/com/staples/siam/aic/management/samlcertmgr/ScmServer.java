package com.staples.siam.aic.management.samlcertmgr;

import java.util.EnumSet;

import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.staples.siam.aic.management.samlcertmgr.dropwizard.SpaFallbackFilter;

import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.lifecycle.Managed;
import jakarta.servlet.DispatcherType;

public class ScmServer extends Application<ScmConfig> {
    private static final Logger logger = LoggerFactory.getLogger(ScmServer.class);

    @Override
    public void initialize(Bootstrap<ScmConfig> bootstrap) {
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
                logger.info("NovelKMS Version {} Build {}",
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
