package com.staples.siam.aic.management.samlcertmgr.web;

import java.net.URI;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.staples.siam.aic.management.samlcertmgr.auth.AuthUser;
import com.staples.siam.aic.management.samlcertmgr.auth.OidcAuthClient;
import com.staples.siam.aic.management.samlcertmgr.auth.PendingAuthStore;
import com.staples.siam.aic.management.samlcertmgr.auth.SessionStore;

import io.dropwizard.auth.Auth;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * These endpoints have no {@code @Auth} parameter, so
 * {@link com.staples.siam.aic.management.samlcertmgr.auth.CookieSessionAuthFilter}
 * is never applied to them (Jersey's {@code AuthDynamicFeature} only binds
 * resource methods that declare one) — they're public by construction, not by
 * an allow-list someone has to remember to maintain.
 */
@Path("/")
public class AuthResource {

    private static final Logger logger = LoggerFactory.getLogger(AuthResource.class);

    /** 10 hours, matching SessionStore's TTL. */
    private static final int SESSION_COOKIE_MAX_AGE = 10 * 60 * 60;

    private final OidcAuthClient   oidc;
    private final PendingAuthStore pendingAuth;
    private final SessionStore     sessions;
    private final boolean          cookieSecure;
    private final String           postLoginRedirect;

    public AuthResource(OidcAuthClient oidc, PendingAuthStore pendingAuth, SessionStore sessions,
            boolean cookieSecure, String postLoginRedirect) {
        this.oidc = oidc;
        this.pendingAuth = pendingAuth;
        this.sessions = sessions;
        this.cookieSecure = cookieSecure;
        this.postLoginRedirect = postLoginRedirect;
    }

    /** Appends a query suffix (e.g. "?error=login_failed") to the configured post-login target. */
    private URI redirectTarget(String querySuffix) {
        String base = postLoginRedirect.endsWith("/") ? postLoginRedirect : postLoginRedirect + "/";
        return URI.create(querySuffix == null ? base : base + querySuffix);
    }

    @GET
    @Path("/oauth2/authorization/azure")
    public Response authorize() {
        State state = new State();
        Nonce nonce = new Nonce();
        pendingAuth.put(state.getValue(), nonce.getValue());

        URI redirectTo = oidc.buildAuthorizationRedirect(state.getValue(), nonce.getValue());
        return Response.seeOther(redirectTo).build();
    }

    @GET
    @Path("/login/oauth2/code/azure")
    public Response callback(@QueryParam("code") String code,
            @QueryParam("state") String state,
            @QueryParam("error") String error,
            @QueryParam("error_description") String errorDescription) {
        if (error != null) {
            logger.warn("Entra returned an error on callback: {} — {}", error, errorDescription);
            return Response.seeOther(redirectTarget("?error=login_failed")).build();
        }

        String nonce = pendingAuth.consume(state).orElse(null);
        if (nonce == null) {
            logger.warn("Callback with unknown/expired state");
            return Response.seeOther(redirectTarget("?error=login_failed")).build();
        }

        try {
            IDTokenClaimsSet claims = oidc.exchangeAndValidate(code, nonce);

            if (!oidc.isAuthorized(claims)) {
                logger.warn("User {} authenticated but is not in the required access group",
                        oidc.email(claims));
                return Response.seeOther(redirectTarget("?error=forbidden")).build();
            }

            String sessionId = sessions.create(oidc.email(claims), oidc.displayName(claims));
            String csrfToken = sessions.lookup(sessionId).map(r -> r.csrfToken()).orElse("");

            return Response.seeOther(redirectTarget(null))
                    .cookie(CookieUtil.session(sessionId, SESSION_COOKIE_MAX_AGE, cookieSecure))
                    .cookie(CookieUtil.xsrf(csrfToken, SESSION_COOKIE_MAX_AGE, cookieSecure))
                    .build();
        } catch (Exception e) {
            logger.error("Entra token exchange/validation failed", e);
            return Response.seeOther(redirectTarget("?error=login_failed")).build();
        }
    }

    @GET
    @Path("/logout")
    public Response logout(@CookieParam("SESSION") String sessionId) {
        sessions.invalidate(sessionId);
        return Response.seeOther(redirectTarget(null))
                .cookie(CookieUtil.expire("SESSION", true, cookieSecure))
                .cookie(CookieUtil.expire("XSRF-TOKEN", false, cookieSecure))
                .build();
    }

    @GET
    @Path("/me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response me(@Auth AuthUser user) {
        return Response.ok(Map.of("name", user.getDisplayName(), "email", user.getName())).build();
    }
}