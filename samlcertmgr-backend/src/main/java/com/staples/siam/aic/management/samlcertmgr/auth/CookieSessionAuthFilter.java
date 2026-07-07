package com.staples.siam.aic.management.samlcertmgr.auth;

import java.io.IOException;

import io.dropwizard.auth.AuthFilter;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.ext.Provider;

/**
 * Only applied to resource methods with an {@code @Auth AuthUser} parameter —
 * Dropwizard/Jersey's {@code AuthDynamicFeature} only binds this filter where
 * that annotation appears, so the login/callback/logout endpoints (which have
 * no such parameter) are untouched and stay public.
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class CookieSessionAuthFilter extends AuthFilter<String, AuthUser> {
    static final String         SESSION_COOKIE = "SESSION";

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        Cookie cookie    = requestContext.getCookies().get(SESSION_COOKIE);
        String sessionId = cookie != null ? cookie.getValue() : null;

        if (sessionId != null) {
            if (authenticate(requestContext, sessionId, "Session")) {
                return;
            }
        }
        throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }

    public static class Builder extends AuthFilterBuilder<String, AuthUser, CookieSessionAuthFilter> {
        @Override
        protected CookieSessionAuthFilter newInstance() {
            return new CookieSessionAuthFilter();
        }
    }
}