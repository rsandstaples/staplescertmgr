package com.staples.siam.aic.management.samlcertmgr.web;

import jakarta.ws.rs.core.NewCookie;

/** Uses NewCookie.Builder#sameSite(...) — needs Jakarta REST 3.1+, which Dropwizard 5.0.2 provides. */
public final class CookieUtil {

    private CookieUtil() {
    }

    public static NewCookie session(String value, int maxAgeSeconds, boolean secure) {
        return build("SESSION", value, maxAgeSeconds, true, secure);
    }

    public static NewCookie xsrf(String value, int maxAgeSeconds, boolean secure) {
        // Must be readable by JS so the SPA can echo it back as X-XSRF-TOKEN.
        return build("XSRF-TOKEN", value, maxAgeSeconds, false, secure);
    }

    public static NewCookie expire(String name, boolean httpOnly, boolean secure) {
        return build(name, "", 0, httpOnly, secure);
    }

    private static NewCookie build(String name, String value, int maxAgeSeconds, boolean httpOnly, boolean secure) {
        return new NewCookie.Builder(name)
                .value(value)
                .path("/")
                .maxAge(maxAgeSeconds)
                .httpOnly(httpOnly)
                .secure(secure)
                .sameSite(NewCookie.SameSite.LAX)
                .build();
    }
}