package com.staples.siam.aic.management.samlcertmgr.auth;

/**
 * Poached from saml-migration (not depended-on) — this console only ever
 * needs the service-account path, so only this interface came along.
 * {@code InteractiveTokenProvider} (the SSO-cookie/admin-login path) was
 * deliberately left behind; see IdpPushToAIC in this package for the
 * corresponding trim.
 */
public interface TokenProvider {
    String getToken() throws Exception;
}