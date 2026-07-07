package com.staples.siam.aic.management.samlcertmgr.auth;

import java.util.Optional;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;

public class SessionAuthenticator implements Authenticator<String, AuthUser> {

    private final SessionStore sessionStore;

    public SessionAuthenticator(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    @Override
    public Optional<AuthUser> authenticate(String sessionId) throws AuthenticationException {
        return sessionStore.lookup(sessionId)
                .map(r -> new AuthUser(r.email(), r.displayName(), r.csrfToken()));
    }
}