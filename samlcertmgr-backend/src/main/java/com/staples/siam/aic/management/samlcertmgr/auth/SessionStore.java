package com.staples.siam.aic.management.samlcertmgr.auth;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Server-side session store. The browser only ever holds an opaque, random
 * session id (the SESSION cookie); everything about who the user is lives
 * here, in-process.
 *
 * <p>
 * In-memory is fine for a single instance. If this app is ever scaled out
 * to multiple nodes behind a load balancer, swap this for a shared store
 * (Redis, or a sticky-session LB rule) — the {@link SessionAuthenticator}
 * interface doesn't change either way.
 */
public class SessionStore {

    private static final Duration     SESSION_TTL = Duration.ofHours(10);
    private static final SecureRandom RNG         = new SecureRandom();

    private final Cache<String, SessionRecord> sessions = Caffeine.newBuilder()
            .expireAfterWrite(SESSION_TTL)
            .maximumSize(5_000)
            .build();

    /** Creates a session and returns the opaque id to set as the SESSION cookie value. */
    public String create(String email, String displayName) {
        String sessionId = randomToken();
        String csrfToken = randomToken();
        sessions.put(sessionId, new SessionRecord(email, displayName, csrfToken, Instant.now()));
        return sessionId;
    }

    public Optional<SessionRecord> lookup(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.getIfPresent(sessionId));
    }

    public void invalidate(String sessionId) {
        if (sessionId != null) {
            sessions.invalidate(sessionId);
        }
    }

    static String randomToken() {
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}