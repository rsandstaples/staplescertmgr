package com.staples.siam.aic.management.samlcertmgr.auth;

import java.time.Duration;
import java.util.Optional;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Bridges the two legs of the OIDC authorization-code flow: the {@code state}
 * value handed to Entra on the way out is looked up here on the way back to
 * recover the {@code nonce} we're expecting in the ID token. A 5-minute TTL
 * comfortably covers a login prompt without leaving stale entries around.
 */
public class PendingAuthStore {

    private final Cache<String, String> pending = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(5))
            .maximumSize(1_000)
            .build();

    public void put(String state, String nonce) {
        pending.put(state, nonce);
    }

    /** Looks up and removes in one step — a state value is single-use. */
    public Optional<String> consume(String state) {
        if (state == null) {
            return Optional.empty();
        }
        String nonce = pending.getIfPresent(state);
        pending.invalidate(state);
        return Optional.ofNullable(nonce);
    }
}