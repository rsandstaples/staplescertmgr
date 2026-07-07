package com.staples.siam.aic.management.samlcertmgr.auth;

import java.time.Instant;

public record SessionRecord(String email, String displayName, String csrfToken, Instant createdAt) {
}