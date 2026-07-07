package com.staples.siam.aic.management.samlcertmgr.auth;

import java.security.Principal;

import lombok.AllArgsConstructor;
import lombok.Getter;

/** 
 * Resolved from the SESSION cookie by {@link SessionAuthenticator}. 
 */
@AllArgsConstructor
public class AuthUser implements Principal {
    @Getter
    private final String name; // will hold e-mail address as our primary identifier
    @Getter
    private final String displayName;
    @Getter
    private final String csrfToken;
}