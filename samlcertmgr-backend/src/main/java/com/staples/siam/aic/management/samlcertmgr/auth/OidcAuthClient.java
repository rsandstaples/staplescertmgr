package com.staples.siam.aic.management.samlcertmgr.auth;

import java.net.URI;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import com.staples.siam.aic.management.samlcertmgr.config.EntraConfig;

/**
 * Thin wrapper around Nimbus's {@code oauth2-oidc-sdk} for the two legs of
 * the Entra ID authorization-code flow. No tokens or secrets from this class
 * ever reach the browser — only the resulting session cookie does.
 *
 * <p>
 * NOTE: built against oauth2-oidc-sdk {@code 11.20.1}'s API from memory —
 * smoke-test the token exchange and validation calls against whatever version
 * actually resolves; Nimbus's SDK does shift method signatures between minors.
 */
public class OidcAuthClient {

    private final EntraConfig      entra;
    private final IDTokenValidator idTokenValidator;

    public OidcAuthClient(EntraConfig entra) throws Exception {
        this.entra = entra;
        this.idTokenValidator = new IDTokenValidator(
                new Issuer(entra.issuer()),
                new ClientID(entra.getClientId()),
                JWSAlgorithm.RS256,
                entra.jwksEndpoint().toURL());
    }

    /** Builds the URL to redirect the browser to in order to start login. */
    public URI buildAuthorizationRedirect(String state, String nonce) {
        AuthenticationRequest request = new AuthenticationRequest.Builder(
                ResponseType.CODE,
                new Scope("openid", "profile", "email"),
                new ClientID(entra.getClientId()),
                URI.create(entra.getRedirectUri()))
                .endpointURI(entra.authorizationEndpoint())
                .state(new State(state))
                .nonce(new Nonce(nonce))
                .build();
        return request.toURI();
    }

    /**
     * Exchanges the authorization code for tokens, validates the ID token
     * (issuer, audience, signature via Entra's published JWKS, and the nonce
     * we generated on the way out), and returns its claim set.
     */
    public IDTokenClaimsSet exchangeAndValidate(String code, String expectedNonce) throws Exception {
        ClientAuthentication clientAuth = new ClientSecretBasic(
                new ClientID(entra.getClientId()), new Secret(entra.getClientSecret()));

        TokenRequest tokenRequest = new TokenRequest(
                entra.tokenEndpoint(), clientAuth,
                new AuthorizationCodeGrant(new AuthorizationCode(code), URI.create(entra.getRedirectUri())), null);

        HTTPResponse  httpResponse  = tokenRequest.toHTTPRequest().send();
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

        if (!tokenResponse.indicatesSuccess()) {
            throw new IllegalStateException(
                    "Entra token exchange failed: " + tokenResponse.toErrorResponse().getErrorObject());
        }

        OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
        JWT               idToken         = successResponse.getOIDCTokens().getIDToken();

        return idTokenValidator.validate(idToken, new Nonce(expectedNonce));
    }

    /** Group object ids from the claim configured as {@code entra.groupClaimName}. */
    public List<String> groups(IDTokenClaimsSet claims) throws Exception {
        List<String> groups = claims.toJWTClaimsSet().getStringListClaim(entra.getGroupClaimName());
        return groups != null ? groups : List.of();
    }

    public boolean isAuthorized(IDTokenClaimsSet claims) throws Exception {
        return groups(claims).contains(entra.getAuthGroupId());
    }

    public String email(IDTokenClaimsSet claims) throws Exception {
        String preferred = claims.toJWTClaimsSet().getStringClaim("preferred_username");
        return preferred != null ? preferred : claims.getSubject().getValue();
    }

    public String displayName(IDTokenClaimsSet claims) throws Exception {
        String name = claims.toJWTClaimsSet().getStringClaim("name");
        return name != null ? name : email(claims);
    }
}