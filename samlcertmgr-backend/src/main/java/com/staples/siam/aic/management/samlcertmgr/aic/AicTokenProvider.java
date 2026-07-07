package com.staples.siam.aic.management.samlcertmgr.aic;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.staples.siam.aic.management.samlcertmgr.auth.TokenProvider;

/**
 * Mints AIC access tokens via the service-account JWT-bearer grant and caches
 * them until shortly before expiry. Implements {@link TokenProvider} so it
 * drops straight into {@code IdpPushToAIC}.
 *
 * <p>Grant details:
 * <ul>
 *   <li>POST to the <em>root-realm</em> {@code /am/oauth2/access_token} endpoint.</li>
 *   <li>{@code client_id} is the literal string {@code service-account}.</li>
 *   <li>The service-account UUID is the JWT {@code iss}/{@code sub}.</li>
 *   <li>{@code kid} is set only when the JWK actually carries one.</li>
 * </ul>
 */
public class AicTokenProvider implements TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(AicTokenProvider.class);

    private final URI          tokenEndpoint;
    private final String       serviceAccountId;
    private final RSAKey       jwk;
    private final String       scope;
    private final HttpClient   http;
    private final ObjectMapper mapper;

    private final Object  lock      = new Object();
    private volatile String  token;
    private volatile Instant expiresAt = Instant.EPOCH;

    public AicTokenProvider(URI tokenEndpoint, String serviceAccountId, RSAKey jwk,
                            String scope, HttpClient http, ObjectMapper mapper) {
        this.tokenEndpoint = tokenEndpoint;
        this.serviceAccountId = serviceAccountId;
        this.jwk = jwk;
        this.scope = scope;
        this.http = http;
        this.mapper = mapper;
    }

    @Override
    public String getToken() throws Exception {
        if (token != null && Instant.now().isBefore(expiresAt.minusSeconds(30))) {
            return token;
        }
        synchronized (lock) {
            if (token != null && Instant.now().isBefore(expiresAt.minusSeconds(30))) {
                return token;
            }
            return mint();
        }
    }

    private String mint() throws Exception {
        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(serviceAccountId)
                .subject(serviceAccountId)
                .audience(tokenEndpoint.toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(180)))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (jwk.getKeyID() != null && !jwk.getKeyID().isBlank()) {
            header.keyID(jwk.getKeyID());
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims);
        jwt.sign(new RSASSASigner(jwk));
        String assertion = jwt.serialize();

        String form = "grant_type=" + enc("urn:ietf:params:oauth:grant-type:jwt-bearer")
                + "&client_id=service-account"
                + "&assertion=" + enc(assertion)
                + "&scope=" + enc(scope);

        HttpRequest req = HttpRequest.newBuilder(tokenEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .timeout(Duration.ofSeconds(30))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException(
                    "AIC token endpoint returned HTTP " + resp.statusCode() + ": " + resp.body());
        }

        JsonNode json = mapper.readTree(resp.body());
        token = json.get("access_token").asText();
        long expiresIn = json.path("expires_in").asLong(300);
        expiresAt = now.plusSeconds(expiresIn);
        logger.debug("Minted AIC token for {} (valid {}s)", serviceAccountId, expiresIn);
        return token;
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
