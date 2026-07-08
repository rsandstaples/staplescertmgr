package com.staples.siam.aic.management.samlcertmgr.aic;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.staples.siam.aic.management.samlcertmgr.auth.TokenProvider;
import com.staples.siam.aic.management.samlcertmgr.config.AicEnvironmentConfig;

/**
 * Lists every SAML2 remote/hosted entity in a realm via
 * {@code /realm-config/saml2?_queryFilter=true}. Each returned node carries
 * {@code _id}, {@code metadata} (the entity's XML) and {@code entityConfig}.
 */
public class AicEntityReader {

    private static final Logger logger = LoggerFactory.getLogger(AicEntityReader.class);

    private static final int PAGE_SIZE = 100;

    private final AicEnvironmentConfig env;
    private final TokenProvider        auth;
    private final HttpClient           http;
    private final ObjectMapper         mapper;

    public AicEntityReader(AicEnvironmentConfig env, TokenProvider auth, HttpClient http, ObjectMapper mapper) {
        this.env = env;
        this.auth = auth;
        this.http = http;
        this.mapper = mapper;
    }

    /** Returns every entity node in the realm, following paged-results cookies. */
    public List<JsonNode> listAll() throws Exception {
        List<JsonNode> out    = new ArrayList<>();
        String         cookie = null;

        do {
            String url = env.amRealmBaseUrl() + "/realm-config/saml2"
                    + "?_queryFilter=true&_pageSize=" + PAGE_SIZE
                    // AIC's default listing only returns _id/_rev/entityId/location/roles —
                    // metadata (the XML with the actual certs) is a heavier field that's
                    // omitted from listings unless explicitly requested via _fields.
                    + "&_fields=_id,entityId,location,roles,metadata";
            if (cookie != null) {
                url += "&_pagedResultsCookie=" + URLEncoder.encode(cookie, StandardCharsets.UTF_8);
            }

            logger.info("Sending request to {}", url);

            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("Authorization", "Bearer " + auth.getToken())
                    .header("Accept", "application/json")
                    .header("Accept-API-Version", "protocol=2.1,resource=1.0")
                    .GET()
                    .timeout(Duration.ofSeconds(60))
                    .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IllegalStateException(
                        "SAML2 query failed: HTTP " + resp.statusCode() + " — " + resp.body());
            }

            JsonNode body = mapper.readTree(resp.body());
            for (JsonNode entry : body.path("result")) {
                out.add(entry);
            }
            cookie = body.path("pagedResultsCookie").asText(null);
            if (cookie != null && cookie.isBlank()) {
                cookie = null;
            }
        } while (cookie != null);

        logger.info("Read {} SAML entities from {} realm {}", out.size(), env.getTenantFqdn(), env.getRealm());
        return out;
    }
}