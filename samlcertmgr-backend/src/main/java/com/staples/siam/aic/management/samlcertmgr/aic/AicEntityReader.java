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
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.staples.siam.aic.management.samlcertmgr.auth.TokenProvider;
import com.staples.siam.aic.management.samlcertmgr.config.AicEnvironmentConfig;

/**
 * Lists every SAML2 remote/hosted entity in a realm, with each entity's
 * actual SAML metadata XML (the document with the signing certs).
 *
 * <p>
 * Two AIC surfaces are in play here, and they turned out to be genuinely
 * different data models, not two views of the same thing:
 * <ul>
 * <li>{@code /realm-config/saml2/{location}/{_id}} (the REST config API) —
 * returns a <em>decomposed, structured</em> representation of the
 * entity's behavior (NameID format, SSO bindings, signing toggles under
 * {@code identityProvider.assertionContent}, etc.) — no metadata XML,
 * no certs, at least not inline. This was the previous approach here;
 * it works, but answers the wrong question for this app.</li>
 * <li>{@code exportmetadata.jsp} (legacy AM SAML2 JSP, not the REST API) —
 * the actual {@code <EntityDescriptor>} document, same surface
 * {@code IdpPushToAIC.entityExists()} already reads from (realm-wide,
 * used there only for a substring check) and the same shape
 * {@code IdpPushToAIC.importEntity()} writes back via
 * {@code standardMetadata}. Scoped to one entity via {@code &entityid=},
 * per standard OpenAM/AM convention — this is the one this class needs.</li>
 * </ul>
 *
 * <p>
 * So: query the REST API for the lean list of entityId/location/roles
 * (cheap, paged), then fetch each entity's real metadata XML from
 * exportmetadata.jsp and fold it into a synthetic JSON node under a
 * {@code "metadata"} key — so {@link com.staples.siam.aic.management.samlcertmgr.saml.SamlMetadataService},
 * which already expects exactly that shape, needs no changes at all.
 */
public class AicEntityReader {

    private static final Logger logger = LoggerFactory.getLogger(AicEntityReader.class);

    private static final int PAGE_SIZE = 100;

    private final AicEnvironmentConfig env;
    private final TokenProvider        auth;
    private final HttpClient           http;
    private final ObjectMapper         mapper;

    /** Logs the very first per-entity metadata fetch's outcome at INFO, to confirm/refute this quickly. */
    private final AtomicBoolean firstFetchLogged = new AtomicBoolean(false);

    public AicEntityReader(AicEnvironmentConfig env, TokenProvider auth, HttpClient http, ObjectMapper mapper) {
        this.env = env;
        this.auth = auth;
        this.http = http;
        this.mapper = mapper;
    }

    /** Returns every entity, each with a "metadata" field containing its real SAML metadata XML. */
    public List<JsonNode> listAll() throws Exception {
        List<JsonNode> summaries = listSummaries();
        List<JsonNode> full      = new ArrayList<>(summaries.size());

        for (JsonNode summary : summaries) {
            String entityId = summary.path("entityId").asText();
            try {
                String     xml          = fetchMetadataXml(entityId);
                ObjectNode withMetadata = summary.deepCopy();
                withMetadata.put("metadata", xml);
                full.add(withMetadata);
            } catch (Exception e) {
                logger.warn("Failed to fetch metadata XML for entity {}: {} — falling back to summary only",
                        entityId, e.getMessage());
                full.add(summary); // row still shows up, just without cert data
            }
        }
        return full;
    }

    /** Lean listing — _id/entityId/location/roles only. */
    private List<JsonNode> listSummaries() throws Exception {
        List<JsonNode> out    = new ArrayList<>();
        String         cookie = null;

        do {
            String url = env.amRealmBaseUrl() + "/realm-config/saml2"
                    + "?_queryFilter=true&_pageSize=" + PAGE_SIZE;
            if (cookie != null) {
                url += "&_pagedResultsCookie=" + URLEncoder.encode(cookie, StandardCharsets.UTF_8);
            }

            HttpResponse<String> resp = getJson(url);
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

        logger.info("Read {} SAML entity summaries from {} realm {}", out.size(), env.getTenantFqdn(), env.getRealm());
        return out;
    }

    /**
     * Fetches one entity's actual SAML metadata XML (the document with the
     * signing certs) from the legacy exportmetadata.jsp endpoint, scoped to
     * this specific entityId.
     */
    private String fetchMetadataXml(String entityId) throws Exception {
        String url = env.getTenantFqdn() + "/am/saml2/jsp/exportmetadata.jsp"
                + "?realm=" + URLEncoder.encode(env.getRealm(), StandardCharsets.UTF_8)
                + "&entityid=" + URLEncoder.encode(entityId, StandardCharsets.UTF_8);

        HttpRequest          req  = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + auth.getToken())
                .header("Accept", "application/xml, text/xml, */*")
                .GET()
                .timeout(Duration.ofSeconds(30))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());

        if (!firstFetchLogged.compareAndSet(false, true)) {
            // only the first entity gets the verbose probe below
        } else if (resp.statusCode() == 200) {
            String body    = resp.body() == null ? "" : resp.body();
            String snippet = body.substring(0, Math.min(body.length(), 300));
            logger.info("First exportmetadata.jsp fetch succeeded — GET {} → HTTP 200, first 300 chars: {}",
                    url, snippet);
            logger.info("Contains X509Certificate: {}", body.contains("X509Certificate"));
        } else {
            logger.warn("First exportmetadata.jsp fetch FAILED — GET {} → HTTP {}: {}",
                    url, resp.statusCode(), resp.body());
        }

        if (resp.statusCode() != 200 || resp.body() == null || resp.body().isBlank()) {
            throw new IllegalStateException(
                    "exportmetadata.jsp returned HTTP " + resp.statusCode() + " (empty or non-200) for " + entityId);
        }
        return resp.body();
    }

    private HttpResponse<String> getJson(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + auth.getToken())
                .header("Accept", "application/json")
                .header("Accept-API-Version", "protocol=2.1,resource=1.0")
                .GET()
                .timeout(Duration.ofSeconds(30))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }
}