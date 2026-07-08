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
import com.staples.siam.aic.management.samlcertmgr.auth.TokenProvider;
import com.staples.siam.aic.management.samlcertmgr.config.AicEnvironmentConfig;

/**
 * Lists every SAML2 remote/hosted entity in a realm.
 *
 * <p>
 * AIC's collection query ({@code /realm-config/saml2?_queryFilter=true})
 * only ever returns a lean summary — {@code _id}, {@code entityId},
 * {@code location}, {@code roles} — regardless of {@code _fields}; the actual
 * metadata XML isn't in that response at all. What does work: {@code _id} is
 * {@code base64url(entityId)}, and reading the <em>specific resource</em> by
 * that id ({@code GET /realm-config/saml2/{location}/{_id}}, no query filter)
 * returns the full object, metadata included. So this does the query first
 * for the list of ids, then one GET per entity for the full record.
 *
 * <p>
 * N+1 requests, but this runs once per "Refresh" click on an admin
 * console, not on a hot path — correctness over cleverness here. If it's
 * ever noticeably slow with 250+ partnerships, the per-entity fetches below
 * are the thing to parallelize.
 */
public class AicEntityReader {

    private static final Logger logger = LoggerFactory.getLogger(AicEntityReader.class);

    private static final int PAGE_SIZE = 100;

    private final AicEnvironmentConfig env;
    private final TokenProvider        auth;
    private final HttpClient           http;
    private final ObjectMapper         mapper;

    /** Logs the very first per-entity fetch's outcome at INFO, to confirm/refute the hypothesis quickly. */
    private final AtomicBoolean firstFetchLogged = new AtomicBoolean(false);

    public AicEntityReader(AicEnvironmentConfig env, TokenProvider auth, HttpClient http, ObjectMapper mapper) {
        this.env = env;
        this.auth = auth;
        this.http = http;
        this.mapper = mapper;
    }

    /** Returns every entity's full resource (metadata included) in the realm. */
    public List<JsonNode> listAll() throws Exception {
        List<JsonNode> summaries = listSummaries();
        List<JsonNode> full      = new ArrayList<>(summaries.size());

        for (JsonNode summary : summaries) {
            try {
                full.add(fetchFull(summary));
            } catch (Exception e) {
                logger.warn("Failed to fetch full record for entity {} (_id={}): {} — falling back to summary only",
                        summary.path("entityId").asText(), summary.path("_id").asText(), e.getMessage());
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

            HttpResponse<String> resp = get(url);
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
     * Reads one entity's full resource by _id. {@code location} ("remote" or
     * "hosted", from the summary) selects which sub-collection to read from —
     * this is the part most likely to need adjusting if the hypothesis is wrong.
     */
    private JsonNode fetchFull(JsonNode summary) throws Exception {
        String id       = summary.path("_id").asText();
        String location = summary.path("location").asText("remote");
        String url      = env.amRealmBaseUrl() + "/realm-config/saml2/" + location + "/" + id;

        HttpResponse<String> resp = get(url);

        if (!firstFetchLogged.compareAndSet(false, true)) {
            // subsequent entities: no per-row logging, just let failures accumulate via listAll()'s catch
        } else if (resp.statusCode() == 200) {
            JsonNode probe = mapper.readTree(resp.body());
            logger.info("First per-entity fetch succeeded — GET {} returned fields: {}", url,
                    collectFieldNames(probe));
        } else {
            logger.warn("First per-entity fetch FAILED — GET {} → HTTP {}: {}", url, resp.statusCode(), resp.body());
        }

        if (resp.statusCode() != 200) {
            throw new IllegalStateException("GET " + url + " → HTTP " + resp.statusCode() + " — " + resp.body());
        }
        return mapper.readTree(resp.body());
    }

    private HttpResponse<String> get(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + auth.getToken())
                .header("Accept", "application/json")
                .header("Accept-API-Version", "protocol=2.1,resource=1.0")
                .GET()
                .timeout(Duration.ofSeconds(30))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static List<String> collectFieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}