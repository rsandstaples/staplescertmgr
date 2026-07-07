package com.staples.siam.aic.management.samlcertmgr.importer;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.staples.siam.aic.management.samlcertmgr.auth.TokenProvider;

import lombok.Getter;

/**
 * Poached from saml-migration (not depended-on) — trimmed to the
 * service-account auth path only. The original also supports an
 * {@code InteractiveTokenProvider} (SSO-cookie/admin-login) constructor for
 * the migration CLI's interactive mode; this console never runs interactively
 * (its whole point is to avoid that MFA-gated login), so that constructor,
 * its field, and the branch in {@link #applyAuth} were dropped rather than
 * dragging the interactive-auth class along for no reason.
 *
 * <p>
 * Everything else — {@link #importEntity}, {@link #entityExists},
 * {@link #addToCircleOfTrust} — is unchanged from the original.
 */
public class IdpPushToAIC {
    private static final Logger   logger             = LoggerFactory.getLogger(IdpPushToAIC.class);
    private static final String   API_VERSION_HEADER = "Accept-API-Version";
    private static final String   API_VERSION_VALUE  = "resource=1.0";
    private static final Duration REQUEST_TIMEOUT    = Duration.ofSeconds(30);

    private final ImportConfig  config;
    private final TokenProvider serviceAccountAuth;
    @Getter
    private final HttpClient    http;
    private final ObjectMapper  mapper;
    @Getter
    private String              txid;

    /** Service-account (Bearer token) auth — the only mode this console uses. */
    public IdpPushToAIC(ImportConfig config, TokenProvider serviceAccountAuth, HttpClient http, ObjectMapper mapper) {
        this.config = config;
        this.serviceAccountAuth = serviceAccountAuth;
        this.http = http;
        this.mapper = mapper;
    }

    public TokenProvider getTokenProvider() {
        return serviceAccountAuth;
    }

    public boolean entityExists(String entityId) throws Exception {
        String      url    = config.getTenantFqdn() + "/am/saml2/jsp/exportmetadata.jsp?realm=" + config.getRealm();
        HttpRequest theget = buildGet(url);
        logger.trace("Req {}", theget);
        logger.trace("Req headers {}", theget.headers());
        HttpResponse<String> response = http.send(theget, HttpResponse.BodyHandlers.ofString());
        logger.debug("GET (exists?) {} → {}", response.statusCode(), url);
        logger.debug("Resp headers {}", response.headers());
        logger.trace("Resp body: " + response.body());

        if (response.statusCode() == 200 && response.body() != null && response.body().contains(entityId)) {
            logger.info("Entity {} EXISTS", entityId);
            return true;
        }
        return false;
    }

    public ImportEntityResponse importEntity(String base64UrlMetadata, boolean updateCerts) throws Exception {
        var node = mapper.createObjectNode().put("standardMetadata", base64UrlMetadata);
        if (updateCerts)
            node.put("updateType", "UPDATE_CERTIFICATES");

        long                 start     = System.currentTimeMillis();
        HttpResponse<String> response  = http.send(
                buildPost(config.importEntityUrl(),
                        mapper.writeValueAsString(node)),
                HttpResponse.BodyHandlers.ofString());
        long                 latencyMs = System.currentTimeMillis() - start;

        logger.debug("POST importEntity → HTTP {} ({}ms)", response.statusCode(), latencyMs);
        logger.trace("  Resp headers {}", response.headers());
        txid = response.headers().firstValue("x-forgerock-transactionid").orElse(null);
        logger.debug("  Response txid: {}", txid);
        return new ImportEntityResponse(response.statusCode(), txid, response.body(), latencyMs, mapper);
    }

    /**
     * Adds an entity to the Circle of Trust via GET-then-PUT.
     *
     * PATCH/?_action=patch returns 403 for service account tokens even with fr:am:*
     * scope. GET + PUT of the full object is within scope and works reliably.
     */
    public boolean addToCircleOfTrust(String entityId, String cotName) throws Exception {
        if (StringUtils.isBlank(cotName))
            return true;

        String member = entityId + "|saml2";
        String cotUrl = config.amRealmBaseUrl() + "/realm-config/federation/circlesoftrust/"
                + URLEncoder.encode(cotName, StandardCharsets.UTF_8).replace("+", "%20");

        // Step 1 — GET current CoT
        HttpResponse<String> getResponse = http.send(buildGet(cotUrl), HttpResponse.BodyHandlers.ofString());
        txid = getResponse.headers().firstValue("x-forgerock-transactionid").orElse(null);
        if (getResponse.statusCode() != 200) {
            logger.warn("CoT GET failed: HTTP {} — {}", getResponse.statusCode(), getResponse.body());
            return false;
        }

        // Step 2 — append entity to trustedProviders if not already present
        ObjectNode cotNode   = (ObjectNode) mapper.readTree(getResponse.body());
        ArrayNode  providers = cotNode.has("trustedProviders")
                ? (ArrayNode) cotNode.get("trustedProviders")
                : cotNode.putArray("trustedProviders");

        boolean alreadyPresent = false;
        for (JsonNode n : providers) {
            if (member.equals(n.asText())) {
                alreadyPresent = true;
                break;
            }
        }
        if (alreadyPresent) {
            logger.debug("Entity '{}' already in CoT '{}'", entityId, cotName);
            return true;
        }
        providers.add(member);

        // Strip read-only fields AIC rejects on PUT
        Set<String>  validFields = java.util.Set.of("description", "idffReaderServiceUrl",
                "idffWriterServiceUrl", "saml2ReaderServiceUrl", "saml2WriterServiceUrl", "status", "trustedProviders");
        List<String> toRemove    = new java.util.ArrayList<>();
        cotNode.fieldNames().forEachRemaining(f -> {
            if (!validFields.contains(f))
                toRemove.add(f);
        });
        toRemove.forEach(cotNode::remove);

        // Step 3 — PUT the updated CoT back
        var putBuilder = HttpRequest.newBuilder().uri(URI.create(cotUrl)).header(API_VERSION_HEADER, API_VERSION_VALUE)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(cotNode))).timeout(REQUEST_TIMEOUT);
        applyAuth(putBuilder);
        HttpResponse<String> putResponse = http.send(putBuilder.build(), HttpResponse.BodyHandlers.ofString());
        txid = putResponse.headers().firstValue("x-forgerock-transactionid").orElse(null);

        int status = putResponse.statusCode();
        logger.debug("PUT CoT '{}' ← '{}' → HTTP {}", cotName, entityId, status);
        if (status == 200 || status == 204)
            return true;
        logger.warn("CoT PUT failed for '{}': HTTP {} — {}", entityId, status, putResponse.body());
        return false;
    }

    // -------------------------------------------------------------------------
    // Request builders
    // -------------------------------------------------------------------------

    private HttpRequest buildGet(String url) throws Exception {
        var b = HttpRequest.newBuilder()
                .uri(URI.create(url)).header(API_VERSION_HEADER, API_VERSION_VALUE)
                .header("Accept", "application/json").GET().timeout(REQUEST_TIMEOUT);
        applyAuth(b);
        return b.build();
    }

    private HttpRequest buildPost(String url, String body) throws Exception {
        var b = HttpRequest.newBuilder().uri(URI.create(url)).header(API_VERSION_HEADER, API_VERSION_VALUE)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(REQUEST_TIMEOUT);
        applyAuth(b);
        return b.build();
    }

    private void applyAuth(HttpRequest.Builder b) throws Exception {
        if (serviceAccountAuth == null) {
            throw new IllegalStateException("No auth provider configured.");
        }
        b.header("Authorization", "Bearer " + serviceAccountAuth.getToken());
    }

    /**
     * Response wrapper
     */
    public static class ImportEntityResponse {
        public final int          httpStatus;
        public String             txid;
        public final String       rawBody;
        public final long         latencyMs;
        public final List<String> importedEntities;

        public ImportEntityResponse(int httpStatus, String txid, String rawBody, long latencyMs, ObjectMapper mapper) {
            this.httpStatus = httpStatus;
            this.rawBody = rawBody;
            this.latencyMs = latencyMs;
            List<String> parsed = List.of();
            try {
                JsonNode json = mapper.readTree(rawBody);
                if (json.has("importedEntities"))
                    parsed = mapper.readerForListOf(String.class).readValue(json.get("importedEntities"));
            } catch (Exception ignored) {
            }
            this.importedEntities = parsed;
            this.txid = txid;
        }

        public boolean isSuccess() {
            return httpStatus == 200 || httpStatus == 201;
        }

        public String firstImportedEntity() {
            return importedEntities.isEmpty() ? null : importedEntities.get(0);
        }
    }
}