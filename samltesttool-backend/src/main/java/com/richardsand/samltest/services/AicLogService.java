package com.richardsand.samltest.services;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.richardsand.samltest.model.AicLogResult;
import com.richardsand.samltest.model.AicLogResult.AicLogOutcome;

public class AicLogService {

    private final HttpClient   http;
    private final ObjectMapper mapper;
    private final String       tenantBaseUrl;
    private final String       apiKey;
    private final String       apiSecret;

    public AicLogService(
            HttpClient http,
            ObjectMapper mapper,
            String tenantBaseUrl,
            String apiKey,
            String apiSecret) {

        this.http = http;
        this.mapper = mapper;
        this.tenantBaseUrl = stripTrailingSlash(tenantBaseUrl);
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
    }

    public AicLogResult query(String transactionId) {
        if (transactionId == null || transactionId.isBlank()) {
            return AicLogResult.failed(transactionId, "transactionId is blank");
        }

        try {
            String encodedTxid = URLEncoder.encode(transactionId, StandardCharsets.UTF_8);

            String url = tenantBaseUrl
                    + "/monitoring/logs"
                    + "?source=am-everything"
                    + "&transactionId=" + encodedTxid
                    + "&_pageSize=100"
                    + "&_prettyPrint=false";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .header("x-api-key", apiKey)
                    .header("x-api-secret", apiSecret)
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return AicLogResult.failed(
                        transactionId,
                        "AIC log query returned HTTP "
                                + response.statusCode()
                                + ": "
                                + response.body());
            }

            return parse(transactionId, response.body());

        } catch (Exception e) {
            return AicLogResult.failed(transactionId, e.getMessage());
        }
    }

    private AicLogResult parse(String transactionId, String body) throws Exception {
        JsonNode root    = mapper.readTree(body);
        JsonNode results = root.path("result");

        List<JsonNode> entries    = new ArrayList<>();
        List<String>   exceptions = new ArrayList<>();

        for (JsonNode entry : results) {
            JsonNode payload = entry.path("payload");

            String directTxid = payload.path("transactionId").asText("");
            String mdcTxid    = payload.path("mdc").path("transactionId").asText("");
            String entryTxid  = !directTxid.isBlank() ? directTxid : mdcTxid;

            if (!entryTxid.startsWith(transactionId)) {
                continue;
            }

            entries.add(payload);

            String exception = payload.path("exception").asText("").strip();
            if (!exception.isBlank()) {
                exceptions.add(exception);
            }
        }

        AicLogOutcome outcome = classify(entries, exceptions);

        return new AicLogResult(
                transactionId,
                outcome,
                exceptions,
                entries,
                null);
    }

    private AicLogOutcome classify(List<JsonNode> entries, List<String> exceptions) {
        if (entries.isEmpty()) {
            return AicLogOutcome.NO_ENTRIES;
        }

        for (String exception : exceptions) {
            if (exception.contains("entity already exists")) {
                return AicLogOutcome.ALREADY_EXISTS;
            }
        }

        for (String exception : exceptions) {
            if (exception.contains("is not trusted")) {
                return AicLogOutcome.CERT_NOT_TRUSTED;
            }
        }

        for (String exception : exceptions) {
            if (exception.toLowerCase().contains("signature")) {
                return AicLogOutcome.SIGNATURE_ERROR;
            }
        }

        return AicLogOutcome.UNKNOWN;
    }

    private String stripTrailingSlash(String value) {
        return value == null ? null : value.replaceAll("/+$", "");
    }
}