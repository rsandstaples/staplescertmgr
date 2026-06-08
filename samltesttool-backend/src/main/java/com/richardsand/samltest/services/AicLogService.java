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
import java.util.concurrent.ThreadLocalRandom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.richardsand.samltest.model.AicLogResult;
import com.richardsand.samltest.model.AicLogResult.AicLogOutcome;

public class AicLogService {

    private static final int      MAX_ATTEMPTS = 5;
    private static final Duration BASE_BACKOFF = Duration.ofMillis(500);
    private static final Duration MAX_BACKOFF  = Duration.ofSeconds(10);

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

            HttpResponse<String> response = sendWithRetry(request);

            if (response.statusCode() != 200) {
                return AicLogResult.failed(
                        transactionId,
                        "AIC log query returned HTTP "
                                + response.statusCode()
                                + " after retry attempts: "
                                + response.body());
            }

            return parse(transactionId, response.body());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return AicLogResult.failed(transactionId, "Interrupted during AIC log query retry backoff");
        } catch (Exception e) {
            return AicLogResult.failed(transactionId, e.getMessage());
        }
    }

    private HttpResponse<String> sendWithRetry(HttpRequest request) throws Exception {
        HttpResponse<String> response = null;

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());

            if (!shouldRetry(response.statusCode())) {
                return response;
            }

            if (attempt == MAX_ATTEMPTS) {
                return response;
            }

            Duration delay = retryDelay(response, attempt);
            Thread.sleep(delay.toMillis());
        }

        return response;
    }

    private boolean shouldRetry(int statusCode) {
        return statusCode == 429
                || statusCode == 500
                || statusCode == 502
                || statusCode == 503
                || statusCode == 504;
    }

    private Duration retryDelay(HttpResponse<String> response, int attempt) {
        return response.headers()
                .firstValue("Retry-After")
                .map(this::parseRetryAfter)
                .orElseGet(() -> exponentialBackoffWithJitter(attempt));
    }

    private Duration parseRetryAfter(String value) {
        try {
            long seconds = Long.parseLong(value.trim());
            return clamp(Duration.ofSeconds(seconds));
        } catch (NumberFormatException e) {
            return BASE_BACKOFF;
        }
    }

    private Duration exponentialBackoffWithJitter(int attempt) {
        long exponentialMillis = BASE_BACKOFF.toMillis() * (1L << (attempt - 1));
        long cappedMillis      = Math.min(exponentialMillis, MAX_BACKOFF.toMillis());

        long jitterMillis = ThreadLocalRandom.current()
                .nextLong(0, Math.max(1, cappedMillis / 2));

        return Duration.ofMillis(cappedMillis + jitterMillis);
    }

    private Duration clamp(Duration duration) {
        if (duration.compareTo(BASE_BACKOFF) < 0) {
            return BASE_BACKOFF;
        }

        if (duration.compareTo(MAX_BACKOFF) > 0) {
            return MAX_BACKOFF;
        }

        return duration;
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
