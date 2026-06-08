package com.richardsand.samltest.model;

import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

public record AicLogResult(
        String transactionId,
        AicLogOutcome outcome,
        List<String> exceptions,
        List<JsonNode> entries,
        String errorMessage) {

    public enum AicLogOutcome {
        ALREADY_EXISTS,
        CERT_NOT_TRUSTED,
        SIGNATURE_ERROR,
        UNKNOWN,
        NO_ENTRIES,
        QUERY_FAILED
    }

    public static AicLogResult failed(String transactionId, String message) {
        return new AicLogResult(
                transactionId,
                AicLogOutcome.QUERY_FAILED,
                List.of(),
                List.of(),
                message);
    }
}