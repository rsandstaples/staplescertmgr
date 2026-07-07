package com.staples.siam.aic.management.samlcertmgr.auth;

import java.util.Map;

import io.dropwizard.auth.UnauthorizedHandler;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * The default Dropwizard handler adds a WWW-Authenticate header meant for
 * Basic/Bearer schemes. For a cookie session that header is meaningless (and
 * some browsers mishandle unfamiliar WWW-Authenticate schemes), so this just
 * returns a plain 401 with a JSON body the SPA can key off to redirect to login.
 */
public class JsonUnauthorizedHandler implements UnauthorizedHandler {

    @Override
    public Response buildResponse(String prefix, String realm) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", "unauthorized"))
                .build();
    }
}