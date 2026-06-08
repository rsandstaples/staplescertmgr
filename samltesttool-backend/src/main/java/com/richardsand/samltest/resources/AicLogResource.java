package com.richardsand.samltest.resources;

import com.richardsand.samltest.model.AicLogResult;
import com.richardsand.samltest.services.AicLogService;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/api/aic/logs")
@Produces(MediaType.APPLICATION_JSON)
public class AicLogResource {

    private final AicLogService logService;

    public AicLogResource(AicLogService logService) {
        this.logService = logService;
    }

    @GET
    @Path("/{transactionId}")
    public AicLogResult getByTransactionId(@PathParam("transactionId") String transactionId) {
        return logService.query(transactionId);
    }
}