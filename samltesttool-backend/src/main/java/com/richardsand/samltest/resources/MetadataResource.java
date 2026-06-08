package com.richardsand.samltest.resources;
import com.richardsand.samltest.services.MetadataService;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/saml")
public class MetadataResource {
        private final MetadataService metadataService;

        public MetadataResource(MetadataService metadataService) {
            this.metadataService = metadataService;
        }

        @GET
        @Path("/metadata")
        @Produces(MediaType.APPLICATION_XML)
        public Response metadata() {
            String xml = metadataService.generateIdpMetadata(
                    "http://localhost:8080/saml/idp",
                    "http://localhost:8080/saml/sso",
                    loadCertificatePem()
            );

            return Response.ok(xml)
                    .header("Content-Disposition", "inline; filename=\"idp-metadata.xml\"")
                    .build();
        }

        private String loadCertificatePem() {
            // temporary placeholder
            return """
                    -----BEGIN CERTIFICATE-----
                    MIID...
                    -----END CERTIFICATE-----
                    """;
        }
    }
