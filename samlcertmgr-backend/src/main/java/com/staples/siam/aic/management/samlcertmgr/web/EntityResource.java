package com.staples.siam.aic.management.samlcertmgr.web;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.glassfish.jersey.media.multipart.FormDataParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.staples.siam.aic.management.samlcertmgr.ScmConfig;
import com.staples.siam.aic.management.samlcertmgr.aic.AicCredentialService;
import com.staples.siam.aic.management.samlcertmgr.auth.AuthUser;
import com.staples.siam.aic.management.samlcertmgr.importer.IdpPushToAIC.ImportEntityResponse;
import com.staples.siam.aic.management.samlcertmgr.saml.SamlMetadataService;
import com.staples.siam.aic.management.samlcertmgr.saml.SamlMetadataService.NormalizedCert;

import io.dropwizard.auth.Auth;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class EntityResource {

    private static final Logger logger = LoggerFactory.getLogger(EntityResource.class);

    private final ScmConfig            config;
    private final AicCredentialService aic;
    private final SamlMetadataService  saml;

    public EntityResource(ScmConfig config, AicCredentialService aic, SamlMetadataService saml) {
        this.config = config;
        this.aic = aic;
        this.saml = saml;
    }

    /** Dropdown contents: the configured environment keys, in order. */
    @GET
    @Path("/environments")
    public Response environments(@Auth AuthUser user) {
        return Response.ok(List.copyOf(config.getAic().keySet())).build();
    }

    /** All partnerships for one environment, with signing-cert expiry data. */
    @GET
    @Path("/{env}/entities")
    public Response entities(@Auth AuthUser user, @PathParam("env") String env) {
        try {
            List<JsonNode> entries = aic.reader(env).listAll();
            return Response.ok(saml.summarize(entries)).build();
        } catch (IllegalArgumentException e) {
            throw notFound(e.getMessage());
        } catch (Exception e) {
            logger.error("Failed to list entities for {}", env, e);
            throw badGateway("Failed to read AIC entities: " + e.getMessage());
        }
    }

    /**
     * Replaces an entity's signing certificate and pushes the updated metadata to
     * AIC with {@code updateType=UPDATE_CERTIFICATES}.
     *
     * <p>entityId is sent as a form field (not a path segment) because SAML
     * entity IDs are URIs and would otherwise need heavy encoding.
     */
    @POST
    @Path("/{env}/replace-signing-cert")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response replaceSigningCert(@Auth AuthUser user,
                                        @PathParam("env") String env,
                                        @HeaderParam("X-XSRF-TOKEN") String csrf,
                                        @FormDataParam("entityId") String entityId,
                                        @FormDataParam("cert") InputStream certStream) {
        if (!user.getCsrfToken().equals(csrf)) {
            throw new WebApplicationException(Response.status(403)
                    .entity(new ReplaceResult(false, 403, null, null, null, null, 0, "CSRF token mismatch"))
                    .build());
        }

        // 1. Validate + normalize the uploaded cert.
        NormalizedCert newCert;
        try {
            String raw = new String(certStream.readAllBytes(), StandardCharsets.UTF_8);
            newCert = saml.normalizeCert(raw);
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            throw badRequest(e.getMessage());
        }

        try {
            // 2. Fetch the entity's current metadata.
            List<JsonNode> entries = aic.reader(env).listAll();
            String metadataXml = saml.rawMetadataFor(entries, entityId)
                    .orElseThrow(() -> notFound("Entity not found in " + env + ": " + entityId));

            int priorSigningCount = saml.signingCertCount(metadataXml);

            // 3. Splice the new cert into the metadata.
            String updatedXml = saml.replaceSigningCert(metadataXml, newCert.base64Der());
            String base64Url  = saml.toBase64Url(updatedXml);

            // 4. Re-import with updateCerts=true (entity is known to exist).
            ImportEntityResponse resp = aic.pushClient(env).importEntity(base64Url, true);

            logger.info("Replace signing cert for {} in {} → HTTP {} txid={}",
                    entityId, env, resp.httpStatus, resp.txid);

            ReplaceResult result = new ReplaceResult(
                    resp.isSuccess(),
                    resp.httpStatus,
                    resp.txid,
                    newCert.subjectCn(),
                    newCert.issuerCn(),
                    newCert.notAfter(),
                    priorSigningCount,
                    resp.isSuccess()
                            ? "Signing certificate replaced"
                            : "AIC rejected the update: " + resp.rawBody);
            return Response.ok(result).build();
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Replace signing cert failed for {} in {}", entityId, env, e);
            throw badGateway("Cert replacement failed: " + e.getMessage());
        }
    }

    private static WebApplicationException notFound(String message) {
        return new WebApplicationException(Response.status(404).entity(new ErrorBody(message)).build());
    }

    private static WebApplicationException badRequest(String message) {
        return new WebApplicationException(Response.status(400).entity(new ErrorBody(message)).build());
    }

    private static WebApplicationException badGateway(String message) {
        return new WebApplicationException(Response.status(502).entity(new ErrorBody(message)).build());
    }

    public record ErrorBody(String message) {
    }

    public record ReplaceResult(
            boolean success,
            int     httpStatus,
            String  txid,
            String  newSubjectCn,
            String  newIssuerCn,
            String  newExpires,
            int     priorSigningCertCount,
            String  message) {
    }
}
