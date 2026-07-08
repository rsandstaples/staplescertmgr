package com.staples.siam.aic.management.samlcertmgr.saml;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Everything that touches SAML metadata XML: turning AIC's entity dump into
 * summary rows, and swapping a new signing certificate into an entity's
 * metadata prior to re-import. Namespace-agnostic (matches by local name).
 */
public class SamlMetadataService {

    private static final Logger logger = LoggerFactory.getLogger(SamlMetadataService.class);

    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private static final Pattern           CN  = Pattern.compile("CN=([^,]+)");

    /** Expiry window that triggers the "attention" highlight. */
    public static final long WARN_DAYS = 60;

    // ------------------------------------------------------------------ DTOs

    /** One row in the console table. */
    public record EntitySummary(
            String entityId,
            String role, // IDP / SP / UNKNOWN
            String signingSubjectCn,
            String signingIssuerCn,
            String signingSerial,
            String expires, // yyyy-MM-dd of the latest signing cert
            Long daysToExpiry, // null when there is no signing cert
            boolean expired,
            boolean expiringSoon, // within WARN_DAYS and not yet expired
            int signingCertCount,
            String parseError) {
    }

    /** A validated, normalized replacement certificate. */
    public record NormalizedCert(
            String base64Der, // clean single-blob base64 for embedding in metadata
            String subjectCn,
            String issuerCn,
            String serial,
            String notAfter,
            boolean expired) {
    }

    // --------------------------------------------------------------- summaries

    public List<EntitySummary> summarize(List<JsonNode> entries) {
        List<EntitySummary> rows = new ArrayList<>(entries.size());
        for (JsonNode entry : entries) {
            rows.add(summarizeOne(entry));
        }
        // Expiring first: soonest daysToExpiry at the top, nulls last.
        rows.sort((a, b) -> {
            Long da = a.daysToExpiry(), db = b.daysToExpiry();
            if (da == null && db == null)
                return 0;
            if (da == null)
                return 1;
            if (db == null)
                return -1;
            return Long.compare(da, db);
        });
        return rows;
    }

    /** Ensures the one-time diagnostic dump below fires once per run, not once per entity. */
    private final java.util.concurrent.atomic.AtomicBoolean diagnosticsLogged = new java.util.concurrent.atomic.AtomicBoolean(false);

    private EntitySummary summarizeOne(JsonNode entry) {
        String rawMetadata = entry.hasNonNull("metadata") ? entry.get("metadata").asText() : null;
        String fallbackId  = entry.path("_id").asText(null);

        if (rawMetadata == null || rawMetadata.isBlank()) {
            logDiagnosticsOnce(entry, "no 'metadata' field found on entity JSON");
            return new EntitySummary(fallbackId, "UNKNOWN", null, null, null,
                    null, null, false, false, 0, "no metadata");
        }

        try {
            Document doc      = parse(rawMetadata);
            Element  desc     = doc.getDocumentElement();
            String   entityId = attr(desc, "entityID");
            if (entityId == null)
                entityId = fallbackId;

            boolean idp  = !elementsByLocalName(desc, "IDPSSODescriptor").isEmpty();
            boolean sp   = !elementsByLocalName(desc, "SPSSODescriptor").isEmpty();
            String  role = idp ? "IDP" : (sp ? "SP" : "UNKNOWN");

            List<X509Certificate> signing = decodeSigningCerts(desc);
            if (signing.isEmpty()) {
                return new EntitySummary(entityId, role, null, null, null,
                        null, null, false, false, 0, null);
            }

            // "Latest signing cert" = most recently issued (max notBefore).
            X509Certificate latest = signing.stream()
                    .max((x, y) -> x.getNotBefore().compareTo(y.getNotBefore()))
                    .orElse(signing.get(0));

            Instant notAfter     = latest.getNotAfter().toInstant();
            long    days         = ChronoUnit.DAYS.between(Instant.now(), notAfter);
            boolean expired      = notAfter.isBefore(Instant.now());
            boolean expiringSoon = !expired && days <= WARN_DAYS;

            return new EntitySummary(
                    entityId, role,
                    cn(latest.getSubjectX500Principal().getName()),
                    cn(latest.getIssuerX500Principal().getName()),
                    latest.getSerialNumber().toString(16).toUpperCase(),
                    DAY.format(notAfter), days, expired, expiringSoon,
                    signing.size(), null);
        } catch (Exception ex) {
            logger.warn("Failed to summarize entity {}: {}", fallbackId, ex.getMessage());
            logDiagnosticsOnce(entry, "metadata present but failed to parse as XML: "
                    + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            return new EntitySummary(fallbackId, "UNKNOWN", null, null, null,
                    null, null, false, false, 0, ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }

    /**
     * Fires once per SamlMetadataService instance (i.e. once per app run, since
     * one instance is built at startup) rather than once per entity, to avoid
     * spamming 100+ near-identical log lines when every entity fails the same
     * way. Dumps the entity JSON's field names and a snippet of whatever
     * "metadata" actually contains, to diagnose a shape mismatch against what
     * this class assumes (raw XML text).
     */
    private void logDiagnosticsOnce(JsonNode entry, String reason) {
        if (!diagnosticsLogged.compareAndSet(false, true)) {
            return;
        }
        java.util.List<String> fieldNames = new java.util.ArrayList<>();
        entry.fieldNames().forEachRemaining(fieldNames::add);

        String metadataSnippet = "(absent)";
        if (entry.hasNonNull("metadata")) {
            String raw = entry.get("metadata").asText();
            metadataSnippet = raw.substring(0, Math.min(raw.length(), 300));
        }

        logger.warn("═══ SamlMetadataService diagnostic dump (first failure only) ═══");
        logger.warn("Reason: {}", reason);
        logger.warn("Entity JSON top-level fields: {}", fieldNames);
        logger.warn("First 300 chars of 'metadata' value: {}", metadataSnippet);
        logger.warn("Full entity JSON (first entity only): {}", entry);
        logger.warn("═══════════════════════════════════════════════════════════════");
    }

    // ----------------------------------------------------------- cert lookup

    /** Finds the raw metadata XML for a given entityId within a listing. */
    public Optional<String> rawMetadataFor(List<JsonNode> entries, String entityId) {
        for (JsonNode entry : entries) {
            String md = entry.hasNonNull("metadata") ? entry.get("metadata").asText() : null;
            if (md == null || md.isBlank())
                continue;
            try {
                String id = attr(parse(md).getDocumentElement(), "entityID");
                if (entityId.equals(id)) {
                    return Optional.of(md);
                }
            } catch (Exception ignored) {
                // skip unparseable entries
            }
        }
        return Optional.empty();
    }

    // ---------------------------------------------------------- cert replace

    /**
     * Returns a copy of {@code metadataXml} with the signing certificate replaced
     * by {@code newBase64Der}. If several signing certificates are present
     * (rollover in progress) the one nearest expiry is replaced and the others
     * are left untouched; the caller is told how many existed.
     */
    public String replaceSigningCert(String metadataXml, String newBase64Der) throws Exception {
        Document      doc     = parse(metadataXml);
        List<Element> certEls = signingX509Elements(doc.getDocumentElement());
        if (certEls.isEmpty()) {
            throw new IllegalStateException("No signing certificate found in metadata to replace");
        }

        Element target = certEls.size() == 1 ? certEls.get(0) : earliestExpiring(certEls);
        target.setTextContent(newBase64Der);

        if (certEls.size() > 1) {
            logger.warn("Entity has {} signing certs; replaced the earliest-expiring one only", certEls.size());
        }
        return serialize(doc);
    }

    /** How many signing certs an entity currently has (for a UI confirmation hint). */
    public int signingCertCount(String metadataXml) throws Exception {
        return signingX509Elements(parse(metadataXml).getDocumentElement()).size();
    }

    // -------------------------------------------------------- cert validation

    /**
     * Accepts PEM (with or without armor) or raw base64 DER, validates it decodes
     * to an X.509 certificate, and returns a normalized single-line base64 blob
     * suitable for embedding back into metadata.
     */
    public NormalizedCert normalizeCert(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Empty certificate");
        }
        String base64 = input
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        try {
            byte[]          der = Base64.getDecoder().decode(base64);
            X509Certificate x   = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            return new NormalizedCert(
                    base64,
                    cn(x.getSubjectX500Principal().getName()),
                    cn(x.getIssuerX500Principal().getName()),
                    x.getSerialNumber().toString(16).toUpperCase(),
                    DAY.format(x.getNotAfter().toInstant()),
                    x.getNotAfter().before(new Date()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Not a valid X.509 certificate: " + e.getMessage(), e);
        }
    }

    // --------------------------------------------------------------- internals

    private List<X509Certificate> decodeSigningCerts(Element descriptor) {
        List<X509Certificate> out = new ArrayList<>();
        for (Element x509 : signingX509Elements(descriptor)) {
            try {
                byte[] der = Base64.getMimeDecoder().decode(text(x509).replaceAll("\\s", ""));
                out.add((X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der)));
            } catch (Exception ignored) {
                // undecodable cert is skipped for summary purposes
            }
        }
        return out;
    }

    /**
     * X509Certificate elements that belong to a signing KeyDescriptor —
     * i.e. one with {@code use="signing"} or with no {@code use} (which serves both).
     */
    private List<Element> signingX509Elements(Element descriptor) {
        List<Element> out = new ArrayList<>();
        for (Element kd : elementsByLocalName(descriptor, "KeyDescriptor")) {
            String use = attr(kd, "use");
            if (use == null || use.equalsIgnoreCase("signing")) {
                out.addAll(elementsByLocalName(kd, "X509Certificate"));
            }
        }
        return out;
    }

    private Element earliestExpiring(List<Element> certEls) {
        Element best    = certEls.get(0);
        Date    bestExp = null;
        for (Element el : certEls) {
            try {
                byte[]          der = Base64.getMimeDecoder().decode(text(el).replaceAll("\\s", ""));
                X509Certificate x   = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der));
                if (bestExp == null || x.getNotAfter().before(bestExp)) {
                    bestExp = x.getNotAfter();
                    best = el;
                }
            } catch (Exception ignored) {
                // undecodable — leave as-is
            }
        }
        return best;
    }

    private Document parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        // Harden against XXE — this is third-party metadata.
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder b = f.newDocumentBuilder();
        return b.parse(new InputSource(new StringReader(xml)));
    }

    private String serialize(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer t = tf.newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        StringWriter sw = new StringWriter();
        t.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    private static List<Element> elementsByLocalName(Element scope, String local) {
        List<Element> out = new ArrayList<>();
        NodeList      all = scope.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Node n = all.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && local.equals(localName((Element) n))) {
                out.add((Element) n);
            }
        }
        return out;
    }

    private static String localName(Element el) {
        String ln = el.getLocalName();
        if (ln != null)
            return ln;
        String tag = el.getTagName();
        int    i   = tag.indexOf(':');
        return i >= 0 ? tag.substring(i + 1) : tag;
    }

    private static String attr(Element el, String name) {
        String v = el.getAttribute(name);
        return v == null || v.isEmpty() ? null : v;
    }

    private static String text(Element el) {
        return el == null ? null : el.getTextContent();
    }

    private static String cn(String dn) {
        if (dn == null)
            return null;
        Matcher m = CN.matcher(dn);
        return m.find() ? m.group(1) : dn;
    }

    /** Base64URL of the metadata XML, for the importEntity {@code standardMetadata} field. */
    public String toBase64Url(String metadataXml) {
        return Base64.getUrlEncoder().encodeToString(metadataXml.getBytes(StandardCharsets.UTF_8));
    }
}