package com.richardsand.samltest.services;

public class MetadataService {

    public String generateIdpMetadata(
            String entityId,
            String ssoUrl,
            String certificatePem) {

        String certBody = certificatePem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <EntityDescriptor
                    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="%s">

                    <IDPSSODescriptor
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                        WantAuthnRequestsSigned="false">

                        <KeyDescriptor use="signing">
                            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                                <X509Data>
                                    <X509Certificate>%s</X509Certificate>
                                </X509Data>
                            </KeyInfo>
                        </KeyDescriptor>

                        <NameIDFormat>
                            urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
                        </NameIDFormat>

                        <SingleSignOnService
                            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="%s"/>
                    </IDPSSODescriptor>
                </EntityDescriptor>
                """.formatted(
                xmlEscape(entityId),
                certBody,
                xmlEscape(ssoUrl));
    }

    private String xmlEscape(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}
