# samltesttool
SAML 2.0 Test Tool

```
 openssl req -x509 \
  -newkey rsa:4096 \
  -keyout src/main/config/saml-test-idp.key.pem \
  -out src/main/config/saml-test-idp.crt.pem \
  -days 3650 \
  -nodes \
  -sha256 \
  -subj "/CN=SAML Test/O=staples.com"
```