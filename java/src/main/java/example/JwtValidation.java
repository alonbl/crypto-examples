package example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;

public class JwtValidation {

    private static final Map<String, SignatureAlgorithm> validAlgorithms = new HashMap<String, SignatureAlgorithm>() {{
        for (SignatureAlgorithm a : Arrays.asList(
            SignatureAlgorithm.ES256,
            SignatureAlgorithm.ES384,
            SignatureAlgorithm.ES512,
            SignatureAlgorithm.PS256,
            SignatureAlgorithm.PS384,
            SignatureAlgorithm.PS512,
            SignatureAlgorithm.RS256,
            SignatureAlgorithm.RS384,
            SignatureAlgorithm.RS512
        )) {
            put(a.getJwaName(), a);
        }
    }};

    private class CertificateCacheEntry {
        private final X509Certificate cert;
        private final Instant expire;
        CertificateCacheEntry(
            X509Certificate cert,
            Instant expire
        ) {
            this.cert = cert;
            this.expire = expire;
        }
    }

    private final Set<TrustAnchor> anchors;
    private final CertStore authorities;
    private final CertStore certstore;
    private final long ttl;
    private final Map<String, CertificateCacheEntry> cache = new ConcurrentHashMap<>();

    private static byte[] toOctetString(byte[] in) throws IOException {
        // we are layzy
        if (in.length > 127) {
            throw new IllegalArgumentException("Octet string candidate is too long");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((byte)0x04);    // OCTET_STRING
        out.write((byte)in.length);
        out.write(in);
        return out.toByteArray();
    }

    /**
     * Constructor.
     * @param anchors a set of valid anchors.
     * @param authorities a {@link Certstore} with signing authorities.
     * @param certstore a {@link CertStore}  with certificate chains.
     * @param ttl certificate validation interval in seconds.
     *
     * Only supported certtificate with subject key identifier and
     * tokens with kid that refer to the subject key identifier.
     *
     * Not that anchors, certstore and authorities are stored as a reference,
     * modification will affect runtime.
     *
     * authorities should be only end certificate of these that are permitted
     * to sign tokens, do not pass same reference to both authorities and certstore.
     */
    public JwtValidation(Set<TrustAnchor> anchors, CertStore authorities, CertStore certstore, long ttl) {
        this.anchors = anchors;
        this.authorities = authorities;
        this.certstore = certstore;
        this.ttl = ttl;

    }

    /**
     * Constructor.
     * @param anchors a set of valid anchors.
     * @param authorities a {@link Certstore} with signing authorities.
     * @param certstore a {@link CertStore}  with signing certificates.
     */
    public JwtValidation(Set<TrustAnchor> anchors, CertStore authorities, CertStore certstore) {
        this(anchors, authorities, certstore, 60*60);
    }

    /**
     * Verify jwt.
     * @param jwt jwt to verify.
     * @param verifyExpiration if to verify expiration or not.
     * @throws Exception various of failure resasn.
     * @returns {@ref JwtToken}.
     */
    public JwtToken verify(String jwt, boolean verifyExpiration) throws Exception {
        Instant now = Instant.now();

        /*
         * Header
         */
        JwsJwtCompactConsumer consumer = new JwsJwtCompactConsumer(jwt);
        JwsHeaders headers = consumer.getJwsHeaders();
        if (headers == null) {
            throw new IllegalArgumentException("Missing headers");
        }
        String algo_name = headers.getAlgorithm();
        if (algo_name == null) {
            throw new IllegalArgumentException("Missing algorithm");
        }
        SignatureAlgorithm algo = validAlgorithms.get(algo_name);
        if (algo == null) {
            throw new IllegalArgumentException(String.format("Unsupported algorithm '%s'", algo_name));
        }
        String kid = headers.getKeyId();
        if (kid == null || kid.isEmpty()) {
            throw new IllegalArgumentException("Missing keyid");
        }

        /*
         * Key
         */
        CertificateCacheEntry entry = cache.get(kid);
        if (entry == null || now.isAfter(entry.expire)) {
            X509CertSelector selector = new X509CertSelector();
            byte[] kidraw = Base64.getUrlDecoder().decode(kid);
            if (kidraw.length == 0) {
                throw new IllegalArgumentException("Illegal keyid");
            }
            // this stupid java does not apply the actual content
            // we need to wrap in OCTET_STRING
            selector.setSubjectKeyIdentifier(toOctetString(kidraw));

            PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(
                anchors,
                selector
            );
            pkixParams.setRevocationEnabled(Boolean.getBoolean("com.sun.security.enableCRLDP") || Boolean.getBoolean("ocsp.enable"));
            pkixParams.setMaxPathLength(-1);
            pkixParams.addCertStore(certstore);
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)CertPathBuilder.getInstance("PKIX").build(pkixParams);

            List<? extends Certificate> certs = result.getCertPath().getCertificates();
            X509Certificate cert;
            if (certs.size() == 0) {
                // self signed certificate
                cert = result.getTrustAnchor().getTrustedCert();
            } else {
                cert = (X509Certificate)certs.get(0);
            }

            selector = new X509CertSelector();
            selector.setCertificate(cert);
            if (authorities.getCertificates(selector).size() == 0) {
                throw new IllegalArgumentException(String.format("Unauthorized keyid '%s' certificate '%s'", kid, cert.getSubjectX500Principal().getName()));
            }

            entry = new CertificateCacheEntry(cert, now.plusSeconds(ttl));
            cache.put(kid, entry);
        }

        if (!consumer.verifySignatureWith(entry.cert, algo)) {
            throw new IllegalArgumentException(String.format("Invalid keyid '%s' signature", kid));
        }

        /*
         * Claims
         */
        JwtToken token = consumer.getJwtToken();
        if (token == null) {
            throw new IllegalArgumentException("No token");
        }

        JwtClaims claims = token.getClaims();
        if (claims == null) {
            throw new IllegalArgumentException("Missing claims");
        }

        Long expire = claims.getExpiryTime();
        if (expire == null) {
            throw new IllegalArgumentException("Missing expiration time");
        }

        if (verifyExpiration && now.isAfter(Instant.ofEpochSecond(expire))) {
            throw new IllegalArgumentException("Token expired");
        }

        return token;
    }

    /**
     * Verify jwt.
     * @param jwt jwt to verify.
     * @returns {@ref JwtToken}.
     */
    public JwtToken verify(String jwt) throws Exception {
        return verify(jwt, true);
    }

}
