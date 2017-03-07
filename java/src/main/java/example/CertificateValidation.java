package example;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CertificateValidation {

    /**
     * Builds CertsPath object out of chain candidate.
     * Throws CertPathBuilderException exception if fails among other exceptions.
     * @param chain chain candidate, first end certificate last issuer.
     * @param trustAnchors trust anchors to use.
     * @return CertPath
     */
    public static CertPath buildCertPath(
        Set<TrustAnchor> trustAnchors,
        List<Certificate> chain
    ) throws GeneralSecurityException {
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate((X509Certificate)chain.get(0));
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(
            trustAnchors,
            selector
        );
        pkixParams.setRevocationEnabled(Boolean.getBoolean("com.sun.security.enableCRLDP") || Boolean.getBoolean("ocsp.enable"));
        pkixParams.setMaxPathLength(-1);
        pkixParams.addCertStore(
            CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(chain)
            )
        );
        return CertPathBuilder.getInstance("PKIX").build(pkixParams).getCertPath();
    }

    public static List<Certificate> parseCertificates(String... pems) throws CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<Certificate> certs = new ArrayList<>();
        for (String pem : pems) {
            try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))) {
                certs.add(cf.generateCertificate(in));
            }
        }
        return certs;
    }

    public static Set<TrustAnchor> getAnchors(List<Certificate> certs) {
        Set<TrustAnchor> anchors = new HashSet<>();
        for (Certificate cert : certs) {
            anchors.add(new TrustAnchor((X509Certificate)cert, null));
        }
        return anchors;
    }
}
