package example;

import static org.junit.Assert.fail;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsException;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class JwtValidationTest {

    public class MMap<K, V> extends HashMap<K, V> {
        public MMap<K, V> mput(K k, V v) {
            put(k, v);
            return this;
        }
    }

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static KeyStore.PrivateKeyEntry entry;
    private static String entrySKU;
    private static CertStore certstore;
    private static Set<TrustAnchor> anchors;
    private static JwtValidation jv;

    private static KeyStore getKeyStore(String storeType, String store, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(storeType);
        try (InputStream is = ClassLoader.getSystemResourceAsStream(store)) {
            ks.load(is, password.toCharArray());
        }
        return ks;
    }

    private static KeyStore.PrivateKeyEntry getPrivateKeyEntry(KeyStore ks, String alias, String password) throws Exception {
        return (KeyStore.PrivateKeyEntry)ks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
    }

    private static String getSKU(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue("2.5.29.14");
        if (ext == null) {
            throw new RuntimeException("No SKU");
        }
        if (ext[0] != 0x04) {
            throw new RuntimeException("Invalid SKU");
        }
        if ((ext[1] & 0x80) != 0) {
            throw new RuntimeException("SKU too long");
        }
        if (ext[2] != 0x04) {
            throw new RuntimeException("Invalid SKU");
        }
        if ((ext[3] & 0x80) != 0) {
            throw new RuntimeException("SKU too long");
        }
        int len = (int)ext[3];
        byte[] sku = new byte[len];
        System.arraycopy(ext, 4, sku, 0, len);
        return new Base64(0).encodeToString(sku).replaceAll("=", "");
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        entry = getPrivateKeyEntry(getKeyStore("PKCS12", "key1.p12", "changeit"), "1", "changeit");
        entrySKU = getSKU((X509Certificate)entry.getCertificate());
        Certificate[] certs = entry.getCertificateChain();
        certstore = CertStore.getInstance(
            "Collection",
            new CollectionCertStoreParameters(Arrays.asList(certs))
        );
        anchors = CertificateValidation.getAnchors(Arrays.asList(certs[certs.length-1]));
        jv = new JwtValidation(anchors, certstore, certstore);
    }

    private void cleanupMap(Map<String, Object> m) {
        Iterator<Map.Entry<String, Object>> i = m.entrySet().iterator();
        while (i.hasNext()) {
            Map.Entry<String, Object> entry = i.next();
            if (entry.getValue() == null) {
                i.remove();
            }
        }
    }

    private String getJwt(Map<String, Object> eheaders, Map<String, Object> eclaims) {
        Map<String, Object> headers = new MMap<String, Object>()
            .mput("alg", SignatureAlgorithm.RS256.getJwaName())
            .mput("kid", entrySKU)
        ;
        Map<String, Object> claims = new MMap<String, Object>()
            .mput("sub", "1234567890")
            .mput("name", "John Doe")
            .mput("exp", Instant.now().plusSeconds(60).getEpochSecond())
        ;
        if (eheaders != null) {
            headers.putAll(eheaders);
        }
        if (eclaims != null) {
            claims.putAll(eclaims);
        }
        cleanupMap(headers);
        cleanupMap(claims);

        JwsJwtCompactProducer producer = new JwsJwtCompactProducer(
            new JwsHeaders(headers),
            new JwtClaims(claims)
        );
        return producer.signWith(entry.getPrivateKey());
    }

    @Test
    public void testSanityRaw() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImdpUFkxeHZYb0taTVN3eDcvV1dHSUpQQjByTSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MTQ4OTA4MTA3OTc5OTB9.K-Bp_9lAW2W9PjmXGdGwrEID-dvamTmZwwndcQvO8mJJgW_PIo76_BYO-Ncstb_vPnxdG2Re9X_kEjve-i5cymdIkoYczPlryg-QxgLa1ZUt0-7FkLhWbGxghNLxk2k5vdcS07OwOG6wdDhoEvv_49h05p4FKG2Re5dskJIXRKzvmBYddqJrBDJsfYT0UGB94oVKnOQtI7mEB4Q1XpKz5NqYMN_HWZqEF5MHBBLbsIxCpHD6zOeJNppl7BSywFyJMRp-eSBwKlsR3eSX_jMDuM13Eaf3h3yd2pKDIxtValh822xaL9GnDq-YeAxmQrEg8o6tN_r1WRcoS8-cgqw3Ng";
/*
{
  "alg": "RS256",
  "kid": "giPY1xvXoKZMSwx7/WWGIJPB0rM"
}
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "exp": 14890810797990
}
*/
        jv.verify(jwt);
    }

    @Test
    public void testSanity() throws Exception {
        String jwt = getJwt(null, null);
        jv.verify(jwt);
        jv.verify(jwt);
        jv.verify(jwt);
        jv.verify(jwt);
        jv.verify(jwt);
        jv.verify(jwt);
    }

    @Test
    public void testBadTotalyBad() throws Exception {
        thrown.expect(JwsException.class);
        jv.verify("kahdkjsahdkjsahdkjsahdkjsahdakjshdkjsa");
    }

    @Test
    public void testBadTotallyThree() throws Exception {
        // bad jose!
        thrown.expect(StringIndexOutOfBoundsException.class);
        jv.verify("kahdkjsahdkjsahdkjsahdkjsahdakjshdkjsa.asdasdsad.sadasd");
    }

    @Test
    public void testBadInvalidChars() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Missing algorithm");
        jv.verify("adasdשגדשג.asdasdשדגשדג.asdsa");
    }

    @Test
    public void testBadContent() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage(String.format("Invalid keyid '%s' signature", entrySKU));
        String valid = getJwt(null, null);
        jv.verify(
            valid.substring(0, valid.indexOf('.')+1) +
            "X" + valid.substring(valid.indexOf('.')+2)
        );
    }

    @Test
    public void testBadSignature() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage(String.format("Invalid keyid '%s' signature", entrySKU));
        String valid = getJwt(null, null);
        jv.verify(
            valid.substring(0, valid.lastIndexOf('.')+1) +
            "X" + valid.substring(valid.lastIndexOf('.')+2)
        );
    }

    @Test
    public void testBadKeyId() throws Exception {
        thrown.expect(InvalidAlgorithmParameterException.class);
        jv.verify(
            getJwt(
                new MMap<String, Object>().mput("kid", "asdsadsa"),
                null
            )
        );
    }

    @Test
    public void testNoKeyId() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Missing keyid");
        jv.verify(
            getJwt(
                new MMap<String, Object>().mput("kid", null),
                null
            )
        );
    }

    @Test
    public void testBadAlgorithm() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Unsupported algorithm 'xxx'");
        String valid = getJwt(null, null);
        jv.verify(
            new Base64(0).encodeToString("{\"alg\": \"xxx\", \"kid\":\"eee\"}".getBytes(StandardCharsets.UTF_8)) +
            valid.substring(valid.indexOf('.'))
        );
    }

    @Test
    public void testNoAlgorithm() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Missing algorithm");
        String valid = getJwt(null, null);
        jv.verify(
            new Base64(0).encodeToString("{\"kid\":\"eee\"}".getBytes(StandardCharsets.UTF_8)) +
            valid.substring(valid.indexOf('.'))
        );
    }

    @Test
    public void testNoJson() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage(String.format("Invalid keyid '%s' signature", entrySKU));
        String valid = getJwt(null, null);
        jv.verify(
            "X" + valid.substring(1)
        );
    }

    @Test
    public void testExpired() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Token expired");
        jv.verify(
            getJwt(
                null,
                new MMap<String, Object>().mput("exp", 5L)
            )
        );
    }

    @Test
    public void testNoExpired() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Missing expiration time");
        jv.verify(
            getJwt(
                null,
                new MMap<String, Object>().mput("exp", null)
            )
        );
    }

    @Test
    public void testTryToIgnoreMissingExpire() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Missing expiration time");
        jv.verify(
            getJwt(
                null,
                new MMap<String, Object>().mput("exp", null)
            ),
            false
        );
    }

    @Test
    public void testIgnoreExpire() throws Exception {
        jv.verify(
            getJwt(
                null,
                new MMap<String, Object>().mput("exp", 5L)
            ),
            false
        );
    }

    @Test
    public void testUnauthorized() throws Exception {
        thrown.expect(InvalidAlgorithmParameterException.class);
        CertStore empty = CertStore.getInstance(
            "Collection",
            new CollectionCertStoreParameters(Collections.emptyList())
        );
        new JwtValidation(anchors, certstore, empty).verify(getJwt(null, null));
    }
}
