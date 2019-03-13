package example;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;

/**
 * Envelope Sign handling.
 */
public class EnvelopeSign {

    public static interface CertificateVerifier {
        boolean verify(Certificate cert);
    }

    protected static final String ARTIFACT_KEY = "artifact";
    protected static final String VERSION_KEY = "version";
    protected static final String CERTIFICATE_KEY = "certificate";
    protected static final String ALGO_KEY = "algo";
    protected static final String SALT_KEY = "salt";
    protected static final String PAYLOAD_KEY = "payload";
    protected static final String SIGNATURE_KEY = "signature";

    protected static final String ARTIFACT = "EnvelopeSign";
    protected static final String VERSION = "1";

    private static final Set<String> VALID_ALGORITHMS = new HashSet<>(Arrays.asList(
        "SHA256withRSA",
        "SHA512withRSA"
    ));

    /**
     * Verify envelope.
     * @param blob Blob to check.
     * @param certificateVerifier a certificate verifier or <code>null</null>.
     * @return <code>null</code> if fails or payload if success.
     */
    public static String verify(
        String blob,
        CertificateVerifier certificateVerifier
    ) throws IOException, GeneralSecurityException {
        final Base64.Decoder decoder = Base64.getUrlDecoder();

        final Map<String, String> map = new ObjectMapper().readValue(
            decoder.decode(blob),
            TypeFactory.defaultInstance().constructMapType(HashMap.class, String.class, String.class)
        );

        if (!ARTIFACT.equals(map.get(ARTIFACT_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid artifact '%s'", map.get(ARTIFACT_KEY)));
        }
        if (!VERSION.equals(map.get(VERSION_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid version '%s'", map.get(VERSION_KEY)));
        }
        if (!map.containsKey(ALGO_KEY)) {
            throw new IllegalArgumentException("Missing algorithm key");
        }
        if (!VALID_ALGORITHMS.contains(map.get(ALGO_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid algorithm '%s'", map.get(ALGO_KEY)));
        }

        Certificate cert = CertificateFactory.getInstance("X509").generateCertificate(
            new ByteArrayInputStream(decoder.decode(map.get(CERTIFICATE_KEY)))
        );
        if (certificateVerifier != null) {
            if (!certificateVerifier.verify(cert)) {
                throw new IllegalArgumentException("Untrusted certificate");
            }
        }

        Signature signature = Signature.getInstance(map.get(ALGO_KEY));
        signature.initVerify(cert);
        signature.update(decoder.decode(map.get(SALT_KEY)));
        signature.update(map.get(PAYLOAD_KEY).getBytes(StandardCharsets.UTF_8));
        if (signature.verify(decoder.decode(map.get(SIGNATURE_KEY)))) {
            return map.get(PAYLOAD_KEY);
        } else {
            return null;
        }
    }

    /**
     * Encode Sign envelope.
     * @param pkeyEntry Private key entry.
     * @param algorithm Algorithm to use.
     * @param payload Message to encode.
     * @param random SecureRandom to use or <code>null</code>.
     * @return encoded blob.
     */
    public static String sign(
        KeyStore.PrivateKeyEntry pkeyEntry,
        String algorithm,
        String payload,
        SecureRandom random
    ) throws IOException, GeneralSecurityException {

        if (!VALID_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException(String.format("Invalid algorithm '%s'", algorithm));
        }

        if (random == null) {
            random = SecureRandom.getInstance("SHA1PRNG");
        }

        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(pkeyEntry.getPrivateKey(), random);

        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final Map<String, String> map = new HashMap<>();
        final byte[] salt = new byte[MessageDigest.getInstance(
            algorithm.replaceFirst("with.*", "").replaceFirst("(\\d)", "-$1")
        ).getDigestLength()];

        random.nextBytes(salt);

        signature.update(salt);
        signature.update(payload.getBytes(StandardCharsets.UTF_8));

        map.put(ARTIFACT_KEY, ARTIFACT);
        map.put(VERSION_KEY, VERSION);
        map.put(ALGO_KEY, algorithm);
        map.put(CERTIFICATE_KEY, encoder.encodeToString(pkeyEntry.getCertificate().getEncoded()));
        map.put(SALT_KEY, encoder.encodeToString(salt));
        map.put(PAYLOAD_KEY, payload);
        map.put(SIGNATURE_KEY, encoder.encodeToString(signature.sign()));
        return encoder.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8));
    }

    public static String sign(
        KeyStore.PrivateKeyEntry pkeyEntry,
        String algorithm,
        String payload
    ) throws IOException, GeneralSecurityException {
        return sign(pkeyEntry, algorithm, payload, null);
    }

}
