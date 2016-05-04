package example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;

/**
 * Envelope MAC handling.
 */
public class EnvelopeMAC {

    protected static final String ARTIFACT_KEY = "artifact";
    protected static final String VERSION_KEY = "version";
    protected static final String KEYID_ALGO_KEY = "keyid_algo";
    protected static final String KEYID_KEY = "keyid";
    protected static final String MAC_ALGO_KEY = "mac_algo";
    protected static final String SALT_KEY = "salt";
    protected static final String PAYLOAD_KEY = "payload";
    protected static final String MAC_KEY = "mac";

    protected static final String ARTIFACT = "EnvelopeMAC";
    protected static final String VERSION = "1";

    protected static final String KEY_ID_DIGEST = "SHA-1";

    private static final Set<String> VALID_ALGORITHMS = new HashSet<>(Arrays.asList(
        "HmacSHA256",
        "HmacSHA384",
        "HmacSHA512"
    ));

    /**
     * Verify envelope.
     * @param keys Keys to use.
     * @param blob Blob to check.
     * @return <code>null</code> if fails or payload if success.
     */
    public static String verify(
        Collection<byte[]> keys,
        String blob
    ) throws IOException, GeneralSecurityException {
        final Map<String, String> map = new ObjectMapper().readValue(
            Base64.decodeBase64(blob),
            TypeFactory.defaultInstance().constructMapType(HashMap.class, String.class, String.class)
        );

        if (!ARTIFACT.equals(map.get(ARTIFACT_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid artifact '%s'", map.get(ARTIFACT_KEY)));
        }
        if (!VERSION.equals(map.get(VERSION_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid version '%s'", map.get(VERSION_KEY)));
        }
        if (!map.containsKey(MAC_ALGO_KEY)) {
            throw new IllegalArgumentException("Missing algorithm key");
        }
        if (!VALID_ALGORITHMS.contains(map.get(MAC_ALGO_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid algorithm '%s'", map.get(MAC_ALGO_KEY)));
        }

        byte[] key = null;
        byte[] keyid = Base64.decodeBase64(map.get(KEYID_KEY));
        for (byte[] candidate : keys) {
            if (
                Arrays.equals(
                    MessageDigest.getInstance(map.get(KEYID_ALGO_KEY)).digest(candidate),
                    keyid
                )
            ) {
                key = candidate;
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Invalid key");
        }

        Mac mac = Mac.getInstance(map.get(MAC_ALGO_KEY));
        mac.init(new SecretKeySpec(key, map.get(MAC_ALGO_KEY)));
        mac.update(Base64.decodeBase64(map.get(SALT_KEY)));
        mac.update(map.get(PAYLOAD_KEY).getBytes(StandardCharsets.UTF_8));
        if (
            Arrays.equals(
                Base64.decodeBase64(map.get(MAC_KEY)),
                mac.doFinal()
            )
        ) {
            return map.get(PAYLOAD_KEY);
        } else {
            return null;
        }
    }

    /**
     * Encode MAC envelope.
     * @param algorithm Algorithm to use.
     * @param key Key to use.
     * @param payload Message to encode.
     * @param random Random to use or <code>null</code>.
     * @return encoded blob.
     */
    public static String sign(
        String algorithm,
        byte[] key,
        String payload,
        Random random
    ) throws IOException, GeneralSecurityException {

        if (!VALID_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException(String.format("Invalid algorithm '%s'", algorithm));
        }

        if (random == null) {
            random = SecureRandom.getInstance("SHA1PRNG");
        }

        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));

        final Base64 base64 = new Base64(0);
        final Map<String, String> map = new HashMap<>();
        final byte[] salt = new byte[mac.getMacLength()];

        random.nextBytes(salt);

        mac.update(salt);
        mac.update(payload.getBytes(StandardCharsets.UTF_8));

        map.put(ARTIFACT_KEY, ARTIFACT);
        map.put(VERSION_KEY, VERSION);
        map.put(MAC_ALGO_KEY, algorithm);
        map.put(KEYID_ALGO_KEY, KEY_ID_DIGEST);
        map.put(KEYID_KEY, base64.encodeToString(MessageDigest.getInstance(KEY_ID_DIGEST).digest(key)));
        map.put(SALT_KEY, base64.encodeToString(salt));
        map.put(PAYLOAD_KEY, payload);
        map.put(MAC_KEY, base64.encodeToString(mac.doFinal()));
        return base64.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8));
    }

    public static String sign(
        String algorithm,
        byte[] key,
        String payload
    ) throws IOException, GeneralSecurityException {
        return sign(algorithm, key, payload, null);
    }

}
