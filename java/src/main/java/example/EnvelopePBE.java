package example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;

/**
 * Envelope password handling.
 */
public class EnvelopePBE {

    private static final String ARTIFACT_KEY = "artifact";
    private static final String VERSION_KEY = "version";
    private static final String ALGORITHM_KEY = "algorithm";
    private static final String SALT_KEY = "salt";
    private static final String ITERATIONS_KEY = "iterations";
    private static final String SECRET_KEY = "secret";

    private static final String ARTIFACT = "EnvelopePBE";
    private static final String VERSION = "1";

    private static final Set<String> VALID_ALGORITHMS = new HashSet<>(Arrays.asList(
        "PBKDF2WithHmacSHA1"
    ));

    /**
     * Verify password envelope.
     * @param blob Blob to check.
     * @param password Password to check.
     * @return <code>true</code> if matches.
     */
    public static boolean verify(
        String blob,
        String password
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
        if (!map.containsKey(ALGORITHM_KEY)) {
            throw new IllegalArgumentException("Missing algorithm key");
        }
        if (!VALID_ALGORITHMS.contains(map.get(ALGORITHM_KEY))) {
            throw new IllegalArgumentException(String.format("Invalid algorithm '%s'", map.get(ALGORITHM_KEY)));
        }

        final byte[] salt = decoder.decode(map.get(SALT_KEY));
        return Arrays.equals(
            decoder.decode(map.get(SECRET_KEY)),
            SecretKeyFactory.getInstance(map.get(ALGORITHM_KEY)).generateSecret(
                new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    Integer.parseInt(map.get(ITERATIONS_KEY)),
                    salt.length * 8
                )
            ).getEncoded()
        );
    }

    /**
     * Encode password envelope using PBE.
     * @param algorithm Algorithm to use.
     * @param keySize Key size to use.
     * @param iterations Iterations to perform.
     * @param password Password to encode.
     * @param random Random to use or <code>null</code>.
     * @return encoded blob.
     *
     * Recommended settings: algo: PBKDF2WithHmacSHA1, keySize: 256, iterations: 4000.
     */
    public static String encode(
        String algorithm,
        int keySize,
        int iterations,
        String password,
        Random random
    ) throws IOException, GeneralSecurityException {

        if (!VALID_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException(String.format("Invalid algorithm '%s'", algorithm));
        }

        if (random == null) {
            random = SecureRandom.getInstance("SHA1PRNG");
        }

        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final Map<String, String> map = new HashMap<>();
        final byte[] salt = new byte[keySize/8];

        random.nextBytes(salt);

        map.put(ARTIFACT_KEY, ARTIFACT);
        map.put(VERSION_KEY, VERSION);
        map.put(ALGORITHM_KEY, algorithm);
        map.put(SALT_KEY, encoder.encodeToString(salt));
        map.put(ITERATIONS_KEY, Integer.toString(iterations));
        map.put(
            SECRET_KEY,
            encoder.encodeToString(
                SecretKeyFactory.getInstance(algorithm).generateSecret(
                    new PBEKeySpec(
                        password.toCharArray(),
                        salt,
                        iterations,
                        salt.length*8
                    )
                ).getEncoded()
            )
        );
        return encoder.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8));
    }

    public static String encode(
        String algorithm,
        int keySize,
        int iterations,
        String password
    ) throws IOException, GeneralSecurityException {
        return encode(algorithm, keySize, iterations, password, null);
    }

}
