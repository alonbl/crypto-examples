package example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;

public class EnvelopeBlob {

    private static final String ARTIFACT = "EnvelopeBlob";
    private static final String VERSION = "1";
    private static final String PUBKEY_DIGEST_ALGO = "SHA-1";
    private static final String PKEY_MODE_PADDING = "ECB/PKCS1Padding";

    private static final String PAYLOAD_KEY = "payload";
    private static final String RANDOM_KEY = "random";

    private static final String ARTIFACT_KEY = "artifact";
    private static final String VERSION_KEY = "version";
    private static final String CIPHER_ALGO_KEY = "cipher_algo";
    private static final String ENCRYPTED_PAYLOAD_KEY = "encrypted_blob";
    private static final String IV_KEY = "iv";
    private static final String WRAPPED_KEY_KEY = "wrapped_key";
    private static final String WRAP_ALGO_KEY = "wrap_algo";
    private static final String WRAP_KEYID_ALGO_KEY = "wrap_keyid_algo";
    private static final String WRAP_KEYID_KEY = "wrap_keyid";

    /**
     * Encrypt a payload using envelope.
     * @param algo Cipher algorithm to use.
     * @param bits Size of cipher key.
     * @param cert Certificate to encrypt to (wrap key using public key).
     * @param blockSize Adjust the size of payload to blockSize.
     * @param payload Content to encrypt.
     * @param random Random to use.
     * @return Base64 value of envelope.
     *
     * The blockSize is used in order to hide actual payload size.
     */
    public static String encrypt(
        String algorithm,
        int bits,
        Certificate cert,
        int blockSize,
        String payload,
        Random random
    ) throws GeneralSecurityException, IOException {

        if (random == null) {
            random = SecureRandom.getInstance("SHA1PRNG");
        }

        final String wrapAlgo = cert.getPublicKey().getAlgorithm() + "/" + PKEY_MODE_PADDING;
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final Map<String, String> map = new HashMap<>();
        final Map<String, String> env = new HashMap<>();

        env.put(PAYLOAD_KEY, payload);
        byte[] r = new byte[((payload.length() / blockSize) + 1) * blockSize - payload.length()];
        random.nextBytes(r);
        env.put(RANDOM_KEY, encoder.encodeToString(r));

        KeyGenerator gen = KeyGenerator.getInstance(algorithm.split("/", 2)[0]);
        gen.init(bits);
        Key key = gen.generateKey();
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        Cipher wrap = Cipher.getInstance(wrapAlgo);
        wrap.init(Cipher.WRAP_MODE, cert);

        map.put(ARTIFACT_KEY, ARTIFACT);
        map.put(VERSION_KEY, VERSION);
        map.put(WRAP_ALGO_KEY, wrapAlgo);
        map.put(CIPHER_ALGO_KEY, algorithm);
        map.put(ENCRYPTED_PAYLOAD_KEY, encoder.encodeToString(cipher.doFinal(
            new ObjectMapper().writeValueAsString(env).getBytes(StandardCharsets.UTF_8)))
        );
        map.put(IV_KEY, encoder.encodeToString(cipher.getIV()));
        map.put(WRAPPED_KEY_KEY, encoder.encodeToString(wrap.wrap(key)));
        map.put(WRAP_KEYID_ALGO_KEY, PUBKEY_DIGEST_ALGO);
        map.put(WRAP_KEYID_KEY, encoder.encodeToString(MessageDigest.getInstance(PUBKEY_DIGEST_ALGO).digest(cert.getPublicKey().getEncoded())));
        return encoder.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encrypt a payload using envelope.
     * @param algo Cipher algorithm to use.
     * @param bits Size of cipher key.
     * @param cert Certificate to encrypt to (wrap key using public key).
     * @param blockSize Adjust the size of payload to blockSize.
     * @param payload Content to encrypt.
     * @return Base64 value of envelope.
     *
     * The blockSize is used in order to hide actual payload size.
     */
    public static String encrypt(
        String algorithm,
        int bits,
        Certificate cert,
        int blockSize,
        String payload
    ) throws GeneralSecurityException, IOException {
        return encrypt(
            algorithm,
            bits,
            cert,
            blockSize,
            payload,
            null
        );
    }

    /**
     * Decrypt a payload using envelope.
     * @param pkeyEntry A private key entry (key and certificate) to use for decryption.
     * @param blob value of envelope.
     * @return payload.
     */
    public static String decrypt(
        KeyStore.PrivateKeyEntry pkeyEntry,
        String blob
    ) throws GeneralSecurityException, IOException {
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

        if (
            !MessageDigest.isEqual(
                decoder.decode(map.get(WRAP_KEYID_KEY)),
                MessageDigest.getInstance(map.get(WRAP_KEYID_ALGO_KEY)).digest(
                    pkeyEntry.getCertificate().getPublicKey().getEncoded()
                )
            )
        ) {
            throw new KeyException("Private key entry mismatch");
        }

        Cipher wrap = Cipher.getInstance(map.get(WRAP_ALGO_KEY));
        wrap.init(Cipher.UNWRAP_MODE, pkeyEntry.getPrivateKey());
        Cipher cipher = Cipher.getInstance(map.get(CIPHER_ALGO_KEY));
        cipher.init(
            Cipher.DECRYPT_MODE,
            wrap.unwrap(
                decoder.decode(map.get(WRAPPED_KEY_KEY)),
                cipher.getAlgorithm().split("/", 2)[0],
                Cipher.SECRET_KEY
            ),
            new IvParameterSpec(decoder.decode(map.get(IV_KEY)))
        );

        final Map<String, String> env = new ObjectMapper().readValue(
            cipher.doFinal(decoder.decode(map.get(ENCRYPTED_PAYLOAD_KEY))),
            TypeFactory.defaultInstance().constructMapType(HashMap.class, String.class, String.class)
        );
        return env.get(PAYLOAD_KEY);
    }

}
