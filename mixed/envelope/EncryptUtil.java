import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encryption utility.
 */
public class EncryptUtil {

    private final static String CHIPHER_NAME = "AES/CBC/PKCS5Padding";
    private final static String SEPARATOR = "|";
    private final static String SIGNATURE = "$ENC$";
    private final static String VERSION = "0";

    /**
     * Encrypt a text into an envelope.
     * @param keys the keys dictionary keyid-&gth;base64(key).
     * @param keyid the keyid to use for encryption.
     * @param plaintext the plaintext to encrypt.
     * @return an envelope.
     */
    public static String encrypt(Map<String, String> keys, String keyid, String plaintext) throws GeneralSecurityException {
        if (keyid.indexOf(SEPARATOR) != -1) {
            throw new IllegalArgumentException(String.format("Keyid cannot contain '%s'", SEPARATOR));
        }

        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();
        Random random = SecureRandom.getInstance("SHA1PRNG");

        byte[] nonce = new byte[random.nextInt(64)];
        random.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(CHIPHER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(decoder.decode(keys.get(keyid)), CHIPHER_NAME.substring(0, CHIPHER_NAME.indexOf('/'))));

        try (
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ) {
            try (OutputStream os = new CipherOutputStream(bos, cipher)) {
                os.write((byte) ((nonce.length + 1) & 0xff));
                os.write(nonce);
                os.write(plaintext.getBytes(StandardCharsets.UTF_8));
            }

            return Stream.of(
                SIGNATURE,
                VERSION,
                CHIPHER_NAME,
                keyid,
                encoder.encodeToString(cipher.getIV()),
                encoder.encodeToString(bos.toByteArray())
            ).collect(Collectors.joining(SEPARATOR));
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Decrypt an envelope.
     * @param keys the keys dictionary keyid-&gth;base64(key).
     * @param envelope the envelope to decrypt.
     * @return plaintext.
     */
    public static String decrypt(Map<String, String> keys, String envelope) throws GeneralSecurityException {

        if (envelope == null) {
            throw new IllegalArgumentException("Envelope is expected but null");
        }

        if (keys == null) {
            throw new IllegalArgumentException("Keys are expected but null");
        }

        String[] parts = envelope.split(Pattern.quote(SEPARATOR));
        int i = 0;

        if (!SIGNATURE.equals(parts[i++])) {
            throw new IllegalArgumentException("Expected signature not found");
        }
        if (parts.length == 1) {
            throw new IllegalArgumentException("Excepted version component not found");
        }
        if (!VERSION.equals(parts[i])) {
            throw new IllegalArgumentException(String.format("Unsupported version '%s'", parts[i]));
        }
        i++;
        if (parts.length != 6) {
            throw new IllegalArgumentException(String.format("Illegal format of version '%s'", VERSION));
        }

        String cipherName = parts[i++];
        String keyid = parts[i++];
        String iv = parts[i++];
        String ciphered = parts[i++];

        Base64.Decoder decoder = Base64.getDecoder();
        Cipher cipher = Cipher.getInstance(cipherName);
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(
                decoder.decode(
                    Optional.ofNullable(keys.get(keyid)).orElseThrow(
                        () -> new IllegalArgumentException(String.format("Key id '%s' is not available", keyid))
                    )
                ),
                cipherName.substring(0, cipherName.indexOf('/'))
            ),
            new IvParameterSpec(decoder.decode(iv))
        );

        byte[] payload = cipher.doFinal(decoder.decode(ciphered));

        return new String(payload, payload[0] & 0xff, payload.length - (payload[0] & 0xff), StandardCharsets.UTF_8);
    }

    public static void main(String... args) throws Exception {
        Random random = SecureRandom.getInstance("NativePRNG");
        Base64.Encoder encoder = Base64.getEncoder();

        int KEY_SIZE = 128;
        String keyid = "1";
        byte[] rawKey = new byte[KEY_SIZE/8];
        random.nextBytes(rawKey);
        String key = encoder.encodeToString(rawKey);
        String plaintext = "long long long long long secret 1234";
        Map<String, String> keys = new HashMap<>();
        keys.put(keyid, key);

        System.out.printf("keyid='%s', key='%s', plaintext='%s'%n", keyid, key, plaintext);
        String envelope = encrypt(keys, keyid, plaintext);
        System.out.printf("envelope='%s'%n", envelope);
        String plaintext2 = decrypt(keys, envelope);
        System.out.printf("plaintext2='%s' expected=%s%n", plaintext2, plaintext.equals(plaintext2));
    }
}
