package example;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;
import org.junit.BeforeClass;
import org.junit.Test;

public class EnvelopeSignTest {

    private static KeyStore.PrivateKeyEntry entry1;

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

    @BeforeClass
    public static void beforeClass() throws Exception {
        entry1 = getPrivateKeyEntry(getKeyStore("PKCS12", "key1.p12", "changeit"), "1", "changeit");
    }

    @Test
    public void test1() throws Exception {

        Random random = new Random();
        Base64 base64 = new Base64(0);

        for (int i=1;i<100;i++) {
            byte[] r = new byte[i];
            random.nextBytes(r);
            String payload = base64.encodeToString(r);
            String encoded = EnvelopeSign.sign(entry1, "SHA256withRSA", payload);
            assertEquals(
                payload,
                EnvelopeSign.verify(
                    encoded,
                    null
                )
            );

            final Map<String, String> map = new ObjectMapper().readValue(
                Base64.decodeBase64(encoded),
                TypeFactory.defaultInstance().constructMapType(HashMap.class, String.class, String.class)
            );
            map.put(EnvelopeSign.PAYLOAD_KEY, map.get(EnvelopeSign.PAYLOAD_KEY) + "x");
            assertNull(
                EnvelopeSign.verify(
                    base64.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8)),
                    null
                )
            );
        }
    }

    @Test
    public void test2() throws Exception {
        String encoded = "eyJhcnRpZmFjdCI6IkVudmVsb3BlU2lnbiIsInNhbHQiOiJaSFB3aDI1ZU5ubXlMUDU4bmZHV0QxZjF2RUJ4YjNDV0t4a2NpRlFHTHIwPSIsInBheWxvYWQiOiJ0ZXN0aW5nIDEgMiAzIDQiLCJzaWduYXR1cmUiOiJMWnMxVFpIS2VWYmNGN1l2Nm03ZWRtUWUvNGxweUVraUNacGI5dnNHdDNKcnZPNlE5bUdobmNZL3ZVWTZpdEdzZXdEL3FiNVlXdnJLaGs3a0dUclRzMEJpZ3NCUktucUZrYmZsazFMbjFISCtVbHBUMGVRQUdOeUwxbExNWXdldVdWS3JCb3V6TGVma3pWY3F4dUxtUXhFZjBwMm1iRkhic2dMNFhqY2kwZ01PRlJvYk9RS1hFVGg5NTJKaEtabFNEOXRjN3pIWkc0ZFNrakZxM09IcWpnRG5nTUlUYlp5OC96UEJTY203UUp3YUJtcWdpRmY4Z3E1c2hGZWZtWDhMWDA5M2diSy9rTWlTTHFZTHdCeFIrT3E0a0tEdlNFM0ZjUURTc1FtYjVpT0xzWDFMbjR1QlZNdTVCNzFGSWI3SG8zTS96ZU85ajc5dTc1TzMwazNWRVE9PSIsImNlcnRpZmljYXRlIjoiTUlJQzhUQ0NBZG1nQXdJQkFnSUpBT0pDdlBDMG04SGZNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1BOHhEVEFMQmdOVkJBTU1CSFJsYzNRd0hoY05NVFl3TlRFMk1UZzBNRFUyV2hjTk1Ua3dNakV3TVRnME1EVTJXakFQTVEwd0N3WURWUVFEREFSMFpYTjBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXJJRnBlV2MxV056WnQzT2UrWmdhMllVL0RzVDk2djN5VjFxS2FCMkMyYWoyd2VoLzl0b3FqZmdOYmNXVnBydGVXNk9JSFNQcEZ0VWsxOEJnS1U0N1hNc2NsMWFwOEZuUGgwK1hSV2RtL21EbW5laDJEdzBucHVyVWY2elRvOWlxZEgvYjJqTkREeTVMUituTUtXQTVMMWhUYTVTZkdzTWdGNUg5U0FlWThsZE5kVHkzL01PRDJHMmVpNU9ZMVFZUmhQa3k1amxjYmhNNFJXUHRHbHRuM3BZZlhXWXN6ejg1aGtuZmJNZ3RrNThyZ3VzSmJJR3ZDeTBvUUhPZGd2a3JNZWUrZEtwMGs3S2EwalRZNktIOEJ1dXk5dzNZVlN3YnRvYnpUUkkyS0VBbXI3UmYrY3J6MzNUNUxXamZMci9vWGUxYU9RZ3ExT2U4ZHNRZWlWRDd0UUlEQVFBQm8xQXdUakFkQmdOVkhRNEVGZ1FVZ2lQWTF4dlhvS1pNU3d4Ny9XV0dJSlBCMHJNd0h3WURWUjBqQkJnd0ZvQVVnaVBZMXh2WG9LWk1Td3g3L1dXR0lKUEIwck13REFZRFZSMFRCQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFldCtGMmlyTWI2V3dyc2luV1dqY29ILzN4b0RLUG8xZ1JXT2VLdHVwbEM3Z2JhVU5vK3ErcGluak5zdWZpU1FmdVJOelJBei8rRThNcFpJb0ZOVXNuUzkvOUVmYXJRUllneHZXQnFlOG5iaUpLMDNtYjJ3QXZDVWFScHpPTWl5QXpUdjVhY0syNjIzVHlCaDg5WlZhREhZMmpZK0NPOGVNM25jOVlPZEFzYVNwY1ZCazI3KzZuVVFQbUlvNTFsZ243bm1FZXVLdFlkeWNHcXU2WTh1NHBreTNISjF6NGVEU1UzaXBxOVZLb2FvU2JlZzNqSlF2dWV4aFloNUR3V2FscmE0VjZOcUxKT0hpYWlxek90dWZjN2p2MFNpSDBvL0RSWEo2V2hYbm9zK3lZMkV4dkdtUGtEOG5pUXdzdW96Z0pqUWI2RnYraHRjbjlrTDRORE8yTkE9PSIsInZlcnNpb24iOiIxIiwiYWxnbyI6IlNIQTI1NndpdGhSU0EifQ==";
        String test = "testing 1 2 3 4";

        /*
        System.out.println(
            EnvelopeSign.sign(
                entry1,
                "SHA256withRSA",
                test
            )
        );
        */
        assertEquals(
            test,
            EnvelopeSign.verify(
                encoded,
                null
            )
        );
    }
}
