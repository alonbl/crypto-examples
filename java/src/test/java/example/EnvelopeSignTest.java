package example;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyStore;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

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
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

        for (int i=1;i<100;i++) {
            byte[] r = new byte[i];
            random.nextBytes(r);
            String payload = encoder.encodeToString(r);
            String encoded = EnvelopeSign.sign(entry1, "SHA256withRSA", payload);
            assertEquals(
                payload,
                EnvelopeSign.verify(
                    encoded,
                    null
                )
            );

            final Map<String, String> map = new ObjectMapper().readValue(
                Base64.getUrlDecoder().decode(encoded),
                TypeFactory.defaultInstance().constructMapType(HashMap.class, String.class, String.class)
            );
            map.put(EnvelopeSign.PAYLOAD_KEY, map.get(EnvelopeSign.PAYLOAD_KEY) + "x");
            assertNull(
                EnvelopeSign.verify(
                    encoder.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8)),
                    null
                )
            );
        }
    }

    @Test
    public void test2() throws Exception {
        String encoded = "eyJhcnRpZmFjdCI6IkVudmVsb3BlU2lnbiIsInNhbHQiOiJJZndtS0dYckJsdVBTQ3AxLTlBb21ncDd1LXFSc1JkMzlyRTUySDJDTXgwIiwicGF5bG9hZCI6InRlc3RpbmcgMSAyIDMgNCIsInNpZ25hdHVyZSI6ImowQWtmVzBMQXpTb2R5eExoVi00QkVOMzFlSDBycjIyc3o4OEdJWThORDVOd1UzLUhZeVFYM2tYZlVMMTd6aW5LaEtzM0JiRVVYeHBYQWlFR0ljVGt1LUZrbzFnX1NNS29wMlVnTUprQW1QOENSN3ZUM1dsTGNwNGJPeGZ2SFFQSzFNYjhCNEJLeF9qbVV6VUlwemNxSU5ZZlJGUXZxRjg5SVNiejJ5OHg5Y0dkQ29Lb2RpS3VTckhZOWtOV25CdzhZaGFheXQxQ1BNcG9HSG5qaFoxTmhZa2RHeUplbjBhY2pVLVdZdDlkTndwT0t2WV9MRU83dm9JWHBtREU1NjVXeWRtaUpCaTFFUVMwVGluZG11RU1xR2VQbUJLTjJYV2tEeFNBVjBjcV9MbXhzOWFxWDZSMHltM1hmcUlKeFBnQ05KaGtqNlZ1V09JRDBjNUppSmVpdyIsImNlcnRpZmljYXRlIjoiTUlJQzhUQ0NBZG1nQXdJQkFnSUpBT0pDdlBDMG04SGZNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1BOHhEVEFMQmdOVkJBTU1CSFJsYzNRd0hoY05NVFl3TlRFMk1UZzBNRFUyV2hjTk1Ua3dNakV3TVRnME1EVTJXakFQTVEwd0N3WURWUVFEREFSMFpYTjBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXJJRnBlV2MxV056WnQzT2UtWmdhMllVX0RzVDk2djN5VjFxS2FCMkMyYWoyd2VoXzl0b3FqZmdOYmNXVnBydGVXNk9JSFNQcEZ0VWsxOEJnS1U0N1hNc2NsMWFwOEZuUGgwLVhSV2RtX21EbW5laDJEdzBucHVyVWY2elRvOWlxZEhfYjJqTkREeTVMUi1uTUtXQTVMMWhUYTVTZkdzTWdGNUg5U0FlWThsZE5kVHkzX01PRDJHMmVpNU9ZMVFZUmhQa3k1amxjYmhNNFJXUHRHbHRuM3BZZlhXWXN6ejg1aGtuZmJNZ3RrNThyZ3VzSmJJR3ZDeTBvUUhPZGd2a3JNZWUtZEtwMGs3S2EwalRZNktIOEJ1dXk5dzNZVlN3YnRvYnpUUkkyS0VBbXI3UmYtY3J6MzNUNUxXamZMcl9vWGUxYU9RZ3ExT2U4ZHNRZWlWRDd0UUlEQVFBQm8xQXdUakFkQmdOVkhRNEVGZ1FVZ2lQWTF4dlhvS1pNU3d4N19XV0dJSlBCMHJNd0h3WURWUjBqQkJnd0ZvQVVnaVBZMXh2WG9LWk1Td3g3X1dXR0lKUEIwck13REFZRFZSMFRCQVV3QXdFQl96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFldC1GMmlyTWI2V3dyc2luV1dqY29IXzN4b0RLUG8xZ1JXT2VLdHVwbEM3Z2JhVU5vLXEtcGluak5zdWZpU1FmdVJOelJBel8tRThNcFpJb0ZOVXNuUzlfOUVmYXJRUllneHZXQnFlOG5iaUpLMDNtYjJ3QXZDVWFScHpPTWl5QXpUdjVhY0syNjIzVHlCaDg5WlZhREhZMmpZLUNPOGVNM25jOVlPZEFzYVNwY1ZCazI3LTZuVVFQbUlvNTFsZ243bm1FZXVLdFlkeWNHcXU2WTh1NHBreTNISjF6NGVEU1UzaXBxOVZLb2FvU2JlZzNqSlF2dWV4aFloNUR3V2FscmE0VjZOcUxKT0hpYWlxek90dWZjN2p2MFNpSDBvX0RSWEo2V2hYbm9zLXlZMkV4dkdtUGtEOG5pUXdzdW96Z0pqUWI2RnYtaHRjbjlrTDRORE8yTkEiLCJ2ZXJzaW9uIjoiMSIsImFsZ28iOiJTSEEyNTZ3aXRoUlNBIn0";
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
