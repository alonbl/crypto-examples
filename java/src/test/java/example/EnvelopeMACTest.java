package example;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;
import org.junit.Test;

public class EnvelopeMACTest {

    private static final String ALGORITHM = "HmacSHA256";

    private byte[] generateKey() {
        Random random = new Random();
        byte[] key = new byte[256/8];
        random.nextBytes(key);
        return key;
    }

    @Test
    public void test1() throws Exception {

        Random random = new Random();
        Base64 base64 = new Base64(0);
        byte[] key = generateKey();

        for (int i=1;i<100;i++) {
            byte[] r = new byte[i];
            random.nextBytes(r);
            String payload = base64.encodeToString(r);
            String encoded = EnvelopeMAC.sign(ALGORITHM, key, payload);
            assertEquals(
                payload,
                EnvelopeMAC.verify(
                    Arrays.asList(key),
                    encoded
                )
            );

            final Map<String, String> map = new ObjectMapper().readValue(
                Base64.decodeBase64(encoded),
                TypeFactory.defaultInstance().constructMapType(HashMap.class, String.class, String.class)
            );
            map.put(EnvelopeMAC.PAYLOAD_KEY, map.get(EnvelopeMAC.PAYLOAD_KEY) + "x");
            assertNull(
                EnvelopeMAC.verify(
                    Arrays.asList(key),
                    base64.encodeToString(new ObjectMapper().writeValueAsString(map).getBytes(StandardCharsets.UTF_8))
                )
            );
        }
    }

    @Test
    public void test2() throws Exception {
        final byte[] key = new Base64(0).decode("Wd7TqTszHfIJ+o6t7kAcEcn9Wa+oQbirJmn+rlKHg5s=");
        final String encoded = "eyJhcnRpZmFjdCI6IkVudmVsb3BlTUFDIiwia2V5aWRfYWxnbyI6IlNIQS0xIiwic2FsdCI6ImFWT0EzYVVKTGJ0U3NUWVRuQUNTc09hV2dUQU5QT3NKOE5obTVHakt1bkE9IiwicGF5bG9hZCI6Im9rIiwibWFjX2FsZ28iOiJIbWFjU0hBMjU2Iiwia2V5aWQiOiJtWFFjUVp1eHRZZjBrdFhjdmlzRVl4VXR2TVk9IiwidmVyc2lvbiI6IjEiLCJtYWMiOiJML2p1S2FwVTB6WWxtMGhyZXR3R3hBSmdicEpXOEJQbDN2Yy93WnZrcnA0PSJ9";
        String payload = "ok";

        //System.out.println(EnvelopeMAC.sign(ALGORITHM, key, payload));
        assertEquals(
            payload,
            EnvelopeMAC.verify(Arrays.asList(key), encoded)
        );
    }

    @Test
    public void test3() throws Exception {

        byte[] key = generateKey();
        String payload = "payload";

        assertNotEquals(
            EnvelopeMAC.sign(ALGORITHM, key, payload),
            EnvelopeMAC.sign(ALGORITHM, key, payload)
        );
    }

    @Test(expected=IllegalArgumentException.class)
    public void test4() throws Exception {
        EnvelopeMAC.verify(
            Arrays.asList(generateKey()),
            EnvelopeMAC.sign(ALGORITHM, generateKey(), "test")
        );
    }
}
