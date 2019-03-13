package example;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyStore;

import org.junit.BeforeClass;
import org.junit.Test;

public class EnvelopeBlobTest {

    private static KeyStore.PrivateKeyEntry entry1;
    private static KeyStore.PrivateKeyEntry entry2;

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
        entry2 = getPrivateKeyEntry(getKeyStore("PKCS12", "key2.p12", "changeit"), "1", "changeit");
    }

    @Test
    public void test1() throws Exception {
        String test = "testing 1 2 3 4";

        assertEquals(
            test,
            EnvelopeBlob.decrypt(
                entry1,
                EnvelopeBlob.encrypt(
                    "AES/OFB/PKCS5Padding",
                    256,
                    entry1.getCertificate(),
                    100,
                    test
                )
            )
        );
    }

    @Test
    public void test2() throws Exception {
        String test = "testing 1 2 3 4";
        String blob = "eyJhcnRpZmFjdCI6IkVudmVsb3BlQmxvYiIsIndyYXBfYWxnbyI6IlJTQS9FQ0IvUEtDUzFQYWRkaW5nIiwiZW5jcnlwdGVkX2Jsb2IiOiJ3eHl6am1nSmIzZnhIbWNPSmNwa2VLSkpBX2N6X1Z6ZFNUZVNkeUpZZjFMZUY2ekpNT2k2a0Y4b2J2YnRWX3VtRnJPZWN0Tk45YkExZE8za2lsNXBJUERoRE1ZVlNzRDdXeDdlSnBpd0w4OV9QY2NPNkV1Q0lEdmRpREk3dnE4bEtMVGg2ZDZweF9XLUh5ZDhjQ1ZrajBfdzRaTjNWREZUbnJCVExDbVlUUHlQUnVlSEI4ZmMxUWpJYmJ6aTlFU1RmRUQxRTU4Q3N4aklBNnBIOGRtVmJ3Iiwid3JhcHBlZF9rZXkiOiJlVi1KZDNqT2ZJWXhHZDRMQVVfbm5TVm03UEFLLVFGSGdGaHRhVXpVYjZtZjh0SS1YMXRvWGRuZmdTdWRvb1htTDJVU2ZQTVlScWlWVS04WXVKR0VGN2xLWnc1QXF6TFFoTDVyTGpPR2VvZEh4b0dXUEtCV3dOeVMtOV81ZGNKV0ZjZVFyQjdLYWFlYnM2QVRhc1BvejhvdXNyRGhOdXA5YUdoMTNkbk4yNld4Sm80RG1yMFFFZWpKRGlCZGNUa3E0R2U1UnBGaV96WVh1SUllbThpeE82d0RFUTZaMkRncG4xMnlZcnlZVkdwYmdBWTlyNFctS3hQOFhULUlSUXpld0lMbEliZllQS01LVXEwQVd2OUdOMEJnMDZTYU8zR3BjMXBtdUJLSUVzQmJiT3h5ZTFfOWFsbkNDYUxqdGtRV1hqYUtzT04taXZGMWdWUWVGdWpyWUEiLCJ3cmFwX2tleWlkX2FsZ28iOiJTSEEtMSIsImNpcGhlcl9hbGdvIjoiQUVTL09GQi9QS0NTNVBhZGRpbmciLCJ2ZXJzaW9uIjoiMSIsIml2IjoiemlXRjdmYmd5a3oyNERSY1ctZGNvZyIsIndyYXBfa2V5aWQiOiJTdmRzRTRkTV9TNEp2bnJ2ZV84U1ZfVnl6akEifQ";
        /*
        System.out.println(
            EnvelopeBlob.encrypt(
                "AES/OFB/PKCS5Padding",
                256,
                entry1.getCertificate(),
                100,
                test
            )
        );
        */
        assertEquals(
            test,
            EnvelopeBlob.decrypt(
                entry1,
                blob
            )
        );
    }

    @Test(expected=KeyException.class)
    public void testInvalidKey() throws Exception {

        String test = "testing 1 2 3 4";

        assertEquals(
            test,
            EnvelopeBlob.decrypt(
                entry2,
                EnvelopeBlob.encrypt(
                    "AES/OFB/PKCS5Padding",
                    256,
                    entry1.getCertificate(),
                    100,
                    test
                )
            )
        );
    }

}
