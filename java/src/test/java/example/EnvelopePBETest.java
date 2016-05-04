package example;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

public class EnvelopePBETest {

    @Test
    public void test1() throws Exception {

        Random random = new Random();

        for (int i=1;i<100;i++) {
            byte[] r = new byte[i];
            random.nextBytes(r);
            String password = new Base64(0).encodeToString(r);
            String encoded = EnvelopePBE.encode("PBKDF2WithHmacSHA1", 256, 4000, password);
            assertTrue(
                EnvelopePBE.verify(
                    encoded,
                    password
                )
            );
            assertFalse(
                EnvelopePBE.verify(
                    encoded,
                    password + "A"
                )
            );
        }
    }

    @Test
    public void test2() throws Exception {
        String encoded = "eyJhcnRpZmFjdCI6IkVudmVsb3BlUEJFIiwiaXRlcmF0aW9ucyI6IjQwMDAiLCJzZWNyZXQiOiJNWE5nZVlwNUxSWFNRZmRMYzNDOHRVNWRINFZOODExb0czNjlrU0FLOHAwPSIsInNhbHQiOiJudXFaa2M3dlMrNUNkRzVQaEMvWE5ycDMzd0luTnNnZGZIVXlQRE5RS05rPSIsImFsZ29yaXRobSI6IlBCS0RGMldpdGhIbWFjU0hBMSIsInZlcnNpb24iOiIxIn0=";
        assertTrue(
            EnvelopePBE.verify(
                encoded,
                "password"
            )
        );
        assertFalse(
            EnvelopePBE.verify(
                encoded,
                "bad"
            )
        );
    }

    @Test
    public void test3() throws Exception {
        String password = "password";

        assertFalse(
            EnvelopePBE.encode("PBKDF2WithHmacSHA1", 256, 4000, password).equals(
                EnvelopePBE.encode("PBKDF2WithHmacSHA1", 256, 4000, password)
            )
        );
    }
}
