package example;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Base64;
import java.util.Random;

import org.junit.Test;

public class EnvelopePBETest {

    @Test
    public void test1() throws Exception {

        Random random = new Random();

        for (int i=1;i<100;i++) {
            byte[] r = new byte[i];
            random.nextBytes(r);
            String password = Base64.getUrlEncoder().withoutPadding().encodeToString(r);
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
        String encoded = "eyJhcnRpZmFjdCI6IkVudmVsb3BlUEJFIiwic2FsdCI6InJKZVd0cWpaNVRpbjQ5OTE5UjVnTDlSZzdGamRtT1MwdlJkZm4yeDhud2MiLCJzZWNyZXQiOiJQclB0SVo5ZVVSYTdRQXAwSC1heWlFOWduWjNLM01FZFdkemlYQ0E0QTNFIiwidmVyc2lvbiI6IjEiLCJpdGVyYXRpb25zIjoiNDAwMCIsImFsZ29yaXRobSI6IlBCS0RGMldpdGhIbWFjU0hBMSJ9";
        //System.out.println(EnvelopePBE.encode("PBKDF2WithHmacSHA1", 256, 4000, "password"));
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
