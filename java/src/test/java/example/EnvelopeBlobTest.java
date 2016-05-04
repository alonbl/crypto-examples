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
        String blob = "eyJhcnRpZmFjdCI6IkVudmVsb3BlQmxvYiIsIndyYXBfYWxnbyI6IlJTQS9FQ0IvUEtDUzFQYWRkaW5nIiwiZW5jcnlwdGVkX2Jsb2IiOiJYVmZwYm9ITzBzVjNrWVlvVVpRdmV0T25lTlhVaXFoeTBjRGovRVBja0xRRmMvVkZWTHpha0xpMWhwc2JwNElBZzhBbFFXOU9xays5KytTbGxQYzQvQ2c2d3NmY2l4WjBsRnNLTElGeHZVaXo4RS9wMlV6bDZFWFlFWWF5c2U0UVhLWFQvMUdSZHFLOFFST3AyaWN1K0dOSEJqZ1Y4aTdCT1N1c0ptbUp1WHowSjFTbWpodlpOM0xtQml2cDlJT3BMdHJUSWRpYzFGekJ5N0pqQ0tDY2VBPT0iLCJ3cmFwcGVkX2tleSI6IlhiMjFVMlpybnlWSmR1c0NFbHI3dTlRR1RVTndZcW95aE12U1pHOU12SW9aODVsZzE5bnVQcXg5SWJmajdobzhpampVN0o2LzhDYldMbFZmbkEwTk9DVE56UUdRa0ZubkoxRTd2Q2dkcWx5Q0liWjhTdFpNbm9SR0JZQVJ1T05ZWkFRdHN6MHZXOXpaL3FQbFRhaStEL1dXYnJOb0JBeGtXTy9adCtFVmtnaWtKK2VBN3VvSC83ck8yd1JneXVJYW02UkRVN1hyZDlnM3FVbmVoYmhuS0d4U3dKUXMxTzBVNk9zd3BJMnZQVWRMS3huOTdSSCs1cmFYSUNEaG5nb2NLc091c0Q3SVo0NW13QkdocFlDVkMvM0pQdUhGZ3pJL0kzZzFQa0hPWmJIT3puQnVXSUpNWXZKOVJLWFlCc0JONWpRdmdsUTZpUnVlRDR6RXZSamFZdz09Iiwid3JhcF9rZXlpZF9hbGdvIjoiU0hBLTEiLCJjaXBoZXJfYWxnbyI6IkFFUy9PRkIvUEtDUzVQYWRkaW5nIiwidmVyc2lvbiI6IjEiLCJpdiI6Ik44Rmt3MjZ6L25NUVhJOUFaaUgxNWc9PSIsIndyYXBfa2V5aWQiOiJTdmRzRTRkTS9TNEp2bnJ2ZS84U1YvVnl6akE9In0=";

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
