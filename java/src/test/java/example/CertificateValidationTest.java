package example;

import java.security.cert.CertPathBuilderException;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CertificateValidationTest {

    private static final String ENABLE_CRLDP = "com.sun.security.enableCRLDP";
    private static final String ENABLE_AIA = "com.sun.security.enableAIAcaIssuers";
    private static final String ENABLE_OCSP = "ocsp.enable";

    private Map<String, String> originalProperties;

    static {
        System.setProperty(ENABLE_CRLDP, "true");
        System.setProperty(ENABLE_AIA, "true");
        System.setProperty(ENABLE_OCSP, "true");
    }

    /*
     * Not really working as these properties cannot be modified dynamically.
     */
    @Before
    public void beforeTest() {
        originalProperties = new HashMap<>();
        originalProperties.put(ENABLE_CRLDP, System.getProperty(ENABLE_CRLDP));
        originalProperties.put(ENABLE_AIA, System.getProperty(ENABLE_AIA));
        originalProperties.put(ENABLE_OCSP, System.getProperty(ENABLE_OCSP));
    }

    @After
    public void afterTest() {
        for (Map.Entry<String, String> entry : originalProperties.entrySet()) {
            if (entry.getValue() == null) {
                System.getProperties().remove(entry.getKey());
            } else {
                System.setProperty(entry.getKey(), entry.getValue());
            }
        }
    }

    @Test
    public void testGoogleAIA() throws Exception {
        String pems[] = {
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzzCCAregAwIBAgIQOhX0yH+00zmT0+6zv0rl5DANBgkqhkiG9w0BAQsFADBU\n" +
            "MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMSUw\n" +
            "IwYDVQQDExxHb29nbGUgSW50ZXJuZXQgQXV0aG9yaXR5IEczMB4XDTE5MDMwMTA5\n" +
            "NDYzNVoXDTE5MDUyNDA5MjUwMFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh\n" +
            "bGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2ds\n" +
            "ZSBMTEMxFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI\n" +
            "zj0DAQcDQgAEGEOeuWMHeZju/oAHRmPZv6enGuyqiEF6HN4/fKT5NsXm4Va7DhGb\n" +
            "7i+aix5FmE8+v2BUWMM6rNlSbOxLQXizOqOCAVIwggFOMBMGA1UdJQQMMAoGCCsG\n" +
            "AQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNv\n" +
            "bTBoBggrBgEFBQcBAQRcMFowLQYIKwYBBQUHMAKGIWh0dHA6Ly9wa2kuZ29vZy9n\n" +
            "c3IyL0dUU0dJQUczLmNydDApBggrBgEFBQcwAYYdaHR0cDovL29jc3AucGtpLmdv\n" +
            "b2cvR1RTR0lBRzMwHQYDVR0OBBYEFOpdu9+PS1y55JEOLqY38W5ChwzRMAwGA1Ud\n" +
            "EwEB/wQCMAAwHwYDVR0jBBgwFoAUd8K4UJpndnaxLcKG0IOgfqZ+ukswIQYDVR0g\n" +
            "BBowGDAMBgorBgEEAdZ5AgUDMAgGBmeBDAECAjAxBgNVHR8EKjAoMCagJKAihiBo\n" +
            "dHRwOi8vY3JsLnBraS5nb29nL0dUU0dJQUczLmNybDANBgkqhkiG9w0BAQsFAAOC\n" +
            "AQEAGoD+pUAor/VSkY1oTvORpFQI/qPt1VkCL8eC+3qN+6J0ZhK0RIeKeUsSjSVK\n" +
            "xSb/WYPgDvn2RE9YcC8YFEwYAoWZi63Xbk53LbwRBCxBxjP+xrdiTMUm7wkKC/q0\n" +
            "v0TFQw+zfgr6uYiS8VFGAjRPnBJVmyTMc3NHnxmO/Ko/XHvS3DuWQpKh0ocMk7Cp\n" +
            "tJeu2sE9ofH1ruZiWKkjvaNH8MlIvvBa5ecWoYr7Qlnj2lDYFJsJ2epvQNWSuRIt\n" +
            "58z7dTQZopG5YUu5dE5IMT5ZES3ShNVr79I6tyfuyzbtaPvmzxFQr7MiViZg2h+X\n" +
            "sKuItbZwSgEVsFxQx8FjyFsU8A==\n" +
            "-----END CERTIFICATE-----\n" +
            ""
        };
        String[] pemcas = {
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G\n" +
            "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp\n" +
            "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1\n" +
            "MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG\n" +
            "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL\n" +
            "v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8\n" +
            "eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq\n" +
            "tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd\n" +
            "C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa\n" +
            "zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB\n" +
            "mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH\n" +
            "V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n\n" +
            "bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG\n" +
            "3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs\n" +
            "J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO\n" +
            "291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS\n" +
            "ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd\n" +
            "AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7\n" +
            "TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n" +
            "-----END CERTIFICATE-----\n" +
            ""
        };

        System.setProperty(ENABLE_CRLDP, "true");
        System.setProperty(ENABLE_AIA, "true");
        CertificateValidation.buildCertPath(
            CertificateValidation.getAnchors(CertificateValidation.parseCertificates(pemcas)),
            CertificateValidation.parseCertificates(pems)
        );
    }

    @Test
    public void testGoogleCRL() throws Exception {
        String pems[] = {
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzzCCAregAwIBAgIQOhX0yH+00zmT0+6zv0rl5DANBgkqhkiG9w0BAQsFADBU\n" +
            "MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMSUw\n" +
            "IwYDVQQDExxHb29nbGUgSW50ZXJuZXQgQXV0aG9yaXR5IEczMB4XDTE5MDMwMTA5\n" +
            "NDYzNVoXDTE5MDUyNDA5MjUwMFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh\n" +
            "bGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2ds\n" +
            "ZSBMTEMxFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI\n" +
            "zj0DAQcDQgAEGEOeuWMHeZju/oAHRmPZv6enGuyqiEF6HN4/fKT5NsXm4Va7DhGb\n" +
            "7i+aix5FmE8+v2BUWMM6rNlSbOxLQXizOqOCAVIwggFOMBMGA1UdJQQMMAoGCCsG\n" +
            "AQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNv\n" +
            "bTBoBggrBgEFBQcBAQRcMFowLQYIKwYBBQUHMAKGIWh0dHA6Ly9wa2kuZ29vZy9n\n" +
            "c3IyL0dUU0dJQUczLmNydDApBggrBgEFBQcwAYYdaHR0cDovL29jc3AucGtpLmdv\n" +
            "b2cvR1RTR0lBRzMwHQYDVR0OBBYEFOpdu9+PS1y55JEOLqY38W5ChwzRMAwGA1Ud\n" +
            "EwEB/wQCMAAwHwYDVR0jBBgwFoAUd8K4UJpndnaxLcKG0IOgfqZ+ukswIQYDVR0g\n" +
            "BBowGDAMBgorBgEEAdZ5AgUDMAgGBmeBDAECAjAxBgNVHR8EKjAoMCagJKAihiBo\n" +
            "dHRwOi8vY3JsLnBraS5nb29nL0dUU0dJQUczLmNybDANBgkqhkiG9w0BAQsFAAOC\n" +
            "AQEAGoD+pUAor/VSkY1oTvORpFQI/qPt1VkCL8eC+3qN+6J0ZhK0RIeKeUsSjSVK\n" +
            "xSb/WYPgDvn2RE9YcC8YFEwYAoWZi63Xbk53LbwRBCxBxjP+xrdiTMUm7wkKC/q0\n" +
            "v0TFQw+zfgr6uYiS8VFGAjRPnBJVmyTMc3NHnxmO/Ko/XHvS3DuWQpKh0ocMk7Cp\n" +
            "tJeu2sE9ofH1ruZiWKkjvaNH8MlIvvBa5ecWoYr7Qlnj2lDYFJsJ2epvQNWSuRIt\n" +
            "58z7dTQZopG5YUu5dE5IMT5ZES3ShNVr79I6tyfuyzbtaPvmzxFQr7MiViZg2h+X\n" +
            "sKuItbZwSgEVsFxQx8FjyFsU8A==\n" +
            "-----END CERTIFICATE-----\n" +
            "",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEXDCCA0SgAwIBAgINAeOpMBz8cgY4P5pTHTANBgkqhkiG9w0BAQsFADBMMSAw\n" +
            "HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs\n" +
            "U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy\n" +
            "MTUwMDAwNDJaMFQxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg\n" +
            "U2VydmljZXMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzMw\n" +
            "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKUkvqHv/OJGuo2nIYaNVW\n" +
            "XQ5IWi01CXZaz6TIHLGp/lOJ+600/4hbn7vn6AAB3DVzdQOts7G5pH0rJnnOFUAK\n" +
            "71G4nzKMfHCGUksW/mona+Y2emJQ2N+aicwJKetPKRSIgAuPOB6Aahh8Hb2XO3h9\n" +
            "RUk2T0HNouB2VzxoMXlkyW7XUR5mw6JkLHnA52XDVoRTWkNty5oCINLvGmnRsJ1z\n" +
            "ouAqYGVQMc/7sy+/EYhALrVJEA8KbtyX+r8snwU5C1hUrwaW6MWOARa8qBpNQcWT\n" +
            "kaIeoYvy/sGIJEmjR0vFEwHdp1cSaWIr6/4g72n7OqXwfinu7ZYW97EfoOSQJeAz\n" +
            "AgMBAAGjggEzMIIBLzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\n" +
            "AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHfCuFCa\n" +
            "Z3Z2sS3ChtCDoH6mfrpLMB8GA1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYu\n" +
            "MDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdv\n" +
            "b2cvZ3NyMjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dz\n" +
            "cjIvZ3NyMi5jcmwwPwYDVR0gBDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYc\n" +
            "aHR0cHM6Ly9wa2kuZ29vZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
            "HLeJluRT7bvs26gyAZ8so81trUISd7O45skDUmAge1cnxhG1P2cNmSxbWsoiCt2e\n" +
            "ux9LSD+PAj2LIYRFHW31/6xoic1k4tbWXkDCjir37xTTNqRAMPUyFRWSdvt+nlPq\n" +
            "wnb8Oa2I/maSJukcxDjNSfpDh/Bd1lZNgdd/8cLdsE3+wypufJ9uXO1iQpnh9zbu\n" +
            "FIwsIONGl1p3A8CgxkqI/UAih3JaGOqcpcdaCIzkBaR9uYQ1X4k2Vg5APRLouzVy\n" +
            "7a8IVk6wuy6pm+T7HT4LY8ibS5FEZlfAFLSW8NwsVz9SBK2Vqn1N0PIMn5xA6NZV\n" +
            "c7o835DLAFshEWfC7TIe3g==\n" +
            "-----END CERTIFICATE-----\n" +
            ""
        };
        String[] pemcas = {
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G\n" +
            "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp\n" +
            "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1\n" +
            "MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG\n" +
            "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL\n" +
            "v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8\n" +
            "eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq\n" +
            "tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd\n" +
            "C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa\n" +
            "zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB\n" +
            "mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH\n" +
            "V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n\n" +
            "bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG\n" +
            "3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs\n" +
            "J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO\n" +
            "291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS\n" +
            "ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd\n" +
            "AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7\n" +
            "TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n" +
            "-----END CERTIFICATE-----\n" +
            ""
        };

        System.setProperty(ENABLE_CRLDP, "true");
        CertificateValidation.buildCertPath(
            CertificateValidation.getAnchors(CertificateValidation.parseCertificates(pemcas)),
            CertificateValidation.parseCertificates(pems)
        );
    }

    @Test(expected=CertPathBuilderException.class)
    public void failGoogle() throws Exception {
        String pems[] = {
            "-----BEGIN CERTIFICATE-----\n"+
            "MIIEjjCCA3agAwIBAgIIXOvvQRZIbk8wDQYJKoZIhvcNAQELBQAwSTELMAkGA1UE\n"+
            "BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl\n"+
            "cm5ldCBBdXRob3JpdHkgRzIwHhcNMTcwMjIyMDkxODA3WhcNMTcwNTE3MDg1ODAw\n"+
            "WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN\n"+
            "TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOKi5n\n"+
            "b29nbGUuY28uaWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp8I0f\n"+
            "nS09BPFXuu30SQBNKD2jf11p1jCn4NmvH/y1n2AS7M1+PBb3crJm81C5dNzfbgaC\n"+
            "43vb2xCBqPbRGYO9ZDS4quXuqtAxUraNClBSSzWUupNK6spvSTmcSYCQ9bZC84Bm\n"+
            "JP1Sg/jaRIhwKXoLcQPHAJ934R76BCNAb7bimEhA9tiGXdg5OQyMQimzvFUMhu39\n"+
            "IKFOgZgk7AcTMS4umovNJZKcw9sqLUZrvg5plX2cFcO3hBZxnMJcDsREvmauEIYv\n"+
            "pBdWA/UG0dPfl87ciifDbeeVhAoQh09D/awJTa1xmJF02q9LKWxoMTcqNOcKBRuG\n"+
            "IJ/TOaOfrtqHcgJFAgMBAAGjggFZMIIBVTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\n"+
            "KwYBBQUHAwIwJwYDVR0RBCAwHoIOKi5nb29nbGUuY28uaWyCDGdvb2dsZS5jby5p\n"+
            "bDBoBggrBgEFBQcBAQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xl\n"+
            "LmNvbS9HSUFHMi5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29n\n"+
            "bGUuY29tL29jc3AwHQYDVR0OBBYEFIPm0crZLfVla92Qsu2WcfnU2GxyMAwGA1Ud\n"+
            "EwEB/wQCMAAwHwYDVR0jBBgwFoAUSt0GFhu89mi1dvWBtrtiGrpagS8wIQYDVR0g\n"+
            "BBowGDAMBgorBgEEAdZ5AgUBMAgGBmeBDAECAjAwBgNVHR8EKTAnMCWgI6Ahhh9o\n"+
            "dHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IB\n"+
            "AQAk1nDsRDYsnegS/LExzPf/PAGFgHCO6HvMz1o4GIiOGnklxLQ3AD+Oh7y2Y/5V\n"+
            "Wx9zrpfwU2WDVodGY0P0sLMyUJS9DeRV0rUVY6n4h/KipBVlz1seUKP4QtveAvWI\n"+
            "CYKOxUXD51LwQZBpdmIJoai54rQCkmwSsLODWzn570zAtyBFsGGcNzOAt/NOTEkR\n"+
            "s59Bkvi1/XRX5BjUKGtDDf0zCmuFCDaCsHrBY/GVxyvDiKSUoEzelwkVj2t/Cl8F\n"+
            "7mVSSpe18byJvy3pby1xwICbi2I9skrnQrIaE3IVB6qxEZg69nprzJFt7hsjbbGG\n"+
            "QXEUY5QmXjbfIho8NLSaVVlL\n"+
            "-----END CERTIFICATE-----\n"+
            "",
            "-----BEGIN CERTIFICATE-----\n"+
            "MIID8DCCAtigAwIBAgIDAjqSMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT\n"+
            "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\n"+
            "YWwgQ0EwHhcNMTUwNDAxMDAwMDAwWhcNMTcxMjMxMjM1OTU5WjBJMQswCQYDVQQG\n"+
            "EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy\n"+
            "bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"+
            "AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP\n"+
            "VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv\n"+
            "h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE\n"+
            "ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ\n"+
            "EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC\n"+
            "DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7\n"+
            "qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD\n"+
            "VR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov\n"+
            "L2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig\n"+
            "JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ\n"+
            "MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEACE4Ep4B/EBZDXgKt\n"+
            "10KA9LCO0q6z6xF9kIQYfeeQFftJf6iZBZG7esnWPDcYCZq2x5IgBzUzCeQoY3IN\n"+
            "tOAynIeYxBt2iWfBUFiwE6oTGhsypb7qEZVMSGNJ6ZldIDfM/ippURaVS6neSYLA\n"+
            "EHD0LPPsvCQk0E6spdleHm2SwaesSDWB+eXknGVpzYekQVA/LlelkVESWA6MCaGs\n"+
            "eqQSpSfzmhCXfVUDBvdmWF9fZOGrXW2lOUh1mEwpWjqN0yvKnFUEv/TmFNWArCbt\n"+
            "F4mmk2xcpMy48GaOZON9muIAs0nH5Aqq3VuDx3CQRk6+0NtZlmwu9RY23nHMAcIS\n"+
            "wSHGFg==\n"+
            "-----END CERTIFICATE-----\n"+
            ""
        };
        String[] pemcas = {
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G\n" +
            "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp\n" +
            "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1\n" +
            "MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG\n" +
            "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL\n" +
            "v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8\n" +
            "eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq\n" +
            "tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd\n" +
            "C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa\n" +
            "zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB\n" +
            "mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH\n" +
            "V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n\n" +
            "bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG\n" +
            "3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs\n" +
            "J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO\n" +
            "291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS\n" +
            "ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd\n" +
            "AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7\n" +
            "TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n" +
            "-----END CERTIFICATE-----\n" +
            ""
        };

        System.setProperty(ENABLE_CRLDP, "true");
        CertificateValidation.buildCertPath(
            CertificateValidation.getAnchors(CertificateValidation.parseCertificates(pemcas)),
            CertificateValidation.parseCertificates(pems)
        );
    }
}
