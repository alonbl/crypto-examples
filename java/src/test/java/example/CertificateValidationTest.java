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
            ""
        };
        String[] pemcas = {
            "-----BEGIN CERTIFICATE-----\n"+
            "MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT\n"+
            "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\n"+
            "YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG\n"+
            "EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg\n"+
            "R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9\n"+
            "9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq\n"+
            "fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv\n"+
            "iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU\n"+
            "1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+\n"+
            "bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW\n"+
            "MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA\n"+
            "ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l\n"+
            "uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn\n"+
            "Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS\n"+
            "tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF\n"+
            "PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un\n"+
            "hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV\n"+
            "5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==\n"+
            "-----END CERTIFICATE-----\n"+
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
            "-----BEGIN CERTIFICATE-----\n"+
            "MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT\n"+
            "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\n"+
            "YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG\n"+
            "EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg\n"+
            "R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9\n"+
            "9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq\n"+
            "fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv\n"+
            "iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU\n"+
            "1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+\n"+
            "bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW\n"+
            "MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA\n"+
            "ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l\n"+
            "uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn\n"+
            "Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS\n"+
            "tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF\n"+
            "PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un\n"+
            "hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV\n"+
            "5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==\n"+
            "-----END CERTIFICATE-----\n"+
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
            "-----BEGIN CERTIFICATE-----\n"+
            "MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs\n"+
            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"+
            "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"+
            "ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL\n"+
            "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\n"+
            "LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug\n"+
            "RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm\n"+
            "+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW\n"+
            "PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM\n"+
            "xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB\n"+
            "Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3\n"+
            "hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg\n"+
            "EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF\n"+
            "MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA\n"+
            "FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec\n"+
            "nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z\n"+
            "eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF\n"+
            "hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2\n"+
            "Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe\n"+
            "vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep\n"+
            "+OkuE6N36B9K\n"+
            "-----END CERTIFICATE-----\n"+
            ""
        };

        System.setProperty(ENABLE_CRLDP, "true");
        CertificateValidation.buildCertPath(
            CertificateValidation.getAnchors(CertificateValidation.parseCertificates(pemcas)),
            CertificateValidation.parseCertificates(pems)
        );
    }
}
