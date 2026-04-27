package ee.cyber.cdoc2.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.TestData.ISSUING_CERT_EID_Q_2024E;
import static ee.cyber.cdoc2.auth.TestData.ROOT_CERT_G1E;
import static org.junit.jupiter.api.Assertions.*;

class AuthTokenVerifierV2Test {
    private static final String AUTH_NONCE_URI_PATH = "/key-shares/ff0102030405060708090a0b0c0e0dff";
    private static final String AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QiLCJhbGciOiJSU0FTU0EtUFNTK0FDU1BfVjIifQ.eyJpc3MiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwiX3NkIjpbIlhWTzlYZ1hhYmRqa3h1aUZNQTAxMmtUSEg1WURCX0gyWXlpU21ZWklJbXciXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ZGvyeET3GFN4cFLWRAhgG4JParjJEjv3LCIZyEnV6FpKFxBL7XzDlNysqtdGF3NZaXa5iXnWP8WOMAhDtCLOo2iwIJBfovnKLl5yFgKzoxjZfOB4tFiRkL24DKWdYYCCMIjKSPwfoB_A_IKBKy1xJwH6pUtbc0Zg1LZaOXGMJ_evI4pY3Vrc2VNZV7ej57t5Rz5CY8FCTZfgCHFJ_-upc02w4mjUmwYVTiIZdJMazVusaK9cuzUfo2UjlyBIz7Lj3LvJV_e1mJsm4lX1Swk71JNnxy60WTuT_iTMlG6kp8hFpai0jSVWJG3H1K6tCXU3B0Xh9mphaGWWeE1fYcAzL9PG64pgsch8ej6_YEH8GStulC9GJ_pr1tXID3sW5msYEgu8J3FVb0mIbRiWh8-xZ3oFs8LYP31N6vzlyXLc696euz8Ea1wZjgmB6ivxa9SV5JP5hu4UtqipY-lQPC3Czvzij31sZQW1gMWfSh0cGviQyoVNKtkWOugevCWfNAEVBc6_at-K8xSKBiVQ8evvHp7iyqYaQBQZ3p6F6k_rwnaVULF7Su5_OTnkHfwmJtwXl1-ODZXzp0yi4MVwP_odA72yG1FSZ4qjI3W28PGcl6_hMGeepUC8_-_9Bj1PG9XaaQMk4_scjLWwWi1yzTT4VLUcSl-ApGJMNlJQNb2xc7vpXFaSf7NHlp9Fp8ToOkpfl1rXayM4HzuUxE-_sYjWQhYHPV9lo7oOe8sWUS2BKkbu8M2jdDiN9c3sHDb9TtnADONvapy1CoqoJTZbfFJvkxmaZtSJxPDWztTDQud0WPuziEV_LtlzweJCvfJKnKXAe_a6WtDwDA1wo6-JFK-PM6SyFI7wWytwGlEzgvJlPuqDSfautqFjC07whudkqDQpxDv4aPsoFnHeTzHxKdf-TuZwTKNXxJCoPZK1uo1Yj2nx2wZbCTm-Bfmxq5vKDB4wN-OK2tvk5WZByR1Q-sRMpIEO1ijglRf3KT3ig5jHb6e1W1P4eJcN8AZjrZz1fI3N~WyJQMWZ6M0pkaFRoWG5Eb2pkaDlqVnV3IiwiYXVkIixbeyIuLi4iOiJoYy03cGpsYlBwb0w2bjJIemx2bVVJMlU2dEZIUU1EWUJneHAxNlVFUjdJIn0seyIuLi4iOiJFTy11UG1HYUEzLTRfT1RpdjBJUlNqTy0tc1F1NVU0T2lTMWJjaEdYbGs0In1dXQ~WyJ2R2hHSTlabl9BWVk4bVBfamJuV21nIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9rZXktc2hhcmVzL2ZmMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGUwZGZmP25vbmNlPUFBRUNBd1FGQmdjSUNRb0xEQTROX3ciXQ~";
    private static final String SID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";
    private static final SdJwtWrapper AUTH_TOKEN =
        new SdJwtWrapper(AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL);

    private static final String SIGNATURE_VALIDATION_PARAMS_BASE64URL =
        Base64.getUrlEncoder().encodeToString("""
            {
              "interactionsDigest": "4A3QKDqjmqAtxFj6SiY5kbTpLaDY7pPFp3oDA5qAc/8=",
              "interactionTypeUsed": "confirmationMessageAndVerificationCodeChoice",
              "signature": {
                "serverRandom": "moxzIbuBiNpW0ZwtaeybYTe0",
                "userChallenge": "qynnKC8ldGrnkCdpGKILdV2zcqJb5Wk54ZrUcEuHU5Y",
                "signatureAlgorithm": "rsassa-pss",
                "flowType": "Notification",
                "signatureAlgorithmParameters": {
                  "hashAlgorithm": "SHA-256",
                  "maskGenAlgorithm": {
                    "algorithm": "id-mgf1",
                    "parameters": {
                      "hashAlgorithm": "SHA-256"
                    }
                  },
                  "saltLength": 32,
                  "trailerField": "0xbc"
                }
              }
            }
            """.getBytes(StandardCharsets.UTF_8));

    private AuthTokenVerifierV2 defaultAuthTokenVerifier;

    @BeforeEach
    void setUp() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        defaultAuthTokenVerifier = new AuthTokenVerifierV2(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(
                ROOT_CERT_G1E,
                ISSUING_CERT_EID_Q_2024E
            )),
            true
        );
    }

    @Test
    void verifyTokenSuccess() throws VerificationException {
        TokenVerificationResponse response = defaultAuthTokenVerifier.verify(
            AUTH_TOKEN.getSdJwt(),
            SID_SIGNING_CERTIFICATE_BASE64URL,
            SIGNATURE_VALIDATION_PARAMS_BASE64URL,
            "DEMO",
            "smart-id-demo"
        );

        assertNotNull(response);
        assertTrue(response.nonceUri().getPath().contains(AUTH_NONCE_URI_PATH));
        assertEquals("PNOEE-40504040001", response.identifier().getSemanticsIdentifier());
    }

    @Test
    void verifyTokenFailWhenUnsupportedTyp() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> defaultAuthTokenVerifier.verify(
                AUTH_TOKEN.replaceValue("typ", "UNKNOWN_TYPE"),
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                "DEMO",
                "smart-id-demo"
            )
        );

        assertTrue(exception.getMessage()
                .contains("Unsupported \"typ\""),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyTokenFailWhenUnsupportedAlg() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> defaultAuthTokenVerifier.verify(
                AUTH_TOKEN.replaceValue("alg", "UNKNOWN_ALG"),
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                "DEMO",
                "smart-id-demo"
            )
        );

        assertTrue(exception.getMessage()
                .contains("Unsupported \"alg\""),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyTokenFailWhenIssDoesNotMatchCertificate() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> defaultAuthTokenVerifier.verify(
                AUTH_TOKEN.replaceValue("iss", "etsi/PNOEE-40504040999"),
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                "DEMO",
                "smart-id-demo"
            )
        );

        assertTrue(exception.getMessage()
                .contains("Token identity does not match certificate"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyTokenFailWhenIssDoesNotStartWithEtsi() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> defaultAuthTokenVerifier.verify(
                AUTH_TOKEN.replaceValue("iss", "PNOEE-40504040001"),
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                "DEMO",
                "smart-id-demo"
            )
        );

        assertTrue(exception.getMessage()
                .contains("Only identifiers starting with etsi"),
            "Actual message: " + exception.getMessage());
    }
}