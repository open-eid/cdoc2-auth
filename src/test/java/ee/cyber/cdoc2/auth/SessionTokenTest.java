package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SessionTokenTest {
    private static final String SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6IkFmZWZGYjZGV0pYdHdBeWk3VlZzaUlFSG9uNWFpWVh6Wk1KZlVsc0o0SS9yWkpMN1dNb3VZOHc5Nm1EUmhCckdHOHV4ZGdzSXk1VXJTV1IrZHN0R1N3PT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiUTlXNjBWTWtEbmgwNDlneW5ZMWhuODlLMm03U0FvZE5Icm04YlgyZmF4c2FNZ2x4ZnA1U21uc3BXOVA1a3BmUDY5Z0pTb1dBZVBra3JTTDRFaFhtaUNjQ2ZIM05zbjFNUGVXZ09KWGpwb2RhQ1ExdW9kZ0dvMlBCL2JvWmQxY2JGaUU5eUwzcDVaaDU1UUVEblQzMmwzUERSSUNDMW1HbGJTR0JueXJ2SGN6d0EwRVQ0dTJ5SG9GQ2ZOUHYzcld0Rmd1bEZOTk4ra2NnTTBUbzFsZFlvb0Z4K1FDRzhEb21JZXJNeVIzcEc3bExsQWJmN2hYbnIrakNacUNkbEp5bTBlRmtNQjV6d1RQaHRIem10TVp4ZTNLL1A3NHZjMm9xMERJaXNQK1dOckZTcUZsY21EVisxMTFLcGp2WDRHV09zaHZoNE8vVVVTdk9Ydk91WUIxOXVERktWbTNFZVhnV2NFakNJNFpPQkJSOFBBRUxmZ1hkYnJVaXJGYzZCaXp6RXI0ZzA2d0lmaXdOZkQ1MG5wSTZmcXIxaFJ4ZFpBMEdNRkl1OVdYcTVhNGpMaytHa2xXdFhMQ3R6RnhodDIwQ0hlVzIyNGw1MzVpY0hOTFFXVkhlSTZ4SzhqNmlDR3pHYytRV1lONHNhNTFEdnprSGhOM2RWN0VpOUZ3ZTFRa3N4T0J5UEtaZEhLK1BUbUdSTWhTR21nUzBzTWQrcFViYXNmVCtQTk92Z1daQVJxeXZOSlludFlHMlJPTzBZOEZqK1F0eGZNeTU2cHFCVkV1Q21BSlBNY0gvY1BkWnJIZWFyMXZqQm9WRjU5cmFlY0R0QmpFcTJOek9TVGlZbXEwOWZRNzB5WTJ4amZ2OTZxRGY4c0diMFVqamZuL3h0M05KejQrdG9VRThzQSs0a0NQc0E3UGNWcldwL2dHRTlIZ3FSdHRPWTc5cHRIai9wWGY1VnJ5ZEhVZzlGcUtkMExRWk55YWZRZks5U2JkU2lyWTRqc2YrNkRhUllqZzNKaE9yMHhDVkJtQVY2WTQ5V29xM1hyeWw2R0JsOXhJODNrTTFVZ0h4QzM5ayt5N1lrQzRhelNUdjFFQmUxTnB5RkNaNEpmeU5vQnpZeHZYaCtaNDJXSVIrejdzLzVuK050UWpEdVRwM2RBNGtZMEwrY3VRRnl2MVhNSVA5ZC9zeDJlM25JNnJGMUwwc01pVHpFRlZ1YzRrSDdhSWZBQ2hmOGpKd25aN1UvMHg3NGUvQU9oNFExajBpbEp4dkdmN2dwbXBFQnRDS1F2cVNqMXl6dkNCVkNoZWhuRThVeFozTjZncTRZTVE4M1phZU96V0l6eHFWbS94QWsvU2g1bG93Y2xOeCIsInNlcnZlclJhbmRvbSI6InV3d055UnRkcHNuZ3IwTVZPcWZCUHoxQSIsInVzZXJDaGFsbGVuZ2UiOiJ4Ny1EMTQydUdoMURHNFhCRjZMeGpFV2p0bVVybGpZdWtXdnQtYWlrRVhRIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJ0TWNYNXpITldRQlJ1YzdLb085NVVtazA4VDFzT2dTVEM2eWU2aElfRjVrIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3NzY4NjA4NDksImlhdCI6MTc3Njc3NDQ0OSwiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.XoskNyRWqbDul20UoR1USM2d2zuzZXw6zCVFk9DeFCd8ucSGKtp25BsKn_Ea67_5YoL8ULjQRxuSsyolFei5-Q~WyJ1aTNqcUhmWDBvdzU2QkRmQ1JhUEZnIiwiYXVkIixbeyIuLi4iOiI3SkRELUVMUkN3clVUSXlxclo0LTQ5MTZaQVNMNW9yc3ZtRk1NSjJtUHBvIn0seyIuLi4iOiIxVjhwMzU1VGFPTTZWY2tNdzlVZUxxRkFwNHpDajctQ1haVHlQZ1B3dlpRIn1dXQ~WyJYcm54aHYxQnJHUHVLSWZpWlV6eWpRIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3Nlc3Npb25fbm9uY2VfMS8xMjM0NTY3ODkwOTg3NjU0MzIxIl0~WyIyV2JPelRkWWcyY0cxa3h1QTV4Z2Z3IiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3Nlc3Npb25fbm9uY2VfMi85ODc2NTQzMjEyMzQ1Njc4OSJd~";
    private static final String SID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";

    //TEST of SK ID Solutions EID-Q 2024E
    //Validity end: 2039.05.31 13:01:21
    //https://www.skidsolutions.eu/resources/certificates/
    private static final X509Certificate ISSUING_CERT =
        X509CertUtils.parse(Base64.getDecoder().decode(
            "MIIDxzCCAymgAwIBAgIUIJ92Wg42THMIC1QSOpWpxv3+22AwCgYIKoZIzj0EAwMw" +
                "bjELMAkGA1UEBhMCRUUxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzEXMBUG" +
                "A1UEYQwOTlRSRUUtMTA3NDcwMTMxKTAnBgNVBAMMIFRFU1Qgb2YgU0sgSUQgU29s" +
                "dXRpb25zIFJPT1QgRzFFMB4XDTI0MDYwMzEzMDEyMloXDTM5MDUzMTEzMDEyMVow" +
                "cTEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyNEUx" +
                "FzAVBgNVBGEMDk5UUkVFLTEwNzQ3MDEzMRswGQYDVQQKDBJTSyBJRCBTb2x1dGlv" +
                "bnMgQVMxCzAJBgNVBAYTAkVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE9tnu4Hr6" +
                "oZ3virQ52FkQ8zgSnRLjSpbr7y6hjaI5ZtvFTssL3aOgvULxOvV5x+HtOmcGVfmh" +
                "vy9YtoJENq/E3pFFOkofrkX3O/RVLdtPpiVahYa89HCgqoEVDln5ILMWo4IBgzCC" +
                "AX8wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTiHN5j3L74hH4BOy5L" +
                "gLHhf9Xx5jBsBggrBgEFBQcBAQRgMF4wOAYIKwYBBQUHMAKGLGh0dHA6Ly9jLnNr" +
                "LmVlL1RFU1RfU0tfUk9PVF9HMV8yMDIxRS5kZXIuY3J0MCIGCCsGAQUFBzABhhZo" +
                "dHRwOi8vZGVtby5zay5lZS9vY3NwMHAGA1UdIARpMGcwBgYEVR0gADBdBgNVHSAw" +
                "VjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNv" +
                "dXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMDkGA1UdHwQy" +
                "MDAwLqAsoCqGKGh0dHA6Ly9jLnNrLmVlL1RFU1RfU0tfUk9PVF9HMV8yMDIxRS5j" +
                "cmwwHQYDVR0OBBYEFLAkFxmI42b4zShYZXtNFNiSZk9rMA4GA1UdDwEB/wQEAwIB" +
                "BjAKBggqhkjOPQQDAwOBiwAwgYcCQXIdNKdyvEhtB+48QZEXi2dgXiAjYD7O0D4f" +
                "4Y2KPajqrRcwd9KEYr/yFjK0JWYHqRFN47tMdYhisy7aFySEWmKcAkIBUbTJeSbo" +
                "XAKBT9+j2zQduKv8Eqb/AIQybcVXyP23w+1ujNkcQZMkok41nGOH2YNRP7aGsCZa" +
                "7Wy8pf2lw6EcfyU="
        ));

    //TEST of SK ID Solutions ROOT G1E
    //Validity end: 2041.07.09 13:47:14
    //https://www.skidsolutions.eu/resources/certificates/
    private static final X509Certificate ROOT_CERT =
        X509CertUtils.parse(Base64.getDecoder().decode(
            "MIICxDCCAiagAwIBAgIQGjWemJjC5ORg6CkyNQ5DzTAKBggqhkjOPQQDBDBuMQsw" +
                "CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh" +
                "DA5OVFJFRS0xMDc0NzAxMzEpMCcGA1UEAwwgVEVTVCBvZiBTSyBJRCBTb2x1dGlv" +
                "bnMgUk9PVCBHMUUwHhcNMjEwNzA5MTA0NzE0WhcNNDEwNzA5MTA0NzE0WjBuMQsw" +
                "CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh" +
                "DA5OVFJFRS0xMDc0NzAxMzEpMCcGA1UEAwwgVEVTVCBvZiBTSyBJRCBTb2x1dGlv" +
                "bnMgUk9PVCBHMUUwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACGx6ye24WAORL1" +
                "8N0SquoI3TTJ3dd2EcZLs+wZY0XWYzPa0S4o8BKZQTCDbXz9O2x94hpdAjZ4S3Q2" +
                "N7DAvQ0FfAHmM2JotR4UnYvxYv4JxJHpoRvrQoXOXdqO/wMymiPKTXHPFQz6nxxa" +
                "ORjy8xsrQeIdrTLj3c+HDVBRA5yE/IXed6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAO" +
                "BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOIc3mPcvviEfgE7LkuAseF/1fHmMB8G" +
                "A1UdIwQYMBaAFOIc3mPcvviEfgE7LkuAseF/1fHmMAoGCCqGSM49BAMEA4GLADCB" +
                "hwJBNDZ3R6qmJqL5bQf01oT369DEGcLhr2vA00nRZSqeaaLMfq+RQW8aYl0njfIZ" +
                "JAC6q6IJklpH5IyYrcZ29tcBrxECQgFH5aw8ZORororrLDPl1yY2RgsCO1SFoDh5" +
                "eMEaKVtRKNSG1jLzfgiZJOdtIj/h/l/4oDc5DrDDY6kbAnl4M5pDKw=="
        ));

    private static final String AUTH_SERVER_WELL_KNOWN_JWK_JSON = """
        {
          "kty" : "EC",
          "crv" : "P-256",
          "x" : "gQT1_Ud-qCJZL-9zm_HBb2v_L1-ermyIo5IohV4Svyw",
          "y" : "Y0DLwH5fHZSxwTN7Ndp7VrEys3yqdMQ_5cfmAYFOeEk",
          "kid" : "ec-key-2026"
        }""";

    private SessionTokenVerifier defaultSessionTokenVerifier;

    @BeforeEach
    void setUp() throws Exception {
        defaultSessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ROOT_CERT, ISSUING_CERT)),
            true
        );
    }

    @Test
    void verifyTokenSuccess() throws Exception {
        String sdJwtWithFilteredDisclosures = SessionTokenHelper.discloseByClaimValue(
            SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL, "session_nonce_2"
        );

        URI verifiedNonceUri = defaultSessionTokenVerifier.getVerifiedSessionNonce(
            sdJwtWithFilteredDisclosures,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
        );

        Assertions.assertNotNull(verifiedNonceUri);
    }

    @Test
    void verifyTokenFailWithMoreThanOneAudElementDisclosed() {
        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> defaultSessionTokenVerifier.getVerifiedSessionNonce(
                SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            )
        );

        assertTrue(exception.getMessage()
            .contains("More than one element in disclosed aud array")
        );
    }

    @Test
    void verifyTokenFailWithIssuingCertMissing() throws Exception {
        SessionTokenVerifier sessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ROOT_CERT)),
            true);

        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> sessionTokenVerifier.getVerifiedSessionNonce(
                SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            )
        );

        assertTrue(exception.getMessage()
                .contains("Certificate validation error"),
            "Actual message: " + exception.getMessage());
    }
}
