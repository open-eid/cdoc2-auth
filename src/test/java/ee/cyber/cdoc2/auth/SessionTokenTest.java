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
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6IjRVU1k2OXh1S29uRmUydy9XZmFnb0JlSTYxOXR2cWtrc3FnNWVxUzNMeHJ6dVFObkNOak12WkpIaHI0NDlmYnd4MmZJTzhYQTcwcUhTbk1TQk5ONFJ3PT0iLCJfc2QiOlsieFBoM0FjeTJrb05VSXNzcEFSZThfLTRPa255bjR5VGhNMDRkUUVPdTJqVSJdLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwiaW50ZXJhY3Rpb25zRGlnZXN0Ijoib2xKTjdPWFV2ZnkxYlVQTnU3MTJYM0E3TU9tMUJYaVd0bEFtdit1Ykl6MD0iLCJzaWduYXR1cmUiOnsidmFsdWUiOiJLUFBTZ2U5Y0N2NXNlSm8xMWVwLzNwNXdiZ1A2RERaSXZYcFZyWVNIcFJ3SXFPZFhpRmlXWThabDgybTNuVHdpd0Q4YnFrUFh4akJRWjFuNjdwL0RTMnhvYTR4OFduQUtNRXNLT3gwTmtrb1VsVHhrTnc1bmFHUnlvY01zZ2JYR0ZLOFR5NDNWei9yK2VHMlNHdVlKdkJnSFRuUnBkUGt5cGZRYkMzTHFxbkJLR2JzdExmMlk2Lys5VURVUHU3L2Izd2NCdWozZDhnajY4eUl4ZjNEenNmWE1JOTZqek1xNXhGT0VqVitqNW9nK3Jkc3pKU0FkOTdKem9JTU85Q0hGemg2eU11U0I2WjFyS3VRUTRTRmFwSUg2OHd6V1hMOWErZkhBNzlFZ0tEMjFhd09DL1dyRlBXVHEySmlzV2ZMUW9lL1RCUmhiQktXQnpnUStIZllMV2xqWDAza1RUcHhERTJidThzR1E5c1lYQWhDTVBmeW9TZWVjUXlocFhDVVhHQjBqQThpRzBDSHFZeWsrZXV4MGVmdzNPb2VGejNtbmg1aUJ4T04yTm5yWmF2anY0WTJpQnhVTGlOQzVzVEh5eUtKQ0w1aFJIQmtoMlJsZll3RlJXUWtSSjJUb3FjemhjemJxNjNlK05KQnNuSzVWMTVsZUZxNkpZZCs2ZXduZG1rL2d4TUdhamdKN2VtTGFNTGRTamxOalZVZnFxczVPV3NYQ3Y1NktjS3BCdmdCNEpIVmg4NVE4azU0L1RaUG1TM1BhbW85eFlUcTg4ckFGMllHbnFnSktZcFRxOVdoeTdEM3gzTWEvdnFMbWIxZU50Y1QrVDFpUGs5eTdWcENmR0JGbm1yTngyMGRmeXJwa2t5dXB3SjNyTThhVHpORTNpaEdWSTVhdkFLanFlU25GVy9laTd6WjB3R1RXeUFvWUJxWHdqdFRzRno5dzYwWEdpY2p0MWgyTHU2WWt3Sk9VT25tUGJjOFhBNFVvbDZvUWRWNmZMWEFReUIwamtjTW1ha09rZVljZVNUd0FONlExYk5jRGhmUUdLa0diY1VCZWRLRisxaW4yQ2RvcGllaDVINGE2Y2hiZ0laL3JHTXZ3eUVoRm1sN3VwYmJpVUR0YU5qdFNtdjk0NE82aEhTVEo1amFPRmNaKzRuM1RvSnExWlBZb3BtS0ljSytCUHVhQXprb3cveURreGlOMHZOemNURTVHYTVaby92MURvTVRhNHpHcEtlVmZ5cWM5SHg5Q0g5T2h0NjVVb1piWCthNDc3cXU5OUtvUHlkWlNKNzlpS1FobnBZeUdwbm5rZ0EyWXZDbEdGT2RkcElFZGcydmh2Q3NxU1UwZnhEM0h3dFpSIiwic2VydmVyUmFuZG9tIjoiYWxwU1B1cGU1dXd3UW4zUThCYkF2ZUt4IiwidXNlckNoYWxsZW5nZSI6InRyemkzenBQXzRvaW9xMWFMVjUtNWhMb3RMQXdjOEsxSHFIWVA1b1Rld3ciLCJzaWduYXR1cmVBbGdvcml0aG0iOiJyc2Fzc2EtcHNzIiwiZmxvd1R5cGUiOiJOb3RpZmljYXRpb24iLCJzaWduYXR1cmVBbGdvcml0aG1QYXJhbWV0ZXJzIjp7Imhhc2hBbGdvcml0aG0iOiJTSEEtMjU2IiwibWFza0dlbkFsZ29yaXRobSI6eyJhbGdvcml0aG0iOiJpZC1tZ2YxIiwicGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiJ9fSwic2FsdExlbmd0aCI6MzIsInRyYWlsZXJGaWVsZCI6IjB4YmMifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9jZG9jMi1hdXRoLXNlcnZlci5lZSIsInNpZ25hdHVyZVByb3RvY29sIjoiUlNBU1NBLVBTUytBQ1NQX1YyIiwiZXhwIjoxNzc2ODQ0MDQ4LCJpYXQiOjE3NzY3NTc2NDgsImludGVyYWN0aW9uVHlwZVVzZWQiOiJjb25maXJtYXRpb25NZXNzYWdlQW5kVmVyaWZpY2F0aW9uQ29kZUNob2ljZSJ9.9E2LMkePde7bFf6XNPXLONN4a1QtF9objaDTEGgySP2XYI64nBWewPff3y-yMAtiWvkWEdxg9vwUCUDCGBsGJg~WyJWRTZkWXliZ0pCYVQ4SmxJTnkwcDlRIiwiYXVkIixbeyIuLi4iOiJiSFpMX2hvVU5hSWV1SThpT3dudHBXTUF2aElncjVDV3l2Z0Y1MXVPU3hjIn0seyIuLi4iOiJZTmhiRVBCWlZpYUc1dVVqVXVzZDlSZXNVWWlnMmt1US1vOUdLUXd4VmdRIn1dXQ~WyJvcUNFb3R2dWY4QUR1eUp5dFNCUHd3IiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3Nlc3Npb25fbm9uY2VfMS8xMjM0NTY3ODkwOTg3NjU0MzIxIl0~WyJZcXppTEdLRHo3c05TTjRvODhVa3dnIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3Nlc3Npb25fbm9uY2VfMi85ODc2NTQzMjEyMzQ1Njc4OSJd~";
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
            true,
            "smart-id-demo",
            "DEMO"
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
            true,
            "smart-id-demo",
            "DEMO"
        );

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

    @Test
    void verifyTokenFailWithIncorrectSchemeName() throws Exception {
        SessionTokenVerifier sessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ROOT_CERT, ISSUING_CERT)),
            true,
            "UNKNOWN_SCHEME",
            "DEMO"
        );

        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> sessionTokenVerifier.getVerifiedSessionNonce(
                SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            )
        );

        assertTrue(exception.getMessage()
                .contains("Invalid SID signature"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyTokenFailWithIncorrectRpName() throws Exception {
        SessionTokenVerifier sessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ROOT_CERT, ISSUING_CERT)),
            true,
            "smart-id-demo",
            "UNKNOWN_RP"
        );

        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> sessionTokenVerifier.getVerifiedSessionNonce(
                SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            )
        );

        assertTrue(exception.getMessage()
                .contains("Invalid SID signature"),
            "Actual message: " + exception.getMessage());
    }
}
