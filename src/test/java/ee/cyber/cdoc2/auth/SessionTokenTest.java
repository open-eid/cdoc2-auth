package ee.cyber.cdoc2.auth;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static org.junit.jupiter.api.Assertions.*;

public class SessionTokenTest {
    private static final String SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL =
        "eyJraWQiOiJlYy1rZXktMjAyNiIsInR5cCI6InZuZC5jZG9jMi5zZXNzaW9uLXRva2VuLnYyK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJycENoYWxsZW5nZSI6InJrZ2s0cTE2eTYxbFJoRVJOcVZVdzBpdEhXZ3MzbWZMS3Y5cEQ2Z2xCdDl0ZDJRbmVhd1lLM0ZGOHFkMXBSakdDbnlyZ3NWTmprSXJ3T3NuZXkzOXl3PT0iLCJzdWIiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwic2lnbmF0dXJlIjp7InZhbHVlIjoiSlhtVmgwWlZqdFRUZHFFaHlET1NCejNMLyt4UHZPTGF1WXVmbmUydS8wRkVuZ0loQ0g4WEl6ZW5zazhsa3BLZlNxYVBjSzZReDF5bVZpdGM1YUNWY1N6bjRzUVV3SW5OODBXVEd1UTZtNTNESGdXWnFnS3NabHErSDcwamxxMXZSUE0vS3UwVEJIK01GRkhOeWp5SWZWN0MwOVMyK2pCbm1kYWEzM0FaNCtnOS9FNWVnL1p6QktHQWNnQmFyU01lYVpOdXNXQWNrdlJBQ3Y1WXlidUVYK0JSM3NYMXA0U09XNWdMT2lPOUwzaWtzVXNzVFp2K3MyVU9kbFVZTFpTVGVrWWIrYXFQRkdzODdjY1FQUmZuRlRWV1EwZ0pvVENWVG1lWWdXazA5MjZMOVREaUlQZlJ5cWxBbkNQNWRPZGlxRmNLSXFOZ3d4Z0RyZmlITmJ2R3hhQ3hGeVdJd2R2ekdmNEZPa3VMaVdndXVPQVo3YlgxVzIwQnNlZjFHTnRTQUdBVlRMbmJsMUNiOC8rT2dwRU52WXM2UUtxdXdiRlZHTDhzRDJEc1czNXZodllXdkJJN0tVK1NxODBnSDhURkFvdzNiN3QzOU80UEJmbVMzOUJrRTgxMW9mK2MwSFpNMXhJd3NTajZVVkR3bkNLOHYwZ1BKOGZMMmo5NDIrVUVVRUpQUEJaNmo1TWcrRmxBb1ZFR2pHakp1cDF3NVdCTFVBYTl1blRiNWp5UGtFUW84clVrS1Y0ZmQ0b21XTEpobGJXcmNYWlh5ZndrRGhJR211Uzh4Z2w2NSs0anMyVTI4THRDQzJYSjhlNWJhWm9rNWQ0Q2VVbFJvUjErbmIvZTg0cmthOUtPOUV6MGZHVmRlSmc0MFZhYTBWb2xBeDkxYVVmUS9mV0tpRXMxbHBOR0EyMG55cytJSTU3QWZqRDdkdGJxTzZaNzBXbEpUenMrREE0SHJEcXFQQ0ZRbVRmc2VhWFFOOVBxK3RnRFZqdFc1TlVRMTg4UlhSZ2pvalp4ZitCT2piVDJ6b0xxMS96VmdETkZTaW1kSElLQitJYUlwaDB5LzZHWWFGb0p2eERsRm9YSzhwUnU4My8vdGNnZmFuN1gzUWZKMnF1WTN3T2VDUHN5dmM1TklNdHRJdnhHRFlTdWI3QW9Ta3Z4eGFsdHg3Vy9FWEJWVmNDaWROZE1YM1ErZ2VNQlMzeS9NbEE3M0pqMXQxb1N6UmZxdFFpY2tYd0w3bmYrNXB5RzY2eUVFb1ZaZ1dVdE0zMUptSE9LVUF6UGVFOSthd2xRUjd3NXJSeitFemJ1MitLdlY2N1V4NFdXVG5JY0pOUG4rRkhOKzE1V1ZlTVhuRlhxVHZOSiIsInNlcnZlclJhbmRvbSI6InNWOXdsS3RaZTV0cjBnTjlpZXRQU0ovVCIsInVzZXJDaGFsbGVuZ2UiOiJmeWtaTHJmU2tsMW9uMXBITlBrZEFZUS1pekd0N1ZGeWN6eUNDM2x4cmlrIiwic2lnbmF0dXJlQWxnb3JpdGhtIjoicnNhc3NhLXBzcyIsImZsb3dUeXBlIjoiTm90aWZpY2F0aW9uIiwic2lnbmF0dXJlQWxnb3JpdGhtUGFyYW1ldGVycyI6eyJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm1hc2tHZW5BbGdvcml0aG0iOnsiYWxnb3JpdGhtIjoiaWQtbWdmMSIsInBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYifX0sInNhbHRMZW5ndGgiOjMyLCJ0cmFpbGVyRmllbGQiOiIweGJjIn19LCJpc3MiOiJodHRwczovL2Nkb2MyLWF1dGgtc2VydmVyLmVlIiwic2NoZW1lTmFtZSI6InNtYXJ0LWlkLWRlbW8iLCJzaWduYXR1cmVQcm90b2NvbCI6IlJTQVNTQS1QU1MrQUNTUF9WMiIsIl9zZCI6WyJuTEpHdS05X3lKMmlEOGhrRXU5Ym5yc0EzUHJ5Y3UwVVE1WXQ5UENTNV8wIl0sImludGVyYWN0aW9uc0RpZ2VzdCI6Im9sSk43T1hVdmZ5MWJVUE51NzEyWDNBN01PbTFCWGlXdGxBbXYrdWJJejA9IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJleHAiOjE3NzY4NzI1MjksImlhdCI6MTc3Njc4NjEyOSwiaW50ZXJhY3Rpb25UeXBlVXNlZCI6ImNvbmZpcm1hdGlvbk1lc3NhZ2VBbmRWZXJpZmljYXRpb25Db2RlQ2hvaWNlIiwicnBOYW1lIjoiREVNTyJ9.5ORVwgy0tMpX5tdwZmhnnQK_H4ngB-duofWj2OYCrJU5kL5dUvJRSeiC5QLbuzH-8gk08b5asqIW9lWNEErAuw~WyJONGFScHVxNTVRZzh6LTVxS3dlRURBIiwiYXVkIixbeyIuLi4iOiIxM19rVmNGcXF3M0tycllRaUpnUEJ4Qm1zOG1rY0puMmtnNWZBRGc4aUlFIn0seyIuLi4iOiJkaG9VbVZod0c2TEJIbkwyMHJxbDZFTkVFdjlfdHBPOFo4aUVFbmVESmhjIn1dXQ~WyJEWm0yWVA4NTkwMHdmZGlKV2RxV05nIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3Nlc3Npb25fbm9uY2VfMS9XVHE5Z0FrdjVfVUppb0VMWERxT0FBIl0~WyJMb2dqR24xc21ZNmxpWllEZnh4OGhnIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3Nlc3Npb25fbm9uY2VfMi9uclZjU0VjSHVXdDJTS2Zqa01tNlJRIl0~";
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

    private static final Clock CLOCK_SESSION_TOKEN_NOT_EXPIRED =
        Clock.fixed(Instant.parse("2026-04-22T12:30:00Z"), ZoneOffset.UTC);
    private static final Clock CLOCK_SESSION_TOKEN_EXPIRED =
        Clock.fixed(Instant.parse("2026-04-23T12:30:00Z"), ZoneOffset.UTC);
    private static final Clock CLOCK_SESSION_TOKEN_INVALID_ISSUANCE =
        Clock.fixed(Instant.parse("2026-04-21T12:30:00Z"), ZoneOffset.UTC);

    private SessionTokenVerifier defaultSessionTokenVerifier;

    @BeforeEach
    void setUp() throws Exception {
        defaultSessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ROOT_CERT, ISSUING_CERT)),
            true,
            CLOCK_SESSION_TOKEN_NOT_EXPIRED
        );
    }

    @Test
    void verifyTokenSuccess() throws Exception {
        String sdJwtWithFilteredDisclosures = SessionTokenDisclosureHelper.discloseAudByClaimValue(
            SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL, "session_nonce_2"
        );

        TokenVerificationResponse response =
            defaultSessionTokenVerifier.verify(
                sdJwtWithFilteredDisclosures,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            );

        assertNotNull(response);
        assertEquals("PNOEE-40504040001", response.identifier().getSemanticsIdentifier());
    }

    @Test
    void verifyTokenFailWithMoreThanOneAudElementDisclosed() {
        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> defaultSessionTokenVerifier.verify(
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
            CLOCK_SESSION_TOKEN_NOT_EXPIRED
        );

        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> sessionTokenVerifier.verify(
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
    void verifyTokenFailWhenTokenExpired() throws Exception {
        SessionTokenVerifier sessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ISSUING_CERT)),
            true,
            CLOCK_SESSION_TOKEN_EXPIRED
        );

        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> sessionTokenVerifier.verify(
                SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            )
        );

        assertTrue(exception.getMessage()
                .contains("Token has expired"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyTokenFailWhenTokenIssuedInFuture() throws Exception {
        SessionTokenVerifier sessionTokenVerifier = new SessionTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(ISSUING_CERT)),
            true,
            CLOCK_SESSION_TOKEN_INVALID_ISSUANCE
        );

        VerificationException exception = Assertions.assertThrows(VerificationException.class,
            () -> sessionTokenVerifier.verify(
                SESSION_TOKEN_WITH_ALL_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                List.of(JWK.parse(AUTH_SERVER_WELL_KNOWN_JWK_JSON))
            )
        );

        assertTrue(exception.getMessage()
                .contains("Invalid token issuance time"),
            "Actual message: " + exception.getMessage());
    }
}
