package ee.cyber.cdoc2.auth;

import com.nimbusds.jose.util.X509CertUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthTest {

    static Logger log = LoggerFactory.getLogger(AuthTest.class);

    // SID demo env identifier 30303039914 that automatically authenticates successfully
    private static final String SID_DEMO_IDENTIFIER = "30303039914";

    // SID demo env cert for 30303039914 (OK, TESTNUMBER) that automatically authenticates successfully
    private final String sidDemoCertStr = """
        -----BEGIN CERTIFICATE-----
        MIIIIjCCBgqgAwIBAgIQUJQ/xtShZhZmgogesEbsGzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZ
        QVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlE
        LVNLIDIwMTYwIBcNMjQwNzAxMTA0MjM4WhgPMjAzMDEyMTcyMzU5NTlaMGMxCzAJBgNVBAYTAkVFMRYwFAYDVQQDDA1URVNU
        TlVNQkVSLE9LMRMwEQYDVQQEDApURVNUTlVNQkVSMQswCQYDVQQqDAJPSzEaMBgGA1UEBRMRUE5PRUUtMzAzMDMwMzk5MTQw
        ggMiMA0GCSqGSIb3DQEBAQUAA4IDDwAwggMKAoIDAQCo+o1jtKxkNWHvVBRA8Bmh08dSJxhL/Kzmn7WS2u6vyozbF6M3f1lp
        XZXqXqittSmiz72UVj02jtGeu9Hajt8tzR6B4D+DwWuLCvTawqc+FSjFQiEB+wHIb4DrKF4t42Aazy5mlrEy+yMGBe0ygMLd
        6GJmkFw1pzINq8vu6sEY25u6YCPnBLhRRT3LhGgJCqWQvdsN3XCV8aBwDK6IVox4MhIWgKgDF/dh9XW60MMiW8VYwWC7ONa
        3LTqXJRuUhjFxmD29Qqj81k8ZGWn79QJzTWzlh4NoDQT8w+8ZIOnyNBAxQ+Ay7iFR4SngQYUyHBWQspHKpG0dhKtzh3zELIk
        o8sxnBZ9HNkwnIYe/CvJIlqARpSUHY/Cxo8X5upwrfkhBUmPuDDgS14ci4sFBiW2YbzzWWtxbEwiRkdqmA1NxoTJybA9Frj6
        NIjC4Zkk+tL/N8Xdblfn8kBKs+cAjk4ssQPQruSesyvzs4EGNgAk9PX2oeelGTt02AZiVkIpUha8VgDrRUNYyFZc3E3Z3Ph1
        aOCEQMMPDATaRps3iHw/waHIpziHzFAncnUXQDUMLr6tiq+mOlxYCi8+NEzrwT2GOixSIuvZK5HzcJTBYz35+ESLGjxnUjb
        ssfra9RAvyaeE1EDfAOrJNtBHPWP4GxcayCcCuVBK2zuzydhY6Kt8ukXh5MIM08GRGHqj8gbBMOW6zEb3OVNSfyi1xF8MYAT
        KnM1XjSYN49My0BPkJ01xCwFzC2HGXUTyb8ksmHtrC8+MrGLus3M3mKFvKA9VatSeQZ8ILR6WeA54A+GMQeJuV54ZHZtD208
        5Vj7R+IjR+3jakXBvZhVoSTLT7TIIa0U6L46jUIHee/mbf5RJxesZzkP5zA81csYyLlzzNzFah1ff7MxDBi0v/UyJ9ngFCeL
        t7HewtlC8+HRbgSdk+57KgaFIgVFKhv34Hz1Wfh3ze1Rld3r1Dx6so4h4CZOHnUN+hprosI4t1y8jorCBF2GUDbIqmBCx7Dg
        qT6aE5UcMcXd8CAwEAAaOCAckwggHFMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgSwMHkGA1UdIARyMHAwZAYKKwYBBAHOHw
        MRAjBWMFQGCCsGAQUFBwIBFkhodHRwczovL3d3dy5za2lkc29sdXRpb25zLmV1L3Jlc291cmNlcy9jZXJ0aWZpY2F0aW9uLX
        ByYWN0aWNlLXN0YXRlbWVudC8wCAYGBACPegECMB0GA1UdDgQWBBQUFyCLUawSl3KCp22kZI88UhtHvTAfBgNVHSMEGDAWgB
        SusOrhNvgmq6XMC2ZV/jodAr8StDATBgNVHSUEDDAKBggrBgEFBQcDAjB8BggrBgEFBQcBAQRwMG4wKQYIKwYBBQUHMAGGHW
        h0dHA6Ly9haWEuZGVtby5zay5lZS9laWQyMDE2MEEGCCsGAQUFBzAChjVodHRwOi8vc2suZWUvdXBsb2FkL2ZpbGVzL1RFU1
        Rfb2ZfRUlELVNLXzIwMTYuZGVyLmNydDAwBgNVHREEKTAnpCUwIzEhMB8GA1UEAwwYUE5PRUUtMzAzMDMwMzk5MTQtTU9DSy
        1RMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTkwMzAzMDMxMjAwMDBaMA0GCSqGSIb3DQEBCwUAA4ICAQCqlSMpTx+/n
        wfI5eEislq9rce9eOY/9uA0b3Pi7cn6h7jdFes1HIlFDSUjA4DxiSWSMD0XX1MXe7J7xx/AlhwFI1WKKq3eLx4wE8sjOaacH
        nwV/JSTf6iSYjAB4MRT2iJmvopgpWHS6cAQfbG7qHE19qsTvG7Ndw7pW2uhsqzeV5/hcCf10xxnGOMYYBtU7TheKRQtkeBiP
        Jsv4HuIFVV0pGBnrvpqj56Q+TBD9/8bAwtmEMScQUVDduXPc+uIJJoZfLlUdUwIIfhhMEjSRGnaK4H0laaFHa05+KkFtHzc/
        iYEGwJQbiKvUn35/liWbcJ7nr8uCQSuV4PHMjZ2BEVtZ6Qj58L/wSSidb4qNkSb9BtlK+wwNDjbqysJtQCAKP7SSNuYcEAWl
        mvtHmpHlS3tVb7xjko/a7zqiakjCXE5gIFUmtZJFbG5dO/0VkT5zdrBZJoq+4DkvYSVGVDE/AtKC86YZ6d1DY2jIT0c9Blb
        Fp40A4Xkjjjf5/BsRlWFAs8Ip0Y/evG68gQBATJ2g3vAbPwxvNX2x3tKGNg+aDBYMGM76rRrtLhRqPIE4Ygv8x/s7JoBxy1q
        Czuwu/KmB7puXf/y/BBdcwRHIiBq2XQTfEW3ZJJ0J5+Kq48keAT4uOWoJiPLVTHwUP/UBhwOSa4nSOTAfdBXG4NqMknYwvAE
        9g==
        -----END CERTIFICATE-----
        """;

    private final String TEST_of_EID_SK_2016_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIHCTCCBfGgAwIBAgIQVrOxHLphb7pfUJLPiYJRMzANBgkqhkiG9w0BAQwFADB9
        MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1
        czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290
        IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMjAwOTAzMDY1MzAzWhcN
        MzAxMjE3MjE1OTU5WjBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlm
        aXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNV
        BAMME1RFU1Qgb2YgRUlELVNLIDIwMTYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
        ggIKAoICAQDqyjgcqyaktULCg+LV4apGWnzzHebH8XpuolWzAAByqbzrOCGtqF3U
        rydhY6zJebM3k+JaR8s3xAszt58e6b0Syh7n4upTMDBo7UiOgyvAYh/c+y5vpDS7
        pzRXSIq9IT4o42yJI4PYsH2nkk/RYuedNi7Cu3boSrgpx+ztLjK0vzMpyeErQDRm
        Nd19hbz1uKpK7W8LJoXTdAba6O9juv9zvtL256v8glrXEKwRr9/vFxAXQqh+Uv0b
        dBLoCl+FJVcuZdEFHPCK4xrXTLK/Sg7b5lcJXn12CqC6pAu4LjBjlDX+mOAGBrD6
        n2OHRtzeWDaeRRwy+yDvd4e06UVd4Mkd/C4ibDx5OZxEuZnT5DbhJAsoNMxCiO7i
        eC1LgW482T6doD+zzfCKovRj+1djQs/L1FTd1qR73LbH9AzL2XVeacai2OaI8n4T
        LFOGjHBkkAPRCvBEtztcwStQ1vm7Y20I1BVtUiMApAdsqHxcYHvr782Rm77dlBjh
        PKAC/PyczcYvRW40wG8nKxloBDENLDNXynPjrL6GksvZt2UBqYdPnW7KLkKZd5KS
        b4wzM8cZKzKsXYZVTK3iyhgjDMSTABkBMFUuT/dzZ5s/FG5JnqJlCa9zawaOPlfS
        +UuCsdb07w9Ke9sUWBcn4nyzo7PKrO5Ud8oZHAT0CO/BEasb99RVgwIDAQABo4IC
        mDCCApQwHwYDVR0jBBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wHQYDVR0OBBYE
        FK6w6uE2+CarpcwLZlX+Oh0CvxK0MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
        CDAGAQH/AgEAMIHEBgNVHSAEgbwwgbkwPAYHBACL7EABAjAxMC8GCCsGAQUFBwIB
        FiNodHRwczovL3d3dy5zay5lZS9yZXBvc2l0b29yaXVtL0NQUzA8BgcEAIvsQAEA
        MDEwLwYIKwYBBQUHAgEWI2h0dHBzOi8vd3d3LnNrLmVlL3JlcG9zaXRvb3JpdW0v
        Q1BTMDsGBgQAj3oBAjAxMC8GCCsGAQUFBwIBFiNodHRwczovL3d3dy5zay5lZS9y
        ZXBvc2l0b29yaXVtL0NQUzAnBgNVHSUEIDAeBggrBgEFBQcDCQYIKwYBBQUHAwIG
        CCsGAQUFBwMEMIGOBggrBgEFBQcBAQSBgTB/MCIGCCsGAQUFBzABhhZodHRwOi8v
        ZGVtby5zay5lZS9vY3NwMFkGCCsGAQUFBzAChk1odHRwOi8vd3d3LnNrLmVlL3Vw
        bG9hZC9maWxlcy9URVNUX29mX0VFX0NlcnRpZmljYXRpb25fQ2VudHJlX1Jvb3Rf
        Q0EuZGVyLmNydDBBBgNVHR4EOjA4oTYwBIICIiIwCocIAAAAAAAAAAAwIocgAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJQYIKwYBBQUHAQMEGTAXMBUG
        CCsGAQUFBwsCMAkGBwQAi+xJAQEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly93
        d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZWVjY3JjYS5jcmwwDQYJKoZI
        hvcNAQEMBQADggEBACawLCQnjAOtDCaNejt1AqMVc8IwWy03TAAvceJd7rRSG9w2
        Q69OxVMVhUpQ4+K+M+Fqtpkq5IWO9GFXYeYL5JwiL4rjKPk1MIunM4ZKr6f+NQBy
        4A4oHL0ArF4QoQZuYnUS/jesjQs2HXEthcLjdSkFyaoAyfPH50c0WTMDhZj8eEIK
        NWPEqGmGZPkAc4+ivFdl7zEC6ZaaJ6NdtihQKdFcisgv3Uyc4kuzmHK/6OtNAXpg
        qaiLyf4L3ThQ2KA+EuDp6B97rOfV4JWC265HkAwxKd9/3fk7pwnfyMxIonW5MGcN
        nrlYjNXNft5cr9xu2A8mPXh2ArMiZ1yif5NDvHI=
        -----END CERTIFICATE-----""";

    @Test
    void testGenerateVerifyTicket() throws Exception {
        EtsiIdentifier recipient = new EtsiIdentifier("etsi/PNOEE-" + TestData.TEST_IDENTIFIER);

        String sdjwt0  = TestData.generateTestAuthTicket(recipient.getSemanticsIdentifier(),
            "https://css.ria.ee:443",
            "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3",
            "59b314d4815f21f73a0b9168cecbd5773cc694b6");

        log.debug("SDJWT 0: {}", sdjwt0);

        AuthTokenVerifier tokenVerifier = new AuthTokenVerifier(TestData.createTestIssuerTrustStore(), false);
        Map<String, Object> verifiedClaims = tokenVerifier.getVerifiedClaims(sdjwt0, TestData.loadTestCert());
        log.debug("verified claims from ticket: {}", verifiedClaims);

        assertEquals(TestData.TEST_ETSI_RECIPIENT.toString(), verifiedClaims.get("iss"));

        assertTrue(verifiedClaims.containsKey("aud"));

        assertTrue(verifiedClaims.get("aud") instanceof List);

        List audList = (List)verifiedClaims.get("aud");
        assertTrue(audList.size() == 1);

        assertTrue(audList.get(0) instanceof String);

        String aud = (String)audList.get(0);

        assertEquals("https://css.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"
            + "?nonce=59b314d4815f21f73a0b9168cecbd5773cc694b6", aud);
    }

    @Test
    void testVerifyWithSIDCert() throws Exception {
        // pre generated token, signed with demo Smart-ID 30303039914 (real cert and signature)
        // see AuthTokenCreatorTest::testCreateAuthToken in cdoc2-java-ref-imp
        // use https://sdjwt.org to decode
        final String token1 = """
        eyJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QiLCJhbGciOiJSUzI1NiJ9
        .
        eyJpc3MiOiJldHNpL1BOT0VFLTMwMzAzMDM5OTE0IiwiX3NkIjpbIlZUZnV0bWtpdUJMWW5Sczl6dzBDZ2s5X0x3b09uSWhWd
        GZNcXlMUHdSZjAiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ
        .
        CA_tlS6sfG6DTx2RWF2_fNizVC8P2fHcitiUQNH5LNIEKfzwtT310rDn635VHSkFiPkYawpd-g6dJQUO6PN229KNA5qtoMi8T
        a6dc-eCJ9dgHdnSdX-UBkUo4ZPct51dFpoFK_9L3vMpHneT_WRdaXXzMaTrEjD1dIPZ0YAZNY9R_jLYbRYYc-9_YbEtoRdAMCo
        2kf9znoNfNcX1Tvt2wTJPR1FEqOT54DShTDywGbxX_w6mdFxirr0n9jkiZiDwQyvP7JN7s7x1CD6xsH-DyVh88mtPHLpRH42XC
        qF_oBQ_BkAF_GoHYR43mk_C0zVg4PNsQ4eMKme3HW2HhyLUtDWOoF3OfiDdRX19ckPUAxh1C0N27g0nHroHYcyogu7cZ_qTaOE
        3DmTRsymXErSfFXFYrr3CGetxERT6TzGzL-ycKcz-r7nwejhsgny2sgZDvQ0lvSPmiejldsqhkNGQcpnBF6JfX0V5fLLzLdU_c
        mDBig1TLP-y8ic2xG6F-_Yojs8iL7b3DhEmeOXeqkrAT93pqW_HEbS6dyoY1Oi7xJuj6h3d-QJRgSBrUihf4EnD5XhvFFU8AXF
        YhRsuyPOWBTtLiV9hvi7TKOUMPwY9EONpNQQiqFS_roMu4vaqLKve00bFDHGT09-dLt4suNA7cStVO-A2IDey9MfQ_bmuQT-6q
        t02O-nZt4be6R0l0bf7HRlPl-RAThi8lP9qgOFP1ID0oRfK3ralrxGr8e4hjVrJhUSNJ9XAPJBVYdwJtPfee5DckR9HxJ53si3
        FSPOdtnPsCL8pqCU1nMmdSttLllOEvg5oDtHjgoQGXgrCHU2w284TbZl0i86k910XfA-WcBz8Af9fK_QyoNC8UL01Nqc1ZmF1q
        j702iRJ6gl__KDmzLh5aPjKec5SFrBXxJJzjUDCU8wLK5EHtKnOUSGb6Uo2TeTgAbtnCuNRwMcmyOMyDomNsJ2QaMPOYeHeCby
        E3cRhkrIoymNZsSop9gnCz1V9wZR6SvMMLu4ahmfyHD86
        ~
        WyJNdVNxMjlKeFEyallWV2k2NTZuV0lBIiwiYXVkIixbeyIuLi4iOiJ4a0JmWFpacmx5N2RQWTB2YmtwbjRoSGZkQnhxQWYtcD
        B1cDdxUkdIX1drIn0seyIuLi4iOiJiclFTUEhZYnZaOWZzdm1LQ1dZQ2hGVXdtMjhTclo2b3F3S3RYNk1yRXpBIn1dXQ
        ~
        WyJxSTJPTFlqRXU4bVlxamt5N1FodUhnIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0My9rZXktc2hhcmVzL2ZmMDEwMjAzMDQwNT
        A2MDcwODA5MGEwYjBjMGUwZGZmP25vbmNlXHUwMDNkQUFFQ0F3UUZCZ2N
        JQ1FvTERBNE5fdyJd
        ~
        """.replaceAll("\\s", ""); //remove all whitespace

        X509Certificate cert = X509CertUtils.parse(sidDemoCertStr);
        X509Certificate issuerCert = X509CertUtils.parse(TEST_of_EID_SK_2016_PEM);

        KeyStore test_Of_EID_SK_2016 = TestData.createEmptyTrustStore();
        test_Of_EID_SK_2016.setCertificateEntry("test_Of_EID_SK_2016", issuerCert);


        AuthTokenVerifier tokenVerifier = new AuthTokenVerifier(test_Of_EID_SK_2016, false);
        Map<String, Object> verifiedClaims = tokenVerifier.getVerifiedClaims(token1, cert);

        log.debug("claims: {}", verifiedClaims);

        assertNotNull(verifiedClaims.get("iss"));
        assertTrue(verifiedClaims.get("iss").toString().contains(SID_DEMO_IDENTIFIER)); //etsi/PNOEE-30303039914

        var expectedAud = List.of("https://localhost:8443"
            +"/key-shares/ff0102030405060708090a0b0c0e0dff?nonce=AAECAwQFBgcICQoLDA4N_w");

        assertEquals(expectedAud, verifiedClaims.get("aud"));
    }
}