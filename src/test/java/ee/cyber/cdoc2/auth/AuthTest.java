package ee.cyber.cdoc2.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.X509CertUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthTest {

    Logger log = LoggerFactory.getLogger(AuthTest.class);

    // SID demo env identifier 30303039914 that automatically authenticates successfully
    private static final String SID_DEMO_IDENTIFIER = "30303039914";

    // SID demo env cert for 30303039914 that automatically authenticates successfully
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

    @Test
    void testGenerateVerifyTicket() throws ParseException, JOSEException, VerificationException {
        EtsiIdentifier recipient = new EtsiIdentifier("PNOEE-" + SID_DEMO_IDENTIFIER);

        RSAKey privateKey = new RSAKeyGenerator(4096).generate();
        RSAKey rsaPublicJWK = new RSAKey.Builder(privateKey.toRSAPublicKey())
            .keyID(recipient.toString())
            .build();

        JWSSigner jwsSigner = new RSASSASigner(privateKey);

        AuthTokenCreator token = AuthTokenCreator.builder()
            .withEtsiIdentifier(recipient)
            .withShareAccessData(new ShareAccessData(
                "https://cdoc-ccs.ria.ee:443/key-shares/",
                "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3",
                "59b314d4815f21f73a0b9168cecbd5773cc694b6"))
            .withShareAccessData(new ShareAccessData(
                "https://cdoc-ccs.smit.ee:443/key-shares/",
                "5BAE4603-C33C-4425-B301-125F2ACF9B1E",
                "9d23660840b427f405009d970d269770417bc769"))
            .build();

        token.sign(jwsSigner, recipient.toString());

        String sdjwt0  = token.createTicketForShareId("9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3");

        System.out.println("SDJWT 0:");
        System.out.println(sdjwt0);

        Map<String, Object> verifiedClaims = AuthTokenVerifier.getVerifiedClaims(sdjwt0, rsaPublicJWK);
        log.debug("verified claims from token: {}", verifiedClaims);

        assertTrue(verifiedClaims.containsKey("sharedAccessDataPOJO"));

        assertInstanceOf(ShareAccessData.class, verifiedClaims.get("sharedAccessDataPOJO"));

        ShareAccessData shareAccessData = (ShareAccessData)verifiedClaims.get("sharedAccessDataPOJO");

        assertEquals("https://cdoc-ccs.ria.ee:443/key-shares/", shareAccessData.getServerBaseUrl());
        assertEquals("9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3", shareAccessData.getShareId());
        assertEquals("59b314d4815f21f73a0b9168cecbd5773cc694b6", shareAccessData.getNonce());
    }

    @Test
    void testVerifyWithSIDCert() throws VerificationException, ParseException, JOSEException {
        // pre generated token, signed with demo Smart-ID 30303039914 (real cert and signature)
        // see AuthTokenCreatorTest::testCreateAuthToken in cdoc2-java-ref-imp
        // use https://sdjwt.org to decode
        final String token1 = """
            eyJraWQiOiJQTk9FRS0zMDMwMzAzOTkxNCIsInR5cCI6InZuZC5jZG9jMi5DQ1MtYXV0aC10b2tlbi5
            2MStzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJldHNpL1BOT0VFLTMwMzAzMDM5OTE0IiwiX
            3NkIjpbIml3ZXhLa0pZZWxTcUx2TC1WTTNKWE43b0h5MGM4T3YyVGhGZG9Xc2xUUlUiXSwiZXhwIjox
            NzMwODk3NDMxLCJpYXQiOjE3MzA4OTczNzEsIl9zZF9hbGciOiJzaGEtMjU2In0.kFzbI8Dl0QyNQct
            HI_g88dPw4HouAZdJxLrePkc3_gSWuiOSvpIGSjFgbWHPRu0pSduVBXClz98ySRDveykbdU6knhfHKq
            61ST-9LS6iwBC9-mXNPL14Oc6BbcZA1ytehlHAj8UGXbpNgdqdSDBBRCCPKNH3e28SEVGL9lLUrLEfa
            XolGPhXv3ce1irSArVFrJRwn1LS2Aoki2-TTpgGykY6SAUapJVYANYzQBU0RaSTmDwepoH36NFLPDuB
            8Ovdi_qcHx8qg4nhFGfukdMZHlwxrR8iEeaOhEqdTRzBS8bQDl7M6wbIScUBEGlxFNf6HJD6_VaLlvn
            uDIQRsTrPCs3hcmOr3FL0OhiIHNW0ppx4uTXWCGQL0QzzH76r7ueG2dt9SyQDrvAbQKu7fpEVaMlLdT
            VAR7L6-GBgtnj4pz2jLxa7BE7Gx6x6dUZtK9SlnPCsHUEu4qRZEKhDgfaAYLeEaqL2ZmI8EecDP2VQV
            snJlbkEoFhNFzpf9eqPti53pjp9XmGYDFbLiUfhumW6aJjg3z-ysLnlFTd_6FK5vjX6axXLL0oK27V5
            g9MJqPmfvdzVdcpJZF43RvPlE0wGSxU7a8iDDmYuYIAT-9paSuaibAfIoFpMzrANPXSKedT5NkyehlZ
            KZHZEeK9wp--fwgTyL0R-52-wx44sZgB-EbyLTtxB2TqGc_VnfgoCUNcIzKhgsJOdY-BX16dhs1QoCj
            VBH2cG_X-JrblBWJU3DUda0dDGjw1j0yEY2yjc5nFKuSPuO4LO3RYQUQmfoTH0FzNgQpNdWIw9qmqeI
            Euhv4TFNBfqiqyslTt27EEfg5e5AUCYe2JfLg0yk-A9PjzlU1c6F5pMn0C1ESFIjG3wLP0OiR602sur
            qWOhLTsY6JTCabgTwVBm5jhLYi1bV82pqEHFKasT1iMRuaYRl33CfvZj9hScZqz_Byk4WLYGvQDwlPT
            rjYsAfVMhNND95vhKBmRNFKobB-_T3X0ZmL6C_fs25u1GWIFQcL6KsyDa9Ify~WyIzc052dUhqYkRjW
            npXN0E1X2Z5R2dRIiwic2hhcmVBY2Nlc3NEYXRhIixbeyIuLi4iOiItWnZob2tLQ19sUW93VEVtRHI4
            cjlJTks2YV84UnhkYTlRTXZPS2ptNXNBIn0seyIuLi4iOiIydW1uSUxjOHFaeWtiUFh2MjlrOV9wUmV
            5ek1NSGk1bGdkTE5lMl9hSjJ3In1dXQ~WyI0Nkw3Wk5oQi03eHNxSnloQ1N3TUd3Iix7InNlcnZlck5
            vbmNlIjoiMDEiLCJzZXJ2ZXJCYXNlVVJMIjoiaHR0cHM6Ly9jZG9jMi1jc3MucmlhLmVlOjQ0MyIsIn
            NoYXJlSWQiOiI5RUU5MEYyRC1EOTQ2LTRENTQtOUMzRC1GNEM2OEY3RkZBRTMifV0~
            """.replaceAll("\\s", ""); //remove all whitespace

        X509Certificate cert = X509CertUtils.parse(sidDemoCertStr);

        Map<String, Object> verifiedClaims = AuthTokenVerifier.getVerifiedClaims(token1, cert,
            SIDCertificateUtil::getSemanticsIdentifier);

        log.debug("claims: {}", verifiedClaims);

        assertNotNull(verifiedClaims.get("iss"));
        assertTrue(verifiedClaims.get("iss").toString().contains("30303039914")); //etsi/PNOEE-30303039914
    }
}