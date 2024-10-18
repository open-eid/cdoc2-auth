package ee.cyber.cdoc2.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthTest {

    Logger log = LoggerFactory.getLogger(AuthTest.class);

    @Test
    void testGenerateVerifyTicket() throws ParseException, JOSEException, VerificationException {
        RSAKey privateKey = new RSAKeyGenerator(4096).generate();
        RSAKey rsaPublicJWK = privateKey.toPublicJWK();

        JWSSigner jwsSigner = new RSASSASigner(privateKey);

        EtsiIdentifier recipient = new EtsiIdentifier("etsi/PNOEE-48010010101");

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

        token.sign(jwsSigner, rsaPublicJWK);

        String sdjwt0  = token.createTicketForShareId("9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3");

        System.out.println("SDJWT 0:");
        System.out.println(sdjwt0);

        Map<String, Object> verifiedClaims = AuthTokenVerifier.getVerifiedClaims(sdjwt0);
        log.debug("verified claims from token: {}", verifiedClaims);

        assertTrue(verifiedClaims.containsKey("sharedAccessDataPOJO"));

        assertInstanceOf(ShareAccessData.class, verifiedClaims.get("sharedAccessDataPOJO"));

        ShareAccessData shareAccessData = (ShareAccessData)verifiedClaims.get("sharedAccessDataPOJO");

        assertEquals("https://cdoc-ccs.ria.ee:443/key-shares/", shareAccessData.getServerBaseUrl());
        assertEquals("9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3", shareAccessData.getShareId());
        assertEquals("59b314d4815f21f73a0b9168cecbd5773cc694b6", shareAccessData.getNonce());
    }

}