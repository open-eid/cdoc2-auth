package ee.cyber.cdoc2.auth;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.VerificationException;

final class TokenVerifierUtil {
    private static final SDObjectDecoder SD_OBJECT_DECODER = new SDObjectDecoder();

    private TokenVerifierUtil() {
        // utility class
    }

    static SignedJWT getSignedJwt(String credentialJwt) throws VerificationException {
        try {
            return SignedJWT.parse(credentialJwt);
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    static JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws VerificationException {
        try {
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    static Map<String, Object> decodeSdJwtClaims(
        JWTClaimsSet claimsSet,
        List<Disclosure> disclosures
    ) {
        Map<String, Object> claimsMap = claimsSet.getClaims();

        return SD_OBJECT_DECODER.decode(claimsMap, disclosures);
    }

    static EtsiIdentifier verifyTokenIdentityAndReturnEtsiIdentifier(
        X509Certificate cert,
        String tokenIdentity
    ) throws VerificationException {
        EtsiIdentifier etsiIdentifier = new EtsiIdentifier(tokenIdentity);
        String certSemanticsIdentifier = SIDCertificateUtil.getSemanticsIdentifier(cert);
        if (!certSemanticsIdentifier.equals(etsiIdentifier.getSemanticsIdentifier())) {
            throw new VerificationException("Token identity does not match certificate");
        }

        return etsiIdentifier;
    }


    static String getSingleAudArrayElementAsString(Map<String, Object> claims)
        throws VerificationException {
        Object aud = claims.get("aud");
        if (aud == null) {
            throw new VerificationException("aud claim missing in decoded session token");
        }

        if (aud instanceof ArrayList<?> audArray) {
            if (audArray.isEmpty()) {
                throw new VerificationException("disclosed aud array is empty");
            }
            if (audArray.size() > 1) {
                throw new VerificationException("More than one element in disclosed aud array");
            }

            return audArray.get(0).toString();
        } else {
            throw new VerificationException("illegal type for aud claim");
        }
    }
}
