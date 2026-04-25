package ee.cyber.cdoc2.auth;

import java.security.cert.X509Certificate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.VerificationException;

public final class MidSignatureVerifier {

    static boolean isValid(
        SignedJWT signedJWT,
        X509Certificate cert
    )
        throws VerificationException {
        //For Mobile-ID this is in format PNOEE-30303039914
        String subjectSerial = SIDCertificateUtil.getSemanticsIdentifier(cert);

        try {
            // parse ECKey from cert (determining EC curve is a bit tricky) and then set keyID
            ECKey jwk = new ECKey.Builder(ECKey.parse(cert))
                .keyID(subjectSerial)
                .build();

            JWSVerifier jwsVerifier = createECVerifier(jwk);
            return signedJWT.verify(jwsVerifier);
        } catch (JOSEException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    private static JWSVerifier createECVerifier(ECKey pubECKey)
        throws JOSEException, VerificationException {
        if (pubECKey.getKeyID() == null) {
            throw new VerificationException("Expected kid for pubECJwk");
        }
        return new ECDSAVerifier(pubECKey);
    }
}
