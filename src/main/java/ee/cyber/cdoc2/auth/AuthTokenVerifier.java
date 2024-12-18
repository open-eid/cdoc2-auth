package ee.cyber.cdoc2.auth;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.cyber.cdoc2.auth.exception.IllegalCertificateException;
import ee.cyber.cdoc2.auth.exception.InvalidEtsiSemanticsIdenfierException;
import ee.cyber.cdoc2.auth.exception.VerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Class to validate cdoc2 auth tokens, created by {@link AuthTokenCreator}
 * Validated data has the following structure:
 * {@link AuthTokenVerifier#getVerifiedClaims(String,RSAKey)}:
 */
public class AuthTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenVerifier.class);
    private static final Logger tokens_log = LoggerFactory.getLogger("tokens");

    CertVerifier certVerifier;
    Function<X509Certificate, String> extractKIDFunc;

    public AuthTokenVerifier(KeyStore issuersTrustStore, boolean enableRevocationChecks) {
        this.certVerifier = new CertVerifier(issuersTrustStore, enableRevocationChecks);
        this.extractKIDFunc = SIDCertificateUtil::getSemanticsIdentifier;
    }

    /**
     * Verify JWT signature and validate signing certificate.
     * Check that JWT "iss" matches certificate subjectname
     * Disclose data from sd-jwt disclosures.
     * @param token sd-jwt created by {@link AuthTokenCreator}
     * @param cert certificate to verify token signature with
     * @return verified/disclosed claims as JsonObject
     * @throws VerificationException when token doesn't verify or missing/unsupported data
     * @throws ParseException        If the string couldn't be parsed to a valid signed JWT.
     * @throws JOSEException
     */
    public  Map<String, Object> getVerifiedClaims(String token, X509Certificate cert)
        throws VerificationException, JOSEException, ParseException {

        Objects.requireNonNull(token);
        Objects.requireNonNull(cert);

        //check that certificate is issued by a valid issuer
        this.certVerifier.checkCertificate(cert);

        if (!"RSA".equals(cert.getPublicKey().getAlgorithm())) {
            throw new VerificationException("Expected certificate public key to be RSA");
        }

        try {
            //For Smart-ID this is in format PNOEE-30303039914
            String subjectSerial = extractKIDFunc.apply(cert);
            RSAKey jwk = new RSAKey.Builder((RSAPublicKey) cert.getPublicKey())
                .keyID(subjectSerial)
                .build();

            return getVerifiedClaims(token, jwk);
        } catch (IllegalCertificateException ex){
            throw new VerificationException("Failed to extract keyID from certificate", ex);
        }
    }

    /**
     * Verify token with pubRSAJWK and return verified claims from the token
     * @param token token to verify
     * @param pubRSAJWK public RSA jwk to verify token with. Must have kid defined
     * @return verified claims JsonObject as Map
     * @throws VerificationException if verification of token fails
     * @throws JOSEException
     * @throws ParseException
     */
    protected static Map<String, Object> getVerifiedClaims(String token, RSAKey pubRSAJWK)
        throws VerificationException, JOSEException, ParseException {

        SDJWT sdJwt = SDJWT.parse(token);

        String jwt = sdJwt.getCredentialJwt();
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSHeader header = signedJWT.getHeader();

        if (!JWSAlgorithm.RS256.equals(header.getAlgorithm())) { //RSASSA-PKCS-v1_5 using SHA-256
            throw new VerificationException("Algorithm not supported: " + header.getAlgorithm());
        }

        if (header.getType() == null ||
            !Constants.TYPE.equals(signedJWT.getHeader().getType().toString())
        ) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }

        if (pubRSAJWK.getKeyID() == null) {
            throw new VerificationException("Expected kid for pubRSAJWK");
        }

        JWSVerifier verifier = new RSASSAVerifier(pubRSAJWK);

        boolean signatureValid = signedJWT.verify(verifier);
        if (!signatureValid) {
            throw new VerificationException("JWT signature verification failed");
        }

        JWTClaimsSet signedClaims = signedJWT.getJWTClaimsSet();
        Map<String, Object> signedClaimsMap = signedClaims.getClaims();


        String iss = signedClaims.getIssuer();
        EtsiIdentifier issuer;
        try {
            issuer = new EtsiIdentifier(iss); // etsi/PNOEE-30303039914
        } catch (InvalidEtsiSemanticsIdenfierException e) {
            throw new VerificationException("Invalid \"iss\" \"" + iss + "\"", e);
        }

        // check that "iss" matches certificate
        // iss is in format etsi/PNOEE-30303039914
        // x5c serialnumber PNOEE-30303039914
        if (!issuer.getSemanticsIdentifier().equals(pubRSAJWK.getKeyID())) {
            throw new VerificationException("iss semantics identifier doesn't match to x5c serialnumber ("
                + issuer.getSemanticsIdentifier() + "!=" + pubRSAJWK.getKeyID() + ")");
        }

        if (tokens_log.isDebugEnabled()) {
            tokens_log.debug("Claims: {}", signedClaimsMap);
            tokens_log.debug("Disclosures: {}", sdJwt.getDisclosures().stream()
                .map(d-> d.digest() + ": " + d.getJson()).toList());
        }

        List<Disclosure> disclosures = sdJwt.getDisclosures();

        for(Disclosure disclosure: disclosures) {
            if (log.isDebugEnabled()) {
                log.debug("disclosure: ({}) {}={}",
                    disclosure.digest(),
                    disclosure.getClaimName(),
                    disclosure.getClaimValue());
            }
        }

        SDObjectDecoder decoder = new SDObjectDecoder();
        // initial jwt contains "_sd" and "_sd_alg"
        // {iss=etsi/PNOEE-30303039914, _sd=[dtGzdbCMa_byJAeCW-I0UYpxmtJZyFcszns8dsAYWTE], _sd_alg=sha-256}
        var decoded = decoder.decode(signedClaimsMap, disclosures);

        //First decoded disclosure still contains digest(s) for "aud" value:
        // {iss=etsi/PNOEE-30303039914, aud=[{...=ninhZYyUqlOn4i-5VNGv--6LzO-APfhWLKscldaTq3c}]}
        // decode "aud" values remaining digests and disclosures
        // if everything is already decoded, just return it

        return decoder.decode(decoded, disclosures); //will return fully decoded claims:
        // {
        // iss=etsi/PNOEE-30303039914,
        // aud=[https://cdoc-ccs.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce=59..b6]
        // }
    }

}
