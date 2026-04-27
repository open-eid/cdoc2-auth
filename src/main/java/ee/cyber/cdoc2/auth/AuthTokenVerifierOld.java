package ee.cyber.cdoc2.auth;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSAProvider;
import com.nimbusds.jose.crypto.impl.RSASSAProvider;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.IllegalCertificateException;
import ee.cyber.cdoc2.auth.exception.InvalidEtsiSemanticsIdenfierException;
import ee.cyber.cdoc2.auth.exception.VerificationException;

/**
 * Class to validate cdoc2 auth tokens, created by {@link AuthTokenCreator}
 * Validated data has the following structure:
 * {@link AuthTokenVerifierOld#getVerifiedClaimsForRSA(String, RSAKey)} or
 * {@link AuthTokenVerifierOld#getVerifiedClaimsForEC(String, ECKey)}:
 */
public class AuthTokenVerifierOld {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenVerifierOld.class);
    private static final Logger tokens_log = LoggerFactory.getLogger("tokens");

    private final CertVerifier certVerifier;

    public AuthTokenVerifierOld(KeyStore issuersTrustStore, boolean enableRevocationChecks) {
        this.certVerifier = new CertVerifier(issuersTrustStore, enableRevocationChecks);
    }

    /**
     * Verify JWT signature and validate signing certificate.
     * Check that JWT "iss" matches certificate subjectname
     * Disclose data from sd-jwt disclosures.
     *
     * @param token sd-jwt created by {@link AuthTokenCreator}
     * @param cert  certificate to verify token signature with
     * @return verified/disclosed claims as JsonObject
     * @throws VerificationException when token doesn't verify or missing/unsupported data
     * @throws ParseException        If the string couldn't be parsed to a valid signed JWT.
     * @throws JOSEException         if signed JWT verification has failed
     */
    public Map<String, Object> getVerifiedClaims(
        String token,
        X509Certificate cert
    ) throws VerificationException, JOSEException, ParseException {

        Objects.requireNonNull(token);
        Objects.requireNonNull(cert);

        //check that certificate is issued by a valid issuer
        this.certVerifier.checkCertificate(cert);

        try {
            return getVerifiedClaimsByKeyAlgorithm(token, cert);
        } catch (IllegalCertificateException ex) {
            throw new VerificationException("Failed to extract keyID from certificate", ex);
        }
    }

    private Map<String, Object> getVerifiedClaimsByKeyAlgorithm(
        String token,
        X509Certificate cert
    ) throws VerificationException, JOSEException, ParseException {
        String publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();
        if ("RSA".equals(publicKeyAlgorithm)) {
            return getVerifiedClaimsUsingRSACert(cert, token);
        } else if ("EC".equals(publicKeyAlgorithm)) {
            return getVerifiedClaimsUsingECDSACert(cert, token);
        } else {
            throw new VerificationException(
                "Expected certificate public key to be RSA or EC algorithm"
            );
        }
    }

    private Map<String, Object> getVerifiedClaimsUsingRSACert(X509Certificate cert, String token)
        throws VerificationException, ParseException, JOSEException {
        //For Smart-ID this is in format PNOEE-30303039914
        String subjectSerial = SIDCertificateUtil.getSemanticsIdentifier(cert);
        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) cert.getPublicKey())
            .keyID(subjectSerial)
            .build();

        return getVerifiedClaimsForRSA(token, jwk);
    }

    private Map<String, Object> getVerifiedClaimsUsingECDSACert(X509Certificate cert, String token)
        throws VerificationException, ParseException, JOSEException {

        //For Mobile-ID this is in format PNOEE-30303039914
        String subjectSerial = SIDCertificateUtil.getSemanticsIdentifier(cert);

        // parse ECKey from cert (determining EC curve is a bit tricky) and then set keyID
        ECKey jwk = new ECKey.Builder(ECKey.parse(cert))
            .keyID(subjectSerial)
            .build();

        return getVerifiedClaimsForEC(token, jwk);
    }

    private static Map<String, Object> getVerifiedClaimsForRSA(String token, RSAKey pubRSAjwk)
        throws VerificationException, JOSEException, ParseException {
        JWSVerifier jwsVerifier = createRSAVerifier(pubRSAjwk);
        return getVerifiedClaims(token, pubRSAjwk.getKeyID(), jwsVerifier, RSASSAProvider.SUPPORTED_ALGORITHMS);
    }

    private static Map<String, Object> getVerifiedClaimsForEC(String token, ECKey pubECJwk)
        throws VerificationException, ParseException, JOSEException {
        JWSVerifier jwsVerifier = createECVerifier(pubECJwk);
        return getVerifiedClaims(token, pubECJwk.getKeyID(), jwsVerifier, ECDSAProvider.SUPPORTED_ALGORITHMS);
    }

    private static JWSVerifier createRSAVerifier(RSAKey pubRSAJwk)
        throws JOSEException, VerificationException {
        if (pubRSAJwk.getKeyID() == null) {
            throw new VerificationException("Expected kid for pubRSAJwk");
        }

        return new RSASSAVerifier(pubRSAJwk);
    }

    private static JWSVerifier createECVerifier(ECKey pubECKey)
        throws JOSEException, VerificationException {
        if (pubECKey.getKeyID() == null) {
            throw new VerificationException("Expected kid for pubECJwk");
        }
        return new ECDSAVerifier(pubECKey);
    }

    /**
     * Verify token with pubRSAJWK and return verified claims from the token
     *
     * @param token                token to verify
     * @param pubKeyId             public jwk kid for token verification
     * @param jwsVerifier          JWS verifier
     * @param allowedKeyAlgorithms JWS algorithms that are allowed
     * @return verified claims JsonObject as Map
     * @throws VerificationException if verification of token fails
     * @throws JOSEException         if signed JWT verification has failed
     * @throws ParseException        If the string couldn't be parsed to a valid signed JWT
     */
    private static Map<String, Object> getVerifiedClaims(
        String token,
        String pubKeyId,
        JWSVerifier jwsVerifier,
        Set<JWSAlgorithm> allowedKeyAlgorithms
    ) throws VerificationException, JOSEException, ParseException {

        SDJWT sdJwt = SDJWT.parse(token);

        String jwt = sdJwt.getCredentialJwt();
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSHeader header = signedJWT.getHeader();

        if (!allowedKeyAlgorithms.contains(header.getAlgorithm())) {
            throw new VerificationException("Algorithm not supported: " + header.getAlgorithm());
        }

        if (header.getType() == null ||
            !Constants.TYPE_AUTH_TOKEN.equals(signedJWT.getHeader().getType().toString())
        ) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }

        boolean signatureValid = signedJWT.verify(jwsVerifier);
        if (!signatureValid) {
            throw new VerificationException("JWT signature verification failed");
        }

        JWTClaimsSet signedClaims = signedJWT.getJWTClaimsSet();
        Map<String, Object> signedClaimsMap = signedClaims.getClaims();


        String iss = signedClaims.getIssuer();
        EtsiIdentifier issuer;
        try {
            if (!iss.startsWith(EtsiIdentifier.PREFIX)) {
                throw new VerificationException("Only identifiers starting with " + EtsiIdentifier.PREFIX
                    + " are supported.  \"iss\" \"" + iss + "\"");
            }
            issuer = new EtsiIdentifier(iss); // etsi/PNOEE-30303039914
        } catch (InvalidEtsiSemanticsIdenfierException e) {
            throw new VerificationException("Invalid \"iss\" \"" + iss + "\"", e);
        }

        // check that "iss" matches certificate
        // iss is in format etsi/PNOEE-30303039914
        // x5c serialnumber PNOEE-30303039914
        if (!issuer.getSemanticsIdentifier().equals(pubKeyId)) {
            throw new VerificationException("iss semantics identifier doesn't match to x5c serialnumber ("
                + issuer.getSemanticsIdentifier() + "!=" + pubKeyId + ")");
        }

        if (tokens_log.isDebugEnabled()) {
            tokens_log.debug("Claims: {}", signedClaimsMap);
            tokens_log.debug("Disclosures: {}", sdJwt.getDisclosures().stream()
                .map(d -> d.digest() + ": " + d.getJson()).toList());
        }

        List<Disclosure> disclosures = sdJwt.getDisclosures();

        for (Disclosure disclosure : disclosures) {
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
        //
        // First disclosure represents the "aud" field, second disclosure values in the "aud" array.
        //
        // SDObjectDecoder.decode works recursively, so a single decode operation will result in:
        // {
        // iss=etsi/PNOEE-30303039914,
        // aud=[https://cdoc-ccs.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce=59..b6]
        // }
        return decoder.decode(signedClaimsMap, disclosures);
    }
}
