package ee.cyber.cdoc2.auth;

import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.SignatureValidationParams;
import ee.cyber.cdoc2.auth.exception.VerificationException;

public class SessionTokenVerifier {
    private static final Logger log = LoggerFactory.getLogger(SessionTokenVerifier.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final CertVerifier certVerifier;
    private final SidRpv3SignatureVerifier sidSignatureVerifier;
    private final SDObjectDecoder sdObjectDecoder;

    public SessionTokenVerifier(
        KeyStore issuersTrustStore,
        boolean enableRevocationChecks,
        String schemeName,
        String rpName
    ) {
        this.certVerifier = new CertVerifier(issuersTrustStore, enableRevocationChecks);
        this.sidSignatureVerifier = new SidRpv3SignatureVerifier(
            new SidRpv3SignatureVerifier.SidRpv3SignatureVerifierConfig(
                schemeName,
                rpName
            )
        );
        this.sdObjectDecoder = new SDObjectDecoder();
    }

    /**
     * Verifies: JWT signature with provided jwk, certificate chain, JWT sub match with
     * certificate subject, SID signature included with token.
     * Disclosed aud array must have exactly one element.
     * On successful verification returns the signle session nonce URI will be used
     * in validation checks by the caller
     *
     * @param tokenBase64Url session token in BASE64URL encoding
     * @param certBase64Url  signing certificate in BASE64URL encoding
     * @param jwk            JWK public key for the keypair that was used to sign the session token JWT.
     * @return session nonce URI.
     */
    public URI getVerifiedSessionNonce(
        String tokenBase64Url,
        String certBase64Url,
        JWK jwk
    ) throws VerificationException {
        Map<String, Object> verifiedDecodedClaims = getVerifiedClaims(
            tokenBase64Url,
            certBase64Url,
            jwk
        );
        return URI.create(getSingleAudArrayElementAsString(verifiedDecodedClaims));
    }

    private Map<String, Object> getVerifiedClaims(
        String tokenBase64Url,
        String certBase64Url,
        JWK jwk
    ) throws VerificationException {
        Objects.requireNonNull(tokenBase64Url);
        Objects.requireNonNull(certBase64Url);
        Objects.requireNonNull(jwk);

        X509Certificate cert = X509CertUtils.parse(Base64.getUrlDecoder().decode(certBase64Url));

        certVerifier.checkCertificate(cert);

        SDJWT sdjwt = SDJWT.parse(tokenBase64Url);
        SignedJWT signedJWT = getSignedJwt(sdjwt.getCredentialJwt());

        if (!isValidJwtSignature(signedJWT, jwk)) {
            throw new VerificationException("Invalid JWT signature");
        }

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);

        if (!jwtSubMatchesCert(cert, claimsSet)) {
            throw new VerificationException("JWT sub does not mach signing certificate");
        }

        SignatureValidationParams validationParams = createSidSignatureValidationParams(signedJWT);
        PublicKey certPublicKey = cert.getPublicKey();

        if (sidSignatureVerifier.isValid(null, certPublicKey, validationParams)) {
            return decodeSdJwtClaims(claimsSet, sdjwt.getDisclosures());
        } else {
            throw new VerificationException("Invalid SID signature");
        }
    }

    private SignedJWT getSignedJwt(String credentialJwt) throws VerificationException {
        try {
            return SignedJWT.parse(credentialJwt);
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    private JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws VerificationException {
        try {
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    private String getSingleAudArrayElementAsString(Map<String, Object> claims)
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

    private Map<String, Object> decodeSdJwtClaims(
        JWTClaimsSet claimsSet,
        List<Disclosure> disclosures
    ) {
        Map<String, Object> claimsMap = claimsSet.getClaims();

        return sdObjectDecoder.decode(claimsMap, disclosures);
    }

    private boolean isValidJwtSignature(SignedJWT signedJWT, JWK jwk) throws VerificationException {
        JWSVerifier jwsVerifier = createJwsVerifierForJwk(jwk);

        try {
            return signedJWT.verify(jwsVerifier);
        } catch (JOSEException e) {
            throw new VerificationException("JWS could not be verified");
        }
    }

    private boolean jwtSubMatchesCert(X509Certificate cert, JWTClaimsSet claimsSet)
        throws VerificationException {
        try {
            EtsiIdentifier etsiIdentifier = new EtsiIdentifier(claimsSet.getClaimAsString("sub"));
            String certSemanticsIdentifier = SIDCertificateUtil.getSemanticsIdentifier(cert);
            return certSemanticsIdentifier.equals(etsiIdentifier.getSemanticsIdentifier());
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    private JWSVerifier createJwsVerifierForJwk(JWK jwk) throws VerificationException {
        try {
            if (KeyType.RSA == jwk.getKeyType()) {
                RSAKey rsaKey = (RSAKey) jwk;
                RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
                return new RSASSAVerifier(publicKey);
            }
            if (KeyType.EC == jwk.getKeyType()) {
                ECKey ecKey = (ECKey) jwk;
                ECPublicKey publicKey = ecKey.toECPublicKey();
                return new ECDSAVerifier(publicKey);
            }
        } catch (JOSEException e) {
            throw new VerificationException("Error creating JWS verifier");
        }

        throw new VerificationException("Unsupported JWK type");
    }

    private SignatureValidationParams createSidSignatureValidationParams(
        SignedJWT signedJWT
    ) throws VerificationException {
        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            SidRpv3SignatureVerifier.SidSignature sidSignature = OBJECT_MAPPER.convertValue(
                claimsSet.getClaim("signature"),
                SidRpv3SignatureVerifier.SidSignature.class
            );

            String rpChallengeBase64 = claimsSet.getClaimAsString("rpChallenge");
            String interactionsDigestBase64 = claimsSet.getClaimAsString("interactionsDigest");
            String interactionTypeUsed = claimsSet.getClaimAsString("interactionTypeUsed");

            return new SignatureValidationParams(
                rpChallengeBase64,
                interactionsDigestBase64,
                interactionTypeUsed,
                sidSignature
            );
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }
}
