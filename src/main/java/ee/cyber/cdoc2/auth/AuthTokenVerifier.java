package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.Constants.RP_V3_SIGNATURE_ALGORITHM_NAME;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.*;

public class AuthTokenVerifier {
    private static final Logger log = LoggerFactory.getLogger(AuthTokenVerifier.class);

    private final CertVerifier certVerifier;

    public AuthTokenVerifier(
        KeyStore issuersTrustStore,
        boolean enableRevocationChecks
    ) {
        this.certVerifier = new CertVerifier(issuersTrustStore, enableRevocationChecks);
    }

    /**
     * Verifies: JWT signature, using the additional provided signature parameters for SID RPv3
     * signatures, certificate chain, JWT iss match with certificate subject, correct typ, token
     * identity format.
     * Disclosed aud array must have exactly one element.
     * On successful verification returns a response object containing: a single auth nonce
     * URI, ETSI identifier parsed from the token 'iss' claim.
     *
     * @param tokenBase64Url                  session token in BASE64URL encoding
     * @param certBase64Url                   signing certificate in BASE64URL encoding
     * @param sidSignatureParamsJsonBase64Url parameters for SID RpV3 signature verification.
     *                                        {@code null} when veryfying MID signature.
     * @param rpName                          Relying party name for SID RpV3 signature
     *                                        verification. {@code null} when veryfying MID
     *                                        signature.
     * @param schemeName                      Scheme name for SID RpV3 signature verification.
     *                                        {@code null} when veryfying MID signature.
     * @return Response object
     * @throws VerificationException
     */
    public TokenVerificationResponse verify(
        String tokenBase64Url,
        String certBase64Url,
        String sidSignatureParamsJsonBase64Url,
        String rpName,
        String schemeName
    ) throws VerificationException {
        Objects.requireNonNull(tokenBase64Url);
        Objects.requireNonNull(certBase64Url);

        X509Certificate cert = X509CertUtils.parse(Base64.getUrlDecoder().decode(certBase64Url));

        certVerifier.checkCertificate(cert);

        SDJWT sdjwt = SDJWT.parse(tokenBase64Url);
        SignedJWT signedJWT = getSignedJwt(sdjwt.getCredentialJwt());
        JWSHeader header = signedJWT.getHeader();

        if (!Constants.TYPE_AUTH_TOKEN.equals(header.getType().toString())) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        String tokenIdentity = claimsSet.getIssuer();

        if (!tokenIdentity.startsWith(EtsiIdentifier.PREFIX)) {
            throw new VerificationException("Only identifiers starting with " + EtsiIdentifier.PREFIX
                + " are supported.  \"iss\" \"" + tokenIdentity + "\"");
        }

        EtsiIdentifier etsiIdentifier = verifyTokenIdentityAndReturnEtsiIdentifier(
            cert,
            tokenIdentity
        );

        if (sidSignatureParamsJsonBase64Url != null) {
            if (!RP_V3_SIGNATURE_ALGORITHM_NAME.equals(header.getAlgorithm().getName())) {
                throw new VerificationException("Unsupported \"alg\" " + header.getAlgorithm().getName());
            }

            SidRpv3SignatureVerifier.AuthTokenSignatureValidationParams validationParams =
                SidRpv3SignatureVerifier.createAuthTokenValidationParams(sidSignatureParamsJsonBase64Url);

            SidRpv3SignatureVerifier.verify(
                signedJWT.getSignature().toString(),
                cert.getPublicKey(),
                validationParams,
                rpName,
                schemeName,
                createRpChallenge(signedJWT)
            );
        } else {
            MidSignatureVerifier.verify(signedJWT, cert);
        }

        return createResponse(claimsSet, sdjwt, etsiIdentifier);
    }

    private TokenVerificationResponse createResponse(
        JWTClaimsSet claimsSet, SDJWT sdjwt,
        EtsiIdentifier etsiIdentifier
    ) throws VerificationException {
        Map<String, Object> verifiedDecodedClaims = decodeSdJwtClaims(
            claimsSet,
            sdjwt.getDisclosures()
        );

        return new TokenVerificationResponse(
            URI.create(getSingleAudArrayElementAsString(verifiedDecodedClaims)),
            etsiIdentifier
        );
    }

    private String createRpChallenge(SignedJWT signedJWT) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] rpChallengeBytes = digest.digest(signedJWT.getSigningInput());
            return Base64.getEncoder().encodeToString(rpChallengeBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
