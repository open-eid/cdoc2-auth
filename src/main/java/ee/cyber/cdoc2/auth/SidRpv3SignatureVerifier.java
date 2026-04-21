package ee.cyber.cdoc2.auth;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.Objects;

import ee.cyber.cdoc2.auth.exception.VerificationException;


public class SidRpv3SignatureVerifier {
    private final SidRpv3SignatureVerifierConfig config;

    public SidRpv3SignatureVerifier(SidRpv3SignatureVerifierConfig config) {
        this.config = config;
    }

    public boolean isValid(
        String signatureValueBase64Url,
        PublicKey publicKey,
        SignatureValidationParams params
    ) throws VerificationException {
        Objects.requireNonNull(params);
        Objects.requireNonNull(params.sidSignature);

        byte[] signatureToValidate = signatureValueBase64Url != null
            ? Base64.getUrlDecoder().decode(signatureValueBase64Url)
            : Base64.getDecoder().decode(params.sidSignature.value);

        try {
            return validate(signatureToValidate, publicKey, params);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | SignatureException |
                 NoSuchAlgorithmException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    private boolean validate(
        byte[] signatureBytes,
        PublicKey publicKey,
        SignatureValidationParams params
    ) throws InvalidAlgorithmParameterException, InvalidKeyException,
        SignatureException, NoSuchAlgorithmException {

        String separator = "|";
        String schemeName = config.schemeName;
        String signatureProtocol = "ACSP_V2";
        String relyingPartyNameBase64 = Base64.getEncoder()
            .encodeToString(config.rpName.getBytes(StandardCharsets.UTF_8));
        String brokeredRpNameBase64 = "";
        String initialCallbackUrl = "";
        String flowType = params.sidSignature.flowType;

        String[] payloadParts = {
            schemeName,
            signatureProtocol,
            params.sidSignature.serverRandom,
            params.rpChallenge,
            params.sidSignature.userChallenge,
            relyingPartyNameBase64,
            brokeredRpNameBase64,
            params.interactionsDigest,
            params.interactionTypeUsed,
            initialCallbackUrl,
            flowType
        };

        String acspV2Payload = String.join(separator, payloadParts);
        byte[] acspV2PayloadBytes = acspV2Payload.getBytes(StandardCharsets.UTF_8);

        String maskGenDigestAlg =
            params.sidSignature.signatureAlgorithmParameters().maskGenAlgorithm()
                .parameters().hashAlgorithm();

        PSSParameterSpec pssSpec = new PSSParameterSpec(
            params.sidSignature.signatureAlgorithmParameters().hashAlgorithm(),
            "MGF1",
            new MGF1ParameterSpec(maskGenDigestAlg),
            params.sidSignature.signatureAlgorithmParameters().saltLength(),
            PSSParameterSpec.TRAILER_FIELD_BC
        );

        Signature verifier = Signature.getInstance(
            params.sidSignature.signatureAlgorithm()
        );
        verifier.setParameter(pssSpec);
        verifier.initVerify(publicKey);
        verifier.update(acspV2PayloadBytes);

        return verifier.verify(signatureBytes);
    }

    public record SignatureValidationParams(
        String rpChallenge,
        String interactionsDigest,
        String interactionTypeUsed,
        SidSignature sidSignature
    ) {
    }

    public record SidSignature(
        String value,
        String serverRandom,
        String userChallenge,
        String signatureAlgorithm,
        String flowType,
        SignatureAlgorithmParameters signatureAlgorithmParameters
    ) {
    }

    public record SignatureAlgorithmParameters(
        String hashAlgorithm,
        MaskGenAlgorithm maskGenAlgorithm,
        Integer saltLength,
        String trailerField
    ) {
    }

    public record MaskGenAlgorithm(
        String algorithm,
        Parameters parameters
    ) {

        public record Parameters(
            String hashAlgorithm
        ) {
        }
    }

    public record SidRpv3SignatureVerifierConfig(
        String schemeName,
        String rpName
    ) {
    }
}
