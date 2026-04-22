package ee.cyber.cdoc2.auth;

import java.net.URI;

public record TokenVerificationResponse(
    URI nonceUri,
    EtsiIdentifier identifier
) {
}
